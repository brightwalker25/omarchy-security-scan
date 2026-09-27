"""Checks for how security-report re-reads RED lines in the integrity section.

Run from the repository root:

    python3 -m unittest discover -s tests -v

The system calls are replaced with stand-ins, so nothing here reads the real
/usr, /var/lib/pacman or /var/log, and nothing is sent anywhere.
"""

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/security-report"

LINK = "/usr/bin/tool"
TARGET = "/usr/lib/tool/tool-avx512"
OTHER = "/usr/lib/tool/tool-debug"
LINE = f"changed {LINK} (unpackaged file in a system code path)"
SCRIPT_TEXT = f'ln -sf {TARGET} {LINK}\n'


def load_report():
    loader = importlib.machinery.SourceFileLoader("security_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("security_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class ScriptletLinkTest(unittest.TestCase):
    def setUp(self):
        self.r = load_report()

    def explains(self, line=LINE, islink=True, isfile=True, owner="tool-bin\n",
                 version="tool-bin 1.1.0-1\n", qkk="", script=SCRIPT_TEXT, points_at=TARGET):
        def pacman(*args):
            return {"-Qqo": owner, "-Q": version}[args[0]]

        def read_text(path_self):
            if script is None:
                raise OSError("no install script")
            self.assertEqual(str(path_self), "/var/lib/pacman/local/tool-bin-1.1.0-1/install")
            return script

        def realpath(path):
            # The link resolves to points_at; every other path is itself.
            return points_at if path == LINK else os.path.normpath(path)

        done = subprocess.CompletedProcess([], 0, stdout=qkk, stderr="")
        with mock.patch.object(self.r.os.path, "islink", return_value=islink), \
             mock.patch.object(self.r.os.path, "realpath", side_effect=realpath), \
             mock.patch.object(self.r.os.path, "isfile", return_value=isfile), \
             mock.patch.object(self.r, "_pacman", side_effect=pacman), \
             mock.patch.object(self.r.subprocess, "run", return_value=done), \
             mock.patch.object(self.r.Path, "read_text", read_text):
            return self.r.scriptlet_link_explains(line)

    def test_link_made_by_the_install_script_is_explained(self):
        self.assertTrue(self.explains())

    def test_added_link_is_explained_too(self):
        self.assertTrue(self.explains(line=f"added {LINK} (unpackaged file in a system code path)"))

    def test_a_real_file_is_not(self):
        self.assertFalse(self.explains(islink=False))

    def test_a_dangling_link_is_not(self):
        self.assertFalse(self.explains(isfile=False))

    def test_a_link_repointed_to_another_file_of_the_package_is_not(self):
        # The finding in omacom/omarchy-plugin-marketplace#8732: the package
        # owns and verifies OTHER too, but its install script never points
        # the link there.
        self.assertFalse(self.explains(points_at=OTHER, qkk=""))

    def test_a_target_held_in_a_variable_is_not(self):
        self.assertFalse(self.explains(script=f'ln -sf "$target" {LINK}\n'))

    def test_two_different_targets_are_not(self):
        script = (f"if fast; then\n  ln -sf {TARGET} {LINK}\nelse\n"
                  f"  ln -sf {OTHER} {LINK}\nfi\n")
        self.assertFalse(self.explains(script=script))
        self.assertFalse(self.explains(script=script, points_at=OTHER))

    def test_the_same_target_twice_is_explained(self):
        script = f"ln -sf {TARGET} {LINK}\nln -snf {TARGET} {LINK}\n"
        self.assertTrue(self.explains(script=script))

    def test_a_relative_target_resolves_from_the_link_folder(self):
        self.assertTrue(self.explains(script=f"ln -sf ../lib/tool/tool-avx512 {LINK}\n"))

    def test_a_hard_link_is_not(self):
        self.assertFalse(self.explains(script=f"ln -f {TARGET} {LINK}\n"))

    def test_an_option_it_does_not_know_is_not(self):
        self.assertFalse(self.explains(script=f"ln -sf -S .old {TARGET} {LINK}\n"))

    def test_ln_after_other_commands_on_the_line_is_read(self):
        script = f'rm -f {LINK} && /usr/bin/ln -s -- "{TARGET}" {LINK} 2>/dev/null || true\n'
        self.assertTrue(self.explains(script=script))

    def test_a_continued_line_is_read(self):
        self.assertTrue(self.explains(script=f"ln -sf \\\n    {TARGET} \\\n    {LINK}\n"))

    def test_a_commented_out_ln_is_ignored(self):
        self.assertFalse(self.explains(script=f"# ln -sf {TARGET} {LINK}\n"))

    def test_the_link_as_a_source_is_not_a_target(self):
        self.assertFalse(self.explains(script=f"ln -sf {LINK} /usr/bin/tool-alias\n"))

    def test_a_target_no_package_owns_is_not(self):
        self.assertFalse(self.explains(owner=""))

    def test_a_target_that_fails_pacman_is_not(self):
        qkk = f"warning: tool-bin: {TARGET} (SHA256 checksum mismatch)\n"
        self.assertFalse(self.explains(qkk=qkk.replace("SHA256 checksum", "checksum")))

    def test_a_bare_mtime_mismatch_does_not_count(self):
        qkk = f"warning: tool-bin: {TARGET} (Modification time mismatch)\n"
        self.assertTrue(self.explains(qkk=qkk))

    def test_a_package_without_an_install_script_is_not(self):
        self.assertFalse(self.explains(script=None))

    def test_a_script_that_never_names_the_link_is_not(self):
        self.assertFalse(self.explains(script='ln -sf "$target" /usr/bin/other\n'))

    def test_a_longer_path_is_not_the_link(self):
        self.assertFalse(self.explains(script=f"ln -sf {TARGET} {LINK}-osd\n"))

    def test_other_red_lines_are_left_alone(self):
        line = f"changed {LINK} (owned by tool-bin but fails pacman's checksum)"
        self.assertFalse(self.explains(line=line))


class ScriptletLinkTargetCommandTest(unittest.TestCase):
    """The hidden --scriptlet-link-target option that security-scan calls, run
    as a real process against real links in a temporary folder."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.realpath(self.tmp.name)
        os.makedirs(f"{self.dir}/lib")
        for name in ("fast", "slow"):
            Path(f"{self.dir}/lib/{name}").write_text("")
        self.link = f"{self.dir}/bin/tool"

    def target(self, script):
        path = Path(self.dir, "install")
        path.write_text(script)
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--scriptlet-link-target",
                            str(path), self.link], capture_output=True, text=True, env={})
        return r.stdout.strip() if r.returncode == 0 else None

    def test_a_literal_target_is_printed_resolved(self):
        self.assertEqual(self.target(f"ln -sf {self.dir}/lib/fast {self.link}\n"),
                         f"{self.dir}/lib/fast")

    def test_a_variable_target_exits_1(self):
        self.assertIsNone(self.target(f'ln -sf "$t" {self.link}\n'))

    def test_two_targets_exit_1(self):
        script = f"ln -sf {self.dir}/lib/fast {self.link}\nln -sf {self.dir}/lib/slow {self.link}\n"
        self.assertIsNone(self.target(script))

    def test_no_ln_for_the_link_exits_1(self):
        self.assertIsNone(self.target(f"rm -f {self.link}\n"))


if __name__ == "__main__":
    unittest.main()
