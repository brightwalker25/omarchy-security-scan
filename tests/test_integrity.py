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


class ListedLinkTest(unittest.TestCase):
    """Links listed in scan.conf's SCRIPTLET_LINKS, whose target the install
    script picks at run time. Real links and files in a temporary folder;
    pacman and the install script are stand-ins."""

    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.realpath(self.tmp.name)
        os.makedirs(f"{self.dir}/bin")
        os.makedirs(f"{self.dir}/lib")
        for name in ("fast", "slow", "foreign"):
            Path(f"{self.dir}/lib/{name}").write_text("")
        self.link = f"{self.dir}/bin/tool"
        os.symlink(f"{self.dir}/lib/fast", self.link)
        self.line = f"changed {self.link} (unpackaged file in a system code path)"
        self.script = (f"if fast; then target={self.dir}/lib/fast; "
                       f"else target={self.dir}/lib/slow; fi\n"
                       f'ln -sf "$target" {self.link}\n')
        self.owners = {f"{self.dir}/lib/fast": "tool-bin\n",
                       f"{self.dir}/lib/slow": "tool-bin\n",
                       f"{self.dir}/lib/foreign": "other-bin\n"}

    def explains(self, links=None, qkk="", script=None, owners=None):
        links = {self.link: "tool-bin"} if links is None else links
        script = self.script if script is None else script
        owners = self.owners if owners is None else owners
        versions = {"tool-bin": "tool-bin 1.1.0-1\n", "other-bin": "other-bin 2.0-1\n"}

        def pacman(*args):
            if args[0] == "-Qqo":
                return owners.get(args[-1])
            return versions.get(args[-1])

        def read_text(path_self):
            self.assertEqual(str(path_self), "/var/lib/pacman/local/tool-bin-1.1.0-1/install")
            return script

        done = subprocess.CompletedProcess([], 0, stdout=qkk, stderr="")
        with mock.patch.object(self.r, "_pacman", side_effect=pacman), \
             mock.patch.object(self.r.subprocess, "run", return_value=done), \
             mock.patch.object(self.r.Path, "read_text", read_text):
            return self.r.listed_link_explains(self.line, links)

    def repoint(self, name):
        os.remove(self.link)
        os.symlink(f"{self.dir}/lib/{name}", self.link)

    def test_a_listed_link_to_a_verified_file_of_the_package_is_explained(self):
        self.assertTrue(self.explains())
        self.repoint("slow")
        self.assertTrue(self.explains())

    def test_the_general_rule_still_refuses_it(self):
        # The variable target is why the list exists. scriptlet_link_target()
        # must keep refusing it, as settled in the marketplace review #8732.
        self.assertIsNone(self.r.scriptlet_link_target(self.script, self.link))

    def test_a_listed_link_to_a_file_of_another_package_is_not(self):
        self.repoint("foreign")
        self.assertFalse(self.explains())

    def test_a_listed_link_to_a_file_of_two_packages_is_not(self):
        owners = dict(self.owners)
        owners[f"{self.dir}/lib/fast"] = "tool-bin\nother-bin\n"
        self.assertFalse(self.explains(owners=owners))

    def test_a_listed_link_to_an_unpackaged_file_is_not(self):
        self.assertFalse(self.explains(owners={}))

    def test_a_listed_path_that_is_a_regular_file_is_not(self):
        # voxtype's install script can also write a wrapper script there.
        os.remove(self.link)
        Path(self.link).write_text(f'#!/bin/sh\nexec {self.dir}/lib/fast "$@"\n')
        self.assertFalse(self.explains())

    def test_a_dangling_listed_link_is_not(self):
        self.repoint("missing")
        self.assertFalse(self.explains())

    def test_a_target_that_fails_pacman_is_not(self):
        qkk = f"warning: tool-bin: {self.dir}/lib/fast (SHA256 checksum mismatch)\n"
        self.assertFalse(self.explains(qkk=qkk))

    def test_a_script_without_ln_for_the_path_is_not(self):
        self.assertFalse(self.explains(script=f'ln -sf "$target" {self.link}-osd\n'))
        self.assertFalse(self.explains(script=f"rm -f {self.link}\n"))
        self.assertFalse(self.explains(script=f'# ln -sf "$target" {self.link}\n'))

    def test_a_hard_link_in_the_script_is_not(self):
        self.assertFalse(self.explains(script=f'ln -f "$target" {self.link}\n'))

    def test_the_link_as_a_source_is_not(self):
        self.assertFalse(self.explains(script=f'ln -sf {self.link} "$alias"\n'))

    def test_an_unlisted_variable_target_link_is_not(self):
        self.assertFalse(self.explains(links={f"{self.dir}/bin/other": "tool-bin"}))
        self.assertFalse(self.explains(links={}))

    def test_a_listed_link_named_for_another_package_is_not(self):
        self.assertFalse(self.explains(links={self.link: "other-bin"}))

    def test_other_red_lines_are_left_alone(self):
        self.line = f"changed {self.link} (owned by tool-bin but fails pacman's checksum)"
        self.assertFalse(self.explains())


class ListedLinksConfTest(unittest.TestCase):
    """Reading SCRIPTLET_LINKS from scan.conf."""

    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conf = Path(self.tmp.name, "scan.conf")

    def links(self, text, root_only=True):
        self.conf.write_text(text)
        with mock.patch.object(self.r, "_root_only", return_value=root_only):
            return self.r.listed_links(self.conf)

    def test_the_example_lists_nothing(self):
        text = (ROOT / "system/scan.conf.example").read_text()
        self.assertEqual(self.links(text), {})

    def test_the_example_line_uncommented(self):
        text = (ROOT / "system/scan.conf.example").read_text()
        line = next(ln for ln in text.splitlines() if ln.startswith("# SCRIPTLET_LINKS="))
        self.assertEqual(self.links(line[2:] + "\n"), {
            "/usr/bin/voxtype": "voxtype-bin",
            "/usr/lib/voxtype/voxtype-onnx-cuda": "voxtype-bin"})

    def test_a_value_over_several_lines(self):
        text = 'A=1\nSCRIPTLET_LINKS="\n  /usr/bin/a=a-bin\n  /usr/bin/b=b-bin\n"  # note\nB=2\n'
        self.assertEqual(self.links(text), {"/usr/bin/a": "a-bin", "/usr/bin/b": "b-bin"})

    def test_the_last_assignment_wins(self):
        text = 'SCRIPTLET_LINKS="/usr/bin/a=a-bin"\nSCRIPTLET_LINKS=""\n'
        self.assertEqual(self.links(text), {})

    def test_a_variable_or_command_empties_the_list(self):
        for value in ('"/usr/bin/a=a-bin $MORE"', '"/usr/bin/a=$(echo a-bin)"',
                      "`echo /usr/bin/a=a-bin`", '"/usr/bin/a=a-bin \\\n"'):
            self.assertEqual(self.links(f"SCRIPTLET_LINKS={value}\n"), {}, value)

    def test_malformed_entries_are_skipped(self):
        text = ('SCRIPTLET_LINKS="usr/bin/a=a-bin /usr/bin/../b=b-bin /usr/bin/c= '
                '/usr/bin/d=D /usr/bin/e=e-bin"\n')
        self.assertEqual(self.links(text), {"/usr/bin/e": "e-bin"})

    def test_an_unclosed_quote_empties_the_list(self):
        self.assertEqual(self.links('SCRIPTLET_LINKS="/usr/bin/a=a-bin\n'), {})

    def test_a_file_that_is_not_roots_alone_is_ignored(self):
        self.assertEqual(self.links('SCRIPTLET_LINKS="/usr/bin/a=a-bin"\n', root_only=False), {})

    def test_root_only(self):
        def st(mode, uid):
            return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))
        self.assertTrue(self.r._root_only(st(0o100644, 0)))
        self.assertFalse(self.r._root_only(st(0o100664, 0)))
        self.assertFalse(self.r._root_only(st(0o100646, 0)))
        self.assertFalse(self.r._root_only(st(0o100644, 1000)))


class EmptyListChangesNothingTest(unittest.TestCase):
    """With nothing listed, the integrity section grades exactly as before."""

    def setUp(self):
        self.r = load_report()

    def grade(self, links):
        now = self.r.dt.datetime(2026, 9, 30, 12, 0)
        lines = (f"RED {LINE}\n"
                 "PKG changed /usr/bin/ls (coreutils, verified by pacman)\n")
        # Everything a listed link needs is true, so only the list decides.
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        answers = {"-Qqo": "tool-bin\n", "-Q": "tool-bin 1.1.0-1\n"}
        with mock.patch.object(self.r, "logs", return_value=([(now, "log")], None)), \
             mock.patch.object(self.r, "read", return_value=lines), \
             mock.patch.object(self.r, "listed_links", return_value=links), \
             mock.patch.object(self.r, "scriptlet_link_explains", return_value=False), \
             mock.patch.object(self.r.os.path, "islink", return_value=True), \
             mock.patch.object(self.r.os.path, "realpath", return_value=TARGET), \
             mock.patch.object(self.r.os.path, "isfile", return_value=True), \
             mock.patch.object(self.r, "_pacman", side_effect=lambda *a: answers[a[0]]), \
             mock.patch.object(self.r.subprocess, "run", return_value=done), \
             mock.patch.object(self.r.Path, "read_text",
                               lambda _: f'ln -sf "$target" {LINK}\n'):
            return self.r.integrity(now, now)

    def test_an_empty_list_leaves_the_line_red(self):
        s = self.grade({})
        self.assertEqual(s.rating, self.r.RED)
        self.assertEqual([i[1] for i in s.items], [LINE])

    def test_the_same_line_is_a_package_change_once_listed(self):
        s = self.grade({LINK: "tool-bin"})
        self.assertEqual(s.rating, self.r.GREEN)


class ListedLinkCommandTest(unittest.TestCase):
    """The hidden --listed-link option that security-scan calls, run as a
    real process. A scan.conf in a temporary folder is not root's, so it
    must be ignored and the link left red."""

    def run_it(self, conf, link):
        return subprocess.run([sys.executable, "-I", str(SCRIPT), "--listed-link", conf, link],
                              capture_output=True, text=True, env={})

    def test_a_conf_that_is_not_roots_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            os.makedirs(f"{tmp}/lib")
            Path(f"{tmp}/lib/fast").write_text("")
            os.symlink(f"{tmp}/lib/fast", f"{tmp}/tool")
            conf = Path(tmp, "scan.conf")
            conf.write_text(f'SCRIPTLET_LINKS="{tmp}/tool=tool-bin"\n')
            r = self.run_it(str(conf), f"{tmp}/tool")
            self.assertEqual((r.returncode, r.stdout), (1, ""))

    def test_a_missing_conf_exits_1(self):
        r = self.run_it("/nonexistent/scan.conf", "/usr/bin/tool")
        self.assertEqual((r.returncode, r.stdout), (1, ""))


if __name__ == "__main__":
    unittest.main()
