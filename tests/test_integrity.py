"""Checks for how security-report re-reads RED lines in the integrity section.

Run from the repository root:

    python3 -m unittest discover -s tests -v

The system calls are replaced with stand-ins, so nothing here reads the real
/usr, /var/lib/pacman or /var/log, and nothing is sent anywhere.
"""

import importlib.machinery
import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/security-report"

LINK = "/usr/bin/tool"
TARGET = "/usr/lib/tool/tool-avx512"
LINE = f"changed {LINK} (unpackaged file in a system code path)"
SCRIPT_TEXT = f'ln -sf "$target" {LINK}\n'


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
                 version="tool-bin 1.1.0-1\n", qkk="", script=SCRIPT_TEXT):
        def pacman(*args):
            return {"-Qqo": owner, "-Q": version}[args[0]]

        def read_text(path_self):
            if script is None:
                raise OSError("no install script")
            self.assertEqual(str(path_self), "/var/lib/pacman/local/tool-bin-1.1.0-1/install")
            return script

        done = subprocess.CompletedProcess([], 0, stdout=qkk, stderr="")
        with mock.patch.object(self.r.os.path, "islink", return_value=islink), \
             mock.patch.object(self.r.os.path, "realpath", return_value=TARGET), \
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
        self.assertFalse(self.explains(script=f'ln -sf "$target" {LINK}-osd\n'))

    def test_other_red_lines_are_left_alone(self):
        line = f"changed {LINK} (owned by tool-bin but fails pacman's checksum)"
        self.assertFalse(self.explains(line=line))


if __name__ == "__main__":
    unittest.main()
