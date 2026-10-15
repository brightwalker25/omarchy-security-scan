# Changelog

Notable changes to the Security Scan plugin and its scan suite. Versions follow
[semantic versioning](https://semver.org), and the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.11] - 2026-10-15

### Security

- When the desktop user had no group of their own, 0.2.10 left `scan.conf`
  and `risk-register.toml` readable by every local user, so that the report
  could still read them. They hold the user's name, home folder and
  repository paths. The installer now refuses to install in that case,
  before it changes anything, and says how to give the user a private
  primary group. Uninstalling works as before. If an earlier version left
  files in `/etc/security-scan`, the refusal says so and suggests
  `chmod o-rwx` on them until the group exists.
- The test for a group of the user's own is stricter. The group must have
  the user's name and be their primary group, both found in the local
  files; it must be the only group with its GID, with no other member in
  `/etc/group` or `/etc/gshadow`; and no other account may have it as its
  primary group. A primary group shared by several accounts, such as
  `users`, does not count. Only the local files list every account, so a
  machine whose `/etc/nsswitch.conf` also looks up accounts or groups
  elsewhere, such as in LDAP or SSSD, does not qualify either. 0.2.10 did
  not look at `/etc/gshadow`, at other groups with the same GID, or at where
  accounts and groups were looked up.
- A file in `/etc/security-scan` that an administrator had given to another
  group, such as `users`, kept that group, so all of its members could
  still read it after 0.2.10 tightened its mode. Installing now moves
  `scan.conf` and `risk-register.toml` to the desktop user's own group and
  prints `take ... from group` for each. Files only root reads already lost
  their group permissions.
- Each scan shared its log folder in `/var/log/security-scan` (0750) and
  its copy of the lynis report (0640) with the group named after the
  desktop user, even when that group was no longer private, for example
  because another account had been added to it after installing. The logs
  name repositories, files and findings. Each scan run as root now makes
  the same test as the installer and, without a private group, keeps the
  folder 0700 for root alone, writes the lynis copy 0600, and says so on
  stderr. An existing folder is closed on the next run.

## [0.2.10] - 2026-10-14

A review of 0.2.9 looked for every other place where private names or paths
could reach other local users, through the process list or a readable file.

### Security

- AIDE findings in the home folder, such as a changed file in `~/.ssh` or
  `~/.local/bin`, were passed to `pacman`, `readlink` and `python3` as
  arguments, so a private file name was visible in the process list. Paths in
  the home folder are now handled only inside the shell. No package owns
  them, so the verdicts and their wording are unchanged, except that a link
  in the home folder can no longer be explained by a package's install
  script or a `SCRIPTLET_LINKS` entry. A system link that points into the
  home folder is handled the same way, and so is a home folder file in
  rkhunter's results.
- The model scan started `picklescan` and `find` with each model folder's
  path as an argument, visible for the whole scan. Both now run from inside
  the folder. A folder that cannot be entered is reported as not scanned.
- `security-report` passed file paths to `pacman -Qqo` as arguments. It now
  passes them on standard input.
- The files in `/etc/security-scan` were readable by every local user,
  though they hold the desktop user's name and home folder, the folders
  scanned, gitleaks rules written to find a private name, and the paths of
  repositories with findings. `gitleaks.toml` and `aide.conf`, read only by
  the scans, are now 0600. `scan.conf` and `risk-register.toml`, which the
  report reads as the desktop user, are 0640 and shared with that user's own
  group. Installing over an earlier version tightens existing files once and
  prints `make ... private` for each. It only ever removes permissions, and
  leaves a symlink, a file root does not own or anything that is not a
  regular file as it is, with a note. If the user has no group of their own,
  those two files stay readable by everyone and the installer says so. AIDE
  watches `/etc`, so the first scan after upgrading reports these mode
  changes once, in amber.
- The HTML report and the folder that holds it were written with the user's
  umask, usually readable by everyone, though they name repositories, rules
  and changed files. Pages are now 0600 and `~/.local/share/security-report`
  is 0700, and pages already there are made private. A page is written to a
  new file and renamed into place, so a symlink at its path is replaced, not
  written through.

### Fixed

- gitleaks exits 1 both when it finds a secret and when it fails, for
  example on a missing config, so a failed run read as clean. Secrets now
  give exit 3, and any other non-zero exit is logged as an error, which the
  report shows. A missing or unreadable `gitleaks.toml` is logged as well.
- The report dropped a repository whose path holds a space, so its findings
  were missing and the section could show green. Such paths are now read in
  full. If the scan counted more findings than the report could match to a
  repository, the section shows the difference in red.
- A failed write of the HTML report prints a message and exits 2, rather
  than a traceback.

## [0.2.9] - 2026-10-14

### Security

- The gitleaks scan put the path of each repository with findings in its
  desktop notification. `notify-send` takes the notification text as a
  command-line argument, which any local user can read in the process list,
  so repository names and their finding counts were visible outside the
  protected scan logs. The notification now gives only the counts and the log
  path, and the log alone names the repositories.
- gitleaks itself was started with each repository's path on its command
  line, which exposed the same names while it ran. It now runs from inside
  the repository and is given `.`, so no repository path appears in any
  command line the scan starts.

### Changed

- Because gitleaks now scans `.`, an allowlist `paths` pattern in
  `/etc/security-scan/gitleaks.toml` is matched against the path relative to
  the repository root. A pattern that names the repository folder no longer
  matches; drop the folder from it. See INSTALL.md.
- For the same reason, a `.gitleaksignore` fingerprint now names the file
  relative to the repository root, as one committed in a repository usually
  does. An entry written with the full path no longer matches.

## [0.2.8] - 2026-10-12

### Added

- `tests/sandbox-install.sh` runs the installer against a temporary folder
  standing in for `/`, with the system commands replaced by stand-ins, and
  checks fresh installs, upgrades from every release from 0.2.1 to 0.2.7,
  uninstalls, and the refusals below. It needs no root.

### Security

- The installer replaced any existing file at the paths of its units in
  `/etc/systemd/system` and `/etc/systemd/user`, and the uninstaller removed
  every `security-scan-*.timer`, including timers this plugin never
  installed. Both could overwrite or delete units an administrator manages.
  A unit is now replaced or removed only when it is a regular file, not a
  symlink, owned by root, whose content is exactly a unit this plugin has
  shipped, either in the checkout or in an earlier release. The uninstaller
  works from the exact list of names the plugin installs, not a glob, and
  lists anything it leaves in place. Reported in
  omacom/omarchy-plugin-marketplace#8732.
- The same rule now covers the installer's other paths. Before it changes
  anything, the installer checks `security-scan` and `security-report` in
  `/usr/local/bin`, `/opt/security-scan`, the picklescan environment and
  `/etc/security-scan`. If one holds something that is not this plugin's, it
  lists every such path with the reason and stops, leaving the machine as it
  was. The uninstaller removes only the picklescan environment from
  `/opt/security-scan`, not the whole folder, and removes the folder itself
  only once it is empty.
- Files are written to a temporary name in the same folder and renamed into
  place, so a symlink at the destination is replaced rather than written
  through. Existing folders are no longer given new permissions, a
  regenerated `aide.conf` is never more open than the file it replaces, its
  backup keeps the original's permissions up to 0644, and an earlier backup
  from the same day is no longer overwritten.
- The picklescan environment in `/opt/security-scan` is replaced or removed
  only when this installer made it: it carries a marker file the installer
  now writes, or has picklescan installed in it. Any other virtual
  environment at that path is refused. Of the uv tool folder from 0.2.1,
  only picklescan is removed, and the folder only once nothing else is in
  it.
- `/opt/security-scan` and `/etc/security-scan` are refused when group or
  others can write to them, and `aide.conf` is never read through a
  symlink. `--user 0`, or another name for UID 0, is
  refused like `root`. A temporary file is removed if the run is
  interrupted before it is renamed into place.

## [0.2.7] - 2026-10-04

### Fixed

- A package file whose own install script gives it a group and the setgid
  bit no longer turns the integrity check red after every update of that
  package. 1password does this to its browser helper and 1password-cli to
  `op`, so pacman reports a GID and permissions mismatch on files whose
  content is untouched. Such a file is now a package change only when pacman
  finds nothing else wrong with it, the install script plainly runs `chgrp`
  and `chmod g+s` on that exact path, and the file's group, owner and mode
  match what the script and the package say. The script's `chgrp` and
  `chmod` must be certain to run: text in a heredoc, a function nothing
  calls, or a command inside an `if` or after `&&` does not count. The
  rootkit check accepts the same files. Red lines logged before this
  version are not re-graded and age out of the window as usual.
- The report no longer accepts a linked file as verified when it runs as a
  user who cannot read the file. pacman then prints "failed to calculate"
  instead of a checksum mismatch, which the check had not looked for.
- A mismatch line early in a very long pacman listing could be missed,
  because `printf | grep -q` under pipefail reads an early match as no
  match. The scan now matches against the text directly.

### Changed

- A package file that fails only pacman's ownership or permission check is
  now reported as that, instead of as failing pacman's checksum.

## [0.2.6] - 2026-10-03

### Added

- A `reportDays` setting, from 1 to 7 and 7 by default, sets how many days of
  scan results the bar and panel grade. A finding drops out of the bar once it
  is older than that, instead of always waiting a full week. The Monday report
  still covers seven days.

### Changed

- Each scan's latest run now always counts, even when it is older than the
  window, so a short window does not turn a weekly scan such as rkhunter
  amber for having no result. Whether a scan is overdue is still graded in
  the scan health section. `--days` must be at least 1.

### Fixed

- A boot file changed by a package reinstall or downgrade was graded red as
  "boot file changed with no package update", because the scan counted only
  installs, upgrades and removals. A `reinstalled` or `downgraded` line in
  `pacman.log` now counts too. The report applies the same rule to red lines
  already logged: it reads that line as a package change when `pacman.log`
  records a transaction between the end of the check before it and the start
  of the check that logged it, comparing times with their zones so a change of
  clocks cannot reorder them. A transaction made while or after that check
  ran, or a later check's verdict, never clears it. Each check now logs the
  window its own count used, and the report uses that when it is there. Run
  the installer again so the scheduled scan uses the new rule.

## [0.2.5] - 2026-09-30

### Added

- A `SCRIPTLET_LINKS` setting in `scan.conf` lists symlinks, each with the
  package whose files it may point to, that the package's install script
  points at a file it picks when it runs, such as voxtype-bin's
  `/usr/bin/voxtype`. The general rule rightly leaves such a link red, since
  the target cannot be read from the script. A listed link is a package change
  only while it is a symlink, not a file, and resolves to a file owned by the
  listed package alone, pacman finds that file unaltered, and the package's
  install script has an `ln -s` command for the link's exact path. The list is
  empty by default, so nothing changes unless you add to it, and links not on
  it are treated exactly as before. The value is read from the file only,
  must be written out in full, and is ignored if the file is not root's
  alone. The scan runs the report's own check through a hidden option, and
  the report applies it to red lines logged before the link was listed. Add
  the setting to an installed `scan.conf` by hand, since the installer never
  overwrites it, and run the installer again so the scheduled scan uses it.

### Fixed

- AIDE no longer reports limine-snapper-sync's snapshot bookkeeping as red.
  A change to `/boot/limine.conf`, `/boot/limine.conf.old` or
  `limine_history/snapshots.json` with no package update is a package change
  only when limine-snapper-sync's own program logged writing the file since
  the last check, and the file differs from a trusted copy of `limine.conf`
  only inside the Snapshots sub-menu, whose entries may boot only command
  lines and kernel images the trusted copy already boots. A changed kernel
  command line, kernel or initramfs path, or any other entry stays red. The
  scan keeps the trusted copy in `/var/lib/security-scan`, readable by root
  only, and refreshes it after each check that finds nothing red under
  `/boot`; until the first check has made it, these changes stay red. The
  check lives in security-report, and security-scan runs it through a hidden
  `--limine-snapshot-change` option. The weekly report leaves red lines
  logged earlier as they are, because it cannot read `/boot` or the trusted
  copy. Run the installer again after upgrading, so the scheduled scan uses
  the new rule.

## [0.2.4] - 2026-09-29


### Fixed

- The rootkit section grades only the latest rkhunter run. It used to add up
  the warnings of every run in the report's window, so a warning that a later
  clean run had cleared, such as the missing passwd and group copies on the
  first run, stayed red for up to seven days. When an earlier run had warnings
  the latest one no longer shows, the headline now says so.

## [0.2.3] - 2026-09-27


### Fixed

- AIDE no longer reports a symlink as red when a package's own install
  script made it and it points where that script points it. It is explained
  only while it resolves to a file the package owns, pacman finds that file
  unaltered, and the package's install script has an `ln -s` command for the
  link's exact path whose target is written out in full and resolves to that
  same file. The report applies the same check to a red line logged before
  the scanner knew about it, against the system as it is now. Run the
  installer again after upgrading, so the scheduled scan uses the new rule.

### Security

- The first version of that check, on the main branch but never released,
  accepted a link to any verified file of the package whose install script
  named the link's path. A system command link repointed to a different file
  from the same package was therefore reported as a package change instead
  of red, in both the scan and the weekly report. The link's current target
  must now be exactly the target the install script gives. A target held in
  a variable, two different targets for the same link, an `ln` without `-s`,
  or an `ln` option the parser does not understand leaves the link red.
  Reported in omacom/omarchy-plugin-marketplace#8732.
- The scan and the report now read install scripts with one parser, in
  `security-report`, which `security-scan` runs through a hidden
  `--scriptlet-link-target` option, so the two cannot disagree.

## [0.2.2] - 2026-09-26

### Security

- The installer no longer runs `uv tool install --upgrade picklescan --with
  numpy` as root, which fetched whatever versions PyPI served on the day.
  picklescan and numpy are now pinned to exact versions and SHA-256 hashes in
  `system/picklescan-requirements.txt`, and installed as root with
  `--require-hashes` and `--only-binary :all:` into a virtual environment in
  `/opt/security-scan/picklescan`. Any file whose hash is not listed is
  refused, and nothing is built from source. Upgrades now happen only by
  changing that file in a new commit. The old uv tool folder,
  `/opt/security-scan/tools`, is removed.

## [0.2.1] - 2026-09-25

### Changed

- The bar lock is now tinted green, amber or red to match the report, in
  place of the small dot on its corner. A report that could not be read shows
  amber rather than a grey dot.


### Fixed

- AIDE no longer reports a browser's `policies.json` as red when a local
  pacman hook rewrites it after every update to switch off telemetry and
  studies, so that it always fails pacman's checksum. It is explained only
  while the hook is installed and the file holds nothing but the browser's own
  policies and those two switches; any other policy leaves it red.
- The report applies the same check to a RED line for that file logged
  before the scanner knew about the hook, against the file as it is now. The
  log itself is left as written.

## [0.2.0] - 2026-09-24

### Added

- A Privacy (Black Ops) section in the report. It reads the counts in
  `~/.local/state/black-ops/summary.json`, written by Black Ops 0.3.0 and
  later, and nothing else. It is red only when listen mode saw a program
  contact a telemetry host that nobody has reviewed, amber for unreviewed
  software watch findings, protections that slipped, a summary that cannot be
  read, or one more than eight days old, and green when Black Ops is on and
  every count is clean. Each item says what to do.
- A grey rating for things that are off or not installed. Grey is shown but is
  never a problem and never changes the overall rating. The section is grey
  when Black Ops is not installed or is switched off, and listen mode and the
  software watch are grey items while they are off. Grey sections start
  folded in the panel.
- Privacy entries in the risk register, which can lower the rating of one
  privacy item, limited by `count` to the findings that were looked at. A leak
  cannot be accepted this way.
- Tests for the privacy section, run with
  `python3 -m unittest discover -s tests`.

## [0.1.0] - 2026-09-23

First release.

### Added

- Six scheduled scans, run as root by `bin/security-scan` from one templated
  systemd service and six persistent timers: `arch-audit`, `aide` and `models`
  daily, `gitleaks` and `rkhunter` weekly on Monday, and `lynis` monthly. They
  run at idle CPU and disk priority, keep the last 12 logs of each scan in
  `/var/log/security-scan`, and send a desktop notification when they find
  something.
- A report, `bin/security-report`, that reads those logs and grades every
  finding green, amber or red, in the terminal, as a self-contained HTML page,
  or as JSON. It exits 1 when the overall rating is red.
- A risk register, `/etc/security-scan/risk-register.toml`, that records by
  hand what each known package CVE or gitleaks finding means on this machine
  and what is being done about it. A finding with no entry is reported as not
  yet assessed rather than passed, and a CVE entry whose assessed version is
  newer than the installed one is flagged for re-assessment.
- Standing risks, such as the firewall and disk encryption, checked live each
  time the report runs, so a protection that stops being in place is reported red.
- Scan health graded as a finding. A scan that has gone quiet turns amber and
  then red according to its cadence, and one that failed, or never ran, is red.
  A missing result is never read as a clean one.
- AIDE changes explained before they are reported. A file that `pacman -Qkk`
  still verifies counts as a package change, a boot file that changed with no
  package update is red, and unpackaged changes are amber where your own work
  normally lands and red in system code paths. AIDE re-baselines after every
  check, so each run reports only what is new.
- rkhunter's "file properties have changed" warnings accepted only when pacman
  verifies every file they name, after which rkhunter's record is updated.
- A model scan with `picklescan` over the folders in `MODEL_ROOTS`, which
  skips Python environments and reports a scan that crashed as failed.
- A weekly report on Monday at 13:00, written as a dated HTML page with a
  `latest.html` link and announced by a notification that can open it.
- A bar widget: a lock in the bar's own colour with a corner dot that is amber
  or red to match the report, grey when the report cannot be read, and absent
  when it is green. Its panel lists every section, its findings, and what is
  being done about each one, and can open the full report.
- An installer, `bin/security-scan-install`, that installs the packages,
  `picklescan`, the programs, the configuration and the units, creates the
  first baselines, and can be run again safely. `--dry-run` shows every action
  without root, and `--uninstall` removes what it installed while keeping the
  configuration, logs and baselines.

[0.2.0]: https://github.com/brightwalker25/omarchy-security-scan/releases/tag/v0.2.0
[0.1.0]: https://github.com/brightwalker25/omarchy-security-scan/releases/tag/v0.1.0
