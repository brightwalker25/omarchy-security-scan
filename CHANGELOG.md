# Changelog

Notable changes to the Security Scan plugin and its scan suite. Versions follow
[semantic versioning](https://semver.org), and the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
