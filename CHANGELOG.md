# Changelog

Notable changes to the Security Scan plugin and its scan suite. Versions follow
[semantic versioning](https://semver.org), and the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
