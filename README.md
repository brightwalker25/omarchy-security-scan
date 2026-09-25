# omarchy-security-scan

A scheduled security-scan suite for Arch and Omarchy, and a bar widget that
shows its verdict. Six scans run in the background on systemd timers, a report
grades what they found green, amber or red, and a lock in the bar takes the
same colour. Click the lock and the panel lists
every section of the report, what each finding is, and what is being done
about it.

It exists because a scan whose output nobody reads protects nothing. Each of
these tools is useful, but run by itself each one either writes to a log that
is never opened or reports the same known and harmless findings
every week until you stop reading it. The report reads the logs for you,
explains what can be explained (a file changed because a package was upgraded,
a CVE the Arch tracker still lists after the fix shipped), and grades what is
left.

```bash
git clone https://github.com/brightwalker25/omarchy-security-scan.git ~/Work/omarchy-security-scan
sudo ~/Work/omarchy-security-scan/bin/security-scan-install
ln -s ~/Work/omarchy-security-scan ~/.config/omarchy/plugins/brightwalker25.security-scan
omarchy plugin enable brightwalker25.security-scan --section right
```

The scans need root, so they are installed by a privileged installer rather
than by `omarchy plugin add`. The widget needs nothing beyond the plugin
itself. [INSTALL.md](INSTALL.md) covers the requirements, what the installer
changes, the first-run baselines, the configuration files, running scans by
hand, and uninstalling.

## What it scans

| Scan | Cadence | What it catches |
|---|---|---|
| `arch-audit` | daily | installed packages with a known CVE in the Arch security tracker, and how many a `pacman -Syu` would fix |
| `aide` | daily | files added, removed or changed under `/boot`, `/usr`, `/etc`, `/opt` and `/root`, and in the places in your home folder where malware settles to survive a reboot |
| `models` | daily | pickle-format AI model files that would run code when loaded, found with `picklescan` |
| `gitleaks` | weekly, Monday | keys, tokens, passwords and private names in the working trees of your git repositories |
| `rkhunter` | weekly, Monday | known rootkits, hidden files, and changes to the properties of system binaries |
| `lynis` | monthly | a hardening audit of the whole system, with a score out of 100 |

The daily scans start shortly after midnight, the Monday scans after 10:00 and
the monthly audit after 11:00 on the first of the month, each with a random
delay of up to two hours (six for lynis) so they do not all start at once. The
timers are persistent: a scan missed because the laptop was off or asleep runs
at the next opportunity. The scans run at idle CPU and disk priority, so they
do not compete with the desktop.

The home folder paths AIDE watches are `~/.config/autostart`,
`~/.config/systemd/user`, `~/.config/environment.d`,
`~/.config/fish/config.fish`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`,
`~/.ssh` and `~/.local/bin`. A program that cannot get root can still arrange
to start again from one of these, and they change rarely, so a change there is
worth a look.

gitleaks scans the working tree of each repository, not its history. History
that has already been published would be reported again every week, and a
report that repeats the same old finding every week teaches you to ignore it.

## Design

A shell script, `security-scan`, runs one scan and writes a log with a
`summary:` line and, where it can, a verdict on each line it found. A Python
script, `security-report`, reads those logs and a hand-written risk register
and grades the result. The bar widget and panel render the report's JSON and
decide nothing. All of the judgement is in the two scripts, and both run from a
terminal:

```bash
security-report                # the report in colour
security-report --all          # with the green items listed too
security-report --json         # what the widget reads
```

### How findings are graded

Every item in the report is green, amber or red, every section takes the worst
rating of its items, and the overall rating is the worst of the sections.

Green means there is no real exposure: the issue is fixed, not reachable, or
not installed. Amber means the exposure is real but contained, and the report
says how; it also covers changes that are probably yours but that only you can
confirm. Red means something needs doing now.

The report covers nine sections: whether the scans ran on schedule, known
package vulnerabilities, file integrity, rootkits, AI model files, secrets in
your code, system hardening, standing risks, and privacy. The standing risks
section is not a scan. It holds protections you rely on, and each one is
tested live when the report runs, so that a protection you are relying on (the
firewall being active, the disk being encrypted) is reported red if it stops
being in place.

A fourth rating, grey, means off or not installed. A grey item or section is
shown so that you know it was not checked, but it never counts as a problem
and never changes the overall rating. Only the privacy section uses it.

### The privacy section

The Privacy (Black Ops) section reports on
Black Ops, the privacy
plugin, if you use it. It reads one file, `~/.local/state/black-ops/summary.json`,
which Black Ops 0.3.0 and later writes. That file holds counts and states
only, and the report shows only counts. It never reads another Black Ops
file, never runs Black Ops, and names no host, program or package.

| Rating | When |
|---|---|
| grey | Black Ops is not installed or is switched off; listen mode or the software watch is off |
| green | Black Ops is on and every count is clean |
| amber | watch findings not yet reviewed, protections that slipped or were never put in place, a summary that cannot be read, or a summary more than eight days old |
| red | listen mode saw a program on this machine contact a telemetry, analytics or crash-report host, and nobody has reviewed it |

Red has the same meaning as in Black Ops itself, so the report is never red
for anything Black Ops would show as amber. A summary more than eight days old
means the Black Ops watchdog has stopped, so its counts are shown but graded
amber. Risk register entries can lower the rating of individual items, but
not of a leak, which is cleared by reviewing it in Black Ops.

The weekly report runs as your own user, so the summary is found in your home
folder, or under `$XDG_STATE_HOME` when that is set. Run through `sudo`, the
report reads the summary of the user who ran `sudo`. Run as root with no such
user, it reads nothing and says so. `BLACK_OPS_SUMMARY` names another file,
which is what the tests use.

### The risk register

A package CVE or a gitleaks finding is only as serious as its circumstances on
this machine. A vulnerability in a library that nothing reachable uses is not
the same as one in the SSH server. The report cannot know the difference, so
the difference is written down by hand in a risk register,
`/etc/security-scan/risk-register.toml`. Each entry records what the finding
is, what it means here, how confident the assessment is, the rating it
deserves, and what is being done about it. The report shows that text in place
of the raw finding.

A finding with no entry is not passed. A package CVE with no entry is shown as
"not yet assessed", red when the tracker rates it high or critical and amber
otherwise. A gitleaks finding with no entry is red. As a result, the
register can only make the report quieter for findings someone has actually
looked at.

Each CVE entry records the package version it was assessed against. If the
installed version is ever older than that, which happens after a downgrade,
the entry is flagged for re-assessment. Many entries in the Arch tracker stay
open long after the fix has shipped, so a common entry is one marked `stale`:
listed by the tracker, but already fixed in the installed version.

### A scan that stops running is a finding

A scan that has not run leaves no findings, and no findings looks the same as
a clean result. So the report grades each scan's age. A daily scan is amber
after two days without a log and red after seven. A weekly scan is amber after
nine days and red after 21, and the monthly audit after 35 and 62. A scan that
has never run is red. A scan whose last log records an error, or contains
a line marked `!!`, is red as well, because a scan that fails every night is
not protecting anything.

This is also what makes the bar widget safe to leave on a timer. The report
reads stored results and probes nothing live, so a colour that is a few minutes
old cannot hide a scan that went quiet: the report itself turns amber and then
red when that happens.

### AIDE explains changes before it reports them

A plain AIDE report on a rolling-release system is mostly package upgrades,
and after a large upgrade it runs to thousands of lines. `security-scan aide`
explains each change before it is reported:

- A file owned by a package that `pacman -Qkk` still verifies (content, size,
  link target, permissions and ownership all match the package) is counted as
  a package change. A bare modification-time mismatch is ignored, because it is
  common and harmless.
- A file owned by a package that fails that check is red.
- A package's configuration file that you have edited is amber.
- A changed file under `/boot` is a package change if pacman installed,
  upgraded or removed anything since the last check, because that is when the
  boot image is rebuilt. With no package change it is red.
- A file that no package owns is amber under `/usr/local`, `/opt`, `/etc`,
  `/root` and `/home`, where your own changes normally land, and red anywhere
  else, such as `/usr/bin` or `/usr/lib`.
- A browser's `policies.json` that a local pacman hook rewrites after every
  update, to switch telemetry and studies off, always fails pacman's checksum.
  It is not red while that hook is installed and the file holds only the
  browser's own policies and those two switches. Any other policy
  leaves it red. The weekly report applies the same check to a red line
  logged before this rule existed.

After each check it re-baselines, so the next run reports only what is new. The
previous baseline is kept as `/var/lib/aide/aide.db.prev.gz`, and the logs keep
every finding for the weekly report. In the report, amber changes are grouped
by folder, so a week of ordinary work reads as a few lines rather than
hundreds.

### rkhunter changes are accepted only when pacman verifies them

rkhunter records the properties of system binaries and warns when they change.
It has no pacman support, so after every upgrade it warns about every binary
the upgrade replaced. `security-scan rkhunter` checks each file named in that
warning with `pacman -Qkk`. If every one of them is owned by a package and
matches it byte for byte, the warning is accepted and rkhunter's record is
updated. If any one of them cannot be verified, nothing is accepted, the record
is left alone, and the report shows each unverified file as red. Files that
pacman did verify are not reported. Every other rkhunter warning is red.

### What the model scan covers

Model files in the older pickle format (`.ckpt`, `.pt`, `.pth`, `.bin`, `.pkl`,
`.pickle`) can run arbitrary code when they are loaded. `picklescan` looks
inside them for the imports that would do that: a dangerous import is red and
a suspicious one is amber. `.safetensors` and GGUF files are data only and
cannot run code, so there is nothing for it to find in them.

The scan covers only that. Python environments (`.venv`, `venv`,
`site-packages`) are skipped, along with `node_modules` and `.git`, because
they hold library test fixtures rather than models and flood the scan with
parse warnings. That means a malicious pip package is not covered: supply-chain
risk in Python packages is a different problem, and this scan does not claim
to address it. If `picklescan` crashes partway through a folder, the run is
recorded as failed, not as clean.

## The bar widget

The widget is a lock glyph tinted to match the report. It is a lock rather
than a shield so that it cannot be confused with VPN Check, which usually sits
next to it.

| Lock | Meaning |
|---|---|
| green | the report is green |
| amber | the report is amber, or could not be read |
| red | the report is red |

A report that fails to run would otherwise look the same as a green one, so a
failure always shows amber, and the panel says why. The green, amber and red are fixed colours rather
than theme colours, because a theme is free to make its urgent colour a soft
pink, and a warning that reads as decoration does not work as a warning.

The widget re-reads the report every five minutes whether or not the panel is
open. That is cheap: the report only reads stored logs, touches no network, and
takes a fraction of a second. It uses the copy installed in `/usr/local/bin`,
and falls back to the copy in the plugin if the installed one is too old to
support `--json`.

Clicking the lock opens the panel. Middle-clicking re-reads the report. The
panel shows:

- the overall rating, the report's one-line summary, and the period it covers;
- a Refresh button, and an Open full report button that writes a fresh HTML
  report and opens it in the browser;
- one block per section, with its rating and a one-line verdict. Sections with
  something to say start unfolded and green ones start folded. A finding shows
  what it is, the detail behind it, and a line headed "What is being done".
  Green items inside a section that is not green are hidden behind a link, so
  the findings that need attention come first;
- any error, or anything the report printed on stderr, such as a risk register
  that could not be parsed.

The panel can also be driven over IPC, for example from a key binding:

```bash
omarchy-shell brightwalker25.security-scan toggle
omarchy-shell brightwalker25.security-scan refresh
```

## The weekly report

On Monday at 13:00, after the Monday scans, a user timer writes the report as a
self-contained HTML page in `~/.local/share/security-report/`, named by date so
that past weeks stay comparable, and points `latest.html` at it. It then sends
a desktop notification with the overall rating and the summary line. The
notification is marked critical when the report is red, and has an Open action
that shows the page. If the laptop is off at 13:00, the report runs at the next
login.

Each scan also sends its own notification as it finishes when it finds
something: vulnerable packages, secrets in a repository, unexplained file
changes, rootkit warnings, lynis warnings, a dangerous or suspicious model
file, or a failed AIDE or model scan. Packages with a fix waiting, secrets,
unexplained changes, rootkit warnings and dangerous model files are sent as
critical. The
logs are written either way; a notification is skipped only when there is no
graphical session to send it to.

## Limits

A rootkit loaded at boot runs beneath the scans and can hide from anything that
runs on the same machine, including all six of these. AIDE watches `/boot` and
reports a boot file that changes with no package update as red, which catches a
tampered image on disk, but it cannot see anything that has hidden itself from
the running kernel. The report does not track Secure Boot.

rkhunter is dated. Its rootkit signatures have seen little maintenance for
years, so it mainly finds old, well-known rootkits. It is kept for its checks
of file properties, hidden files and startup configuration, which are still
useful, rather than for its signature list.

AIDE comes from the AUR, not the official repositories, so `pacman -Syu` does
not update it. Update it with your AUR helper, for example `yay -Syu`.

The risk register is judgment written by hand. An entry is only as good as the
assessment behind it, and a wrong entry makes a real finding look managed.
Check the fix version against the upstream project before marking an entry
`stale`, and re-assess when a package changes. The register is keyed by package
name, so once a package has an entry, a new CVE for that same package is shown
with the existing entry's text rather than as not yet assessed. The ratings in
the example register describe the machine it was written on and are not a
judgment about yours.

When `arch-audit` cannot reach the Arch security tracker, it records the run as
skipped. The report ignores skipped runs, so the package section keeps showing
the last real result, and a long offline stretch appears as a stale scan in
the schedule section.

The gitleaks scan looks only at working trees, and only for repositories whose
`.git` folder is at most three levels below the scan root, which means the
repository itself is at most two levels below it.

lynis is written with servers in mind. A score in the high 60s is typical for a
desktop, and most of its suggestions are server hardening. Its warnings are
shown as amber, except for the one it raises whenever arch-audit reports
anything, which the package section already grades properly.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests cover the privacy section against the fixtures in
`tests/fixtures/black-ops`. They run in a temporary folder and do not read
your home folder, `/etc` or the scan logs.

## Settings

| Key | Default | Effect |
|---|---|---|
| `refreshIntervalMs` | 300000 | How often the bar re-reads the report, between 30 seconds and an hour |
| `hideWhenGreen` | false | Hide the lock when the report is green, so it shows only when it is amber or red |

These affect only the widget. The scans run on their own timers whatever the
widget is set to. The scan settings live in `/etc/security-scan`; see
[INSTALL.md](INSTALL.md#configuration).

## Requirements

Arch Linux or Omarchy with systemd, the Omarchy shell for the widget, `uv` for
installing `picklescan`, and an AUR helper for AIDE. The installer adds the
rest from the official repositories; see
[INSTALL.md](INSTALL.md#requirements).

## Changelog

[CHANGELOG.md](CHANGELOG.md).

## Written with AI help

Yes, an AI helped write this. No, it is not Skynet, and I have checked the
code to make sure it is not plotting Judgment Day. If that still puts you off,
no hard feelings. The whole point of Linux is that you decide what runs on
your computer.

## Licence

MIT. The bar widget and panel scaffolding derive from Omarchy's own shell
plugins; see `LICENSE`.
