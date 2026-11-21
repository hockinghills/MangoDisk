# process-triage

A read-only report of everything running on a Linux desktop, and where each program came from.

Most task managers can tell you *that* something is using memory. Most startup managers only know about
things the distro package manager or the desktop installed. This works the other way round: it starts from
every running process and traces it back to whatever put it there, including the things side installers
leave behind.

For each running program it works out:

- **What it really is.** `python3 something.py`, `node cli.js`, `bash script.sh` and `java -jar x.jar` are
  resolved to the script or package they run, not reported as "python3".
- **How it got there, and when.** Distro package (apt/dnf/zypper/pacman, plus whether you installed it or it
  came in as a dependency), pip `--user`, pipx, uv tool, virtualenv, conda, npm/pnpm/yarn/bun global, volta,
  npx cache, a node project, Homebrew, `cargo install`, rustup, `go install`, flatpak, snap, AppImage,
  docker/podman container, nix, a git clone, or a file someone dropped in `/usr/local`, `/opt` or your home
  folder. Install dates come from package records, pip `RECORD` files, Homebrew receipts and git reflogs where
  they exist, and otherwise from file dates. The report says which.
- **Where it came from.** Git remotes, pip `direct_url.json` (including `pip install git+https://...`),
  `package.json` repositories, cargo git sources and Go module paths.
- **What started it.** The systemd unit, XDG/KDE autostart entry, a terminal, an editor/IDE, another program,
  cron, ssh or the login session. It also lists lines in `.bashrc`, `.zshrc`, `.profile`, fish config,
  Plasma env scripts and your crontab that mention it.
- **What it costs.** Memory (PSS, so shared memory isn't counted twice), swap, CPU right now, and average
  CPU since it started. Helper tools a side-installed program spawns (`sleep`, `curl`, `ffmpeg`...) are
  counted against that program.
- **What to do about it.** How to stop it now, how to keep it from starting, and how to remove it, using the
  right command for the installer that put it there. Nothing is run for you.

It also lists **everything configured to start automatically** (systemd user and system units, XDG
autostart, Plasma login scripts, crontab, and shell-startup lines that background something), marks which
ones were added outside the package manager, and shows whether each one is running now.

## Run it

Python 3.8 or newer, standard library only. Nothing to install.

```sh
python3 tools/process-triage/process_triage.py            # everything, biggest first
python3 tools/process-triage/process_triage.py --mine     # only things you or side installers added
python3 tools/process-triage/process_triage.py --explain 4242      # one program, by pid
python3 tools/process-triage/process_triage.py --explain syncthing # ...or by name
sudo python3 tools/process-triage/process_triage.py       # also identify root's processes exactly
```

Without `sudo`, your own processes are fully identified. Root's processes can only be identified by
command name, and their memory is shown as RSS (marked `*`).

Each run saves a Markdown report and a JSON snapshot to `~/.local/state/process-triage/`. Run it every few
days and the report starts showing how often each program has been seen running ("running in 5 of 6 scans
since ..."). That stands in for "last used", which Linux mostly doesn't record. Use `--no-save` to skip it.

## History from Netdata

If a Netdata agent is running on the machine (it listens on `http://localhost:19999` by default), each row
also shows what the program did over the last 7 and 30 days: average CPU and the busiest hour, network traffic
for containers, and disk I/O for system services. The numbers come from Netdata's own charts for the systemd
service, the container, or (for anything else) every process with that program's name, and the report says
which. Use `--netdata URL` for a different agent and `--no-netdata` to skip it. Only Netdata's read-only query API
is used.

Program charts are matched only to a row's main process, never to a child it started. When a program-name chart
also counts processes in other rows (several `cloudflared` tunnels, say), the row says so. When Netdata lists a
chart but refuses the query, the row gives Netdata's reason and the next candidate chart is tried.

Memory over the week: the report starts with the machine's RAM and swap in use, one daily average per day, and
lists the rows whose memory (RAM + swap) rose steadily over those days. Verdicts take the week into account, so a
row that is quiet right now but moved gigabytes over the network this week is not called idle.

## Privacy

Everything stays on your machine. Before anything is printed or saved, command-line values that look like
credentials (`--token`, `--password=`, `api_key=`, long random strings) and usernames/passwords inside URLs
are replaced with `***`.

## Limits

- "Last used" isn't recorded by Linux. Use the scan history and the average-CPU column instead.
- A plain `git clone` has no install record. The clone date comes from the repository's first reflog entry,
  or the folder date if the reflog is missing.
- A Node CLI that rewrites its own process title is matched by command name. If two installs have the same
  command name, it uses the path your shell recorded when you launched it.
- Launch sources depend on systemd placing processes in cgroups, which KDE Plasma 6, GNOME and most current
  desktops do. On systems without systemd, the launch column falls back to the parent process tree.

## Tests

```sh
python3 -m unittest discover -s tools/process-triage
```

## Where this is going

This is the detection engine for a planned "Running programs" page in MangoDisk. Once it identifies a real
machine correctly, the logic moves into the Rust platform layer behind MangoDisk's existing
review-before-action workflow. The JSON snapshot is the data the page will be built from.
