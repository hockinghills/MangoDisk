#!/usr/bin/env python3
"""Read-only report of what is running on a Linux desktop and where each program came from.

For every running process this works out:
  * what program it really is (an interpreter is resolved to the script it runs),
  * how it got onto the machine (distro package, pip, pipx, uv, venv, conda, npm, pnpm,
    bun, Homebrew, cargo, go, flatpak, snap, AppImage, container, nix, git clone, or a
    plain file someone dropped in place) and when,
  * what started it (systemd unit, XDG/KDE autostart, cron, a terminal, another program,
    the login session) and where that is configured,
  * how much memory and CPU it uses, and whether it has been sitting idle.

It also lists everything configured to start automatically, so things that are set to
start but are not running right now still show up.

Nothing is changed. The script only reads /proc, files under your home directory and a
few package-manager queries. Suggested commands in the report are for you to review.

Standard library only; Python 3.8 or newer.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import glob
import io
import json
import os
import pwd
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

VERSION = "0.6.1"
CLK_TCK = os.sysconf("SC_CLK_TCK")
PF_KTHREAD = 0x00200000
NOW = time.time()

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def read_text(path: str, limit: int = 1 << 20) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return None


def run(cmd: List[str], timeout: float = 15.0) -> str:
    """Run a read-only query and return stdout; failures return an empty string."""
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def mtime(path: Optional[str], follow: bool = True) -> Optional[float]:
    if not path:
        return None
    try:
        return os.stat(path).st_mtime if follow else os.lstat(path).st_mtime
    except OSError:
        return None


def realpath(path: str) -> str:
    try:
        return os.path.realpath(path)
    except OSError:
        return path


def unescape_unit(text: str) -> str:
    """Undo systemd unit-name escaping such as \\x2d for '-'."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)


def fmt_bytes(kb: Optional[float]) -> str:
    if kb is None:
        return "?"
    value = float(kb) * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB", "MB") else f"{value:.1f} {unit}"
        value /= 1024
    return "?"


def fmt_date(epoch: Optional[float]) -> str:
    if not epoch:
        return "unknown"
    return dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d")


def fmt_age(seconds: Optional[float]) -> str:
    if seconds is None or seconds < 0:
        return "?"
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    if seconds < 172800:
        return f"{seconds / 3600:.0f}h"
    return f"{seconds / 86400:.0f}d"


SECRET_KEY = re.compile(r"(?i)(token|secret|passw(or)?d|passwd|api[-_]?key|auth|credential|cookie|session[-_]?id|private[-_]?key)")
URL_CREDS = re.compile(r"(://)[^/\s:@]+(:[^/\s@]*)?@")
LONG_TOKEN = re.compile(r"[A-Za-z0-9+_\-]{40,}")


CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def redact_text(text: str) -> str:
    text = CONTROL_CHARS.sub(" ", text)
    text = URL_CREDS.sub(r"\1***@", text)
    return LONG_TOKEN.sub("***", text)


def redact_argv(argv: List[str]) -> List[str]:
    """Hide values that look like credentials before anything is printed or saved."""
    out: List[str] = []
    hide_next = False
    for arg in argv:
        if hide_next:
            out.append("***")
            hide_next = False
            continue
        key = arg.split("=", 1)[0]
        if SECRET_KEY.search(key) and not arg.startswith("/"):
            if "=" in arg:
                out.append(key + "=***")
            elif arg.startswith("-"):
                out.append(arg)
                hide_next = True
            else:
                out.append(arg)
            continue
        out.append(redact_text(arg))
    return out


class Paths:
    """Display helper that shortens the invoking user's home directory to '~'."""

    home = os.path.expanduser("~")

    @classmethod
    def show(cls, path: Optional[str]) -> str:
        if not path:
            return ""
        if cls.home and cls.home != "/" and (path == cls.home or path.startswith(cls.home + "/")):
            return "~" + path[len(cls.home):]
        return path

    @classmethod
    def show_all(cls, text: str) -> str:
        if not cls.home or cls.home == "/":
            return text
        return re.sub(rf"(?<![\w/]){re.escape(cls.home)}(?=/|\b)", "~", text)


# ---------------------------------------------------------------------------
# Process snapshot
# ---------------------------------------------------------------------------


@dataclass
class Proc:
    pid: int
    ppid: int
    uid: int
    comm: str
    cmdline: List[str]
    exe: Optional[str]
    exe_deleted: bool
    cwd: Optional[str]
    cgroup: str
    start_epoch: float
    cpu_ticks: int
    rss_kb: int
    pss_kb: Optional[int]
    swap_kb: int
    appimage: Optional[str] = None
    flatpak_id: Optional[str] = None
    cpu_now: float = 0.0


def boot_time() -> float:
    for line in (read_text("/proc/stat") or "").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    return NOW


def parse_stat(text: str) -> Optional[Tuple[str, str, int, int, int, int]]:
    """Return (comm, state, ppid, flags, cpu_ticks, start_ticks) from /proc/<pid>/stat."""
    close = text.rfind(")")
    if close < 0:
        return None
    comm = text[text.find("(") + 1:close]
    fields = text[close + 2:].split()
    if len(fields) < 20:
        return None
    return comm, fields[0], int(fields[1]), int(fields[6]), int(fields[11]) + int(fields[12]), int(fields[19])


def parse_cgroup(text: str) -> str:
    """Prefer the unified (v2) hierarchy; fall back to the systemd v1 hierarchy."""
    unified, v1 = "", ""
    for line in text.splitlines():
        if line.startswith("0::"):
            unified = line[3:]
        elif ":name=systemd:" in line:
            v1 = line.split(":", 2)[2]
    if unified not in ("", "/"):
        return unified
    return v1 if v1 not in ("", "/") else unified


def read_proc(pid: int, btime: float) -> Optional[Proc]:
    base = f"/proc/{pid}"
    stat_text = read_text(base + "/stat")
    if not stat_text:
        return None
    parsed = parse_stat(stat_text)
    if not parsed:
        return None
    comm, state, ppid, flags, ticks, start = parsed
    if flags & PF_KTHREAD or pid == 2 or ppid == 2 or state in ("Z", "X"):
        return None
    status = read_text(base + "/status") or ""
    uid, rss_kb, swap_kb = -1, 0, 0
    for line in status.splitlines():
        if line.startswith("Uid:"):
            uid = int(line.split()[1])
        elif line.startswith("VmRSS:"):
            rss_kb = int(line.split()[1])
        elif line.startswith("VmSwap:"):
            swap_kb = int(line.split()[1])
    raw = b""
    try:
        with open(base + "/cmdline", "rb") as handle:
            raw = handle.read(65536)
    except OSError:
        pass
    cmdline = [part.decode("utf-8", "replace") for part in raw.split(b"\0")]
    while cmdline and cmdline[-1] == "":
        cmdline.pop()
    exe, deleted = None, False
    try:
        exe = os.readlink(base + "/exe")
        if exe.endswith(" (deleted)"):
            exe, deleted = exe[: -len(" (deleted)")], True
    except OSError:
        pass
    try:
        cwd: Optional[str] = os.readlink(base + "/cwd")
    except OSError:
        cwd = None
    pss = None
    rollup = read_text(base + "/smaps_rollup")
    if rollup:
        for line in rollup.splitlines():
            if line.startswith("Pss:"):
                pss = int(line.split()[1])
                break
    proc = Proc(
        pid=pid, ppid=ppid, uid=uid, comm=comm, cmdline=cmdline, exe=exe, exe_deleted=deleted,
        cwd=cwd, cgroup=parse_cgroup(read_text(base + "/cgroup") or ""),
        start_epoch=btime + start / CLK_TCK, cpu_ticks=ticks, rss_kb=rss_kb, pss_kb=pss, swap_kb=swap_kb,
    )
    if exe and "/.mount_" in exe:
        environ = read_text(base + "/environ", limit=1 << 18) or ""
        for item in environ.split("\0"):
            if item.startswith("APPIMAGE="):
                proc.appimage = item[len("APPIMAGE="):]
                break
    if "flatpak" in proc.cgroup:
        info = read_text(base + "/root/.flatpak-info") or ""
        match = re.search(r"(?m)^name=(.+)$", info)
        if match:
            proc.flatpak_id = match.group(1).strip()
    return proc


def snapshot(interval: float) -> List[Proc]:
    btime = boot_time()
    me = os.getpid()
    procs: Dict[int, Proc] = {}
    for name in os.listdir("/proc"):
        if name.isdigit() and int(name) != me:
            proc = read_proc(int(name), btime)
            if proc and not any(arg.endswith("process_triage.py") for arg in proc.cmdline[:3]):
                procs[proc.pid] = proc
    if interval > 0:
        time.sleep(interval)
        for pid, proc in procs.items():
            text = read_text(f"/proc/{pid}/stat")
            parsed = parse_stat(text) if text else None
            if parsed:
                proc.cpu_now = (parsed[4] - proc.cpu_ticks) / CLK_TCK / interval * 100
                proc.cpu_ticks = parsed[4]
    return list(procs.values())


# ---------------------------------------------------------------------------
# Resolve interpreters to the program they run
# ---------------------------------------------------------------------------

SHELLS = {"bash", "sh", "dash", "zsh", "fish", "ksh", "mksh", "tcsh", "csh", "nu"}


def interpreter_family(name: str) -> Optional[str]:
    if re.fullmatch(r"python[0-9.]*(-[a-z]+)?|pypy[0-9.]*", name):
        return "python"
    if name in ("node", "nodejs", "bun", "deno"):
        return "node"
    if name in ("gjs", "gjs-console", "cjs"):
        return "gjs"
    if re.fullmatch(r"ruby[0-9.]*", name):
        return "ruby"
    if re.fullmatch(r"perl[0-9.]*", name):
        return "perl"
    if re.fullmatch(r"php[0-9.]*", name):
        return "php"
    if name in SHELLS:
        return "shell"
    if name == "java":
        return "java"
    if re.fullmatch(r"lua(jit|[0-9.]*)", name):
        return "lua"
    return None


# Options that consume the following argument, per interpreter family.
OPTION_ARGS = {
    "python": {"-W", "-X", "--check-hash-based-pycs"},
    "node": {"-r", "--require", "--loader", "--experimental-loader", "--import", "--env-file", "--conditions", "-C", "--inspect-port", "--title"},
    "ruby": {"-I", "-r", "-C", "-E", "--encoding"},
    "perl": {"-I", "-M", "-m"},
    "php": {"-c", "-d", "-z"},
    "shell": {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"},
    "java": {"-cp", "-classpath", "--class-path", "-p", "--module-path", "--add-modules", "--add-opens", "--add-exports"},
    "lua": {"-l"},
    "gjs": {"-I", "--include-path", "--profile", "--debugger"},
}
INLINE_FLAGS = {
    "python": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}, "ruby": {"-e"},
    "perl": {"-e", "-E"}, "php": {"-r"}, "lua": {"-e"}, "gjs": {"-c", "--command"},
}
RUNNER_WORDS = {"run", "x", "exec", "start", "serve"}


@dataclass
class Target:
    family: Optional[str]          # interpreter family or None for a native binary
    path: Optional[str]            # file that identifies the program (script or binary)
    module: Optional[str] = None   # python -m module / java main class
    inline: bool = False           # code passed on the command line
    interpreter: Optional[str] = None
    invoked: Optional[str] = None  # absolute argv[0] when it differs (venv python symlink)
    project: Optional[str] = None  # project folder for dev servers and `npm run` style launches
    runner: Optional[str] = None   # npm, pnpm, yarn... when the script is a package-manager runner


def find_script(family: str, args: List[str], cwd: Optional[str]) -> Tuple[str, Optional[str]]:
    takes_arg = OPTION_ARGS.get(family, set())
    inline = INLINE_FLAGS.get(family, set())
    skip = False
    for index, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if arg == "--":
            continue
        if family == "python" and arg == "-m" and index + 1 < len(args):
            return "module", args[index + 1]
        if family == "java" and arg == "-jar" and index + 1 < len(args):
            return "path", _abs(args[index + 1], cwd)
        if family == "shell" and arg == "-c":
            if index + 1 < len(args):
                try:
                    words = [w for w in shlex.split(args[index + 1]) if w not in ("exec", "nohup", "env")]
                except ValueError:
                    words = []
                if words and "/" in words[0]:
                    return "path", _abs(words[0], cwd)
            return "inline", None
        if arg in inline:
            return "inline", None
        if arg in takes_arg:
            skip = True
            continue
        if arg.startswith("-") and len(arg) > 1:
            continue
        if family == "node" and arg in RUNNER_WORDS:
            continue
        if family == "java":
            return "module", arg
        return "path", _abs(arg, cwd)
    return "none", None


def _abs(path: str, cwd: Optional[str]) -> Optional[str]:
    if path.startswith("/"):
        return path
    if cwd:
        return os.path.normpath(os.path.join(cwd, path))
    return None


def env_value(pid: int, name: str) -> Optional[str]:
    """Read one variable from a process environment (only readable for your own processes)."""
    prefix = name + "="
    for item in (read_text(f"/proc/{pid}/environ", limit=1 << 18) or "").split("\0"):
        if item.startswith(prefix):
            return item[len(prefix):]
    return None


RUNNER_FILES = {"npm-cli.js", "npx-cli.js", "pnpm.cjs", "pnpm.mjs", "pnpm.js", "yarn.js", "yarn.cjs", "corepack.js", "npm", "npx", "pnpm", "yarn"}
RUNNER_PACKAGE = re.compile(r"/node_modules/(npm|pnpm|yarn|corepack|@pnpm/exe|@yarnpkg/cli-dist)/|/Cellar/(pnpm|yarn)/")
PROJECT_FAMILIES = {"node", "python", "ruby", "php", "perl", "java", "lua"}
BUILD_DIRS = {"dist", "build", "out", "standalone", ".next", ".output", "server", "lib", "bundle"}
PROJECT_MARKERS = ("package.json", "pyproject.toml", "Cargo.toml", "go.mod", "Gemfile", "composer.json", ".git")


def runner_name(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    match = RUNNER_PACKAGE.search(path)
    if match:
        return (match.group(1) or match.group(2)).split("/")[-1].replace("exe", "pnpm").replace("cli-dist", "yarn")
    base = os.path.basename(path)
    if base in RUNNER_FILES:
        return base.split("-")[0].split(".")[0]
    return None


def project_dir(proc: Proc) -> Optional[str]:
    """Folder of the project an interpreter is serving, from npm's environment or the working directory."""
    package_json = env_value(proc.pid, "npm_package_json")
    if package_json and os.path.exists(package_json):
        return os.path.dirname(package_json)
    cwd = proc.cwd
    home = Paths.home
    if not cwd or cwd in ("/", home) or is_system_path(cwd):
        return None
    if not cwd.startswith(home + "/") and cwd.startswith(("/tmp", "/proc", "/run", "/dev")):
        return None
    for marker in PROJECT_MARKERS:
        found = find_upwards(cwd, marker, stop=[home])
        # Build output folders (dist/, .next/standalone) often carry their own package.json.
        while found and os.path.basename(found) in BUILD_DIRS and find_upwards(os.path.dirname(found), marker, stop=[home]):
            found = find_upwards(os.path.dirname(found), marker, stop=[home])
        if found and found != home:
            return found
    return cwd


SYSTEM_BIN_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin")


def system_which(name: str) -> Optional[str]:
    """Find a command in the system directories first: other users' daemons rarely run from your PATH."""
    if not name or "/" in name:
        return None
    for directory in SYSTEM_BIN_DIRS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return realpath(candidate)
    found = shutil.which(name)
    return realpath(found) if found else None


def resolve_target(proc: Proc) -> Target:
    argv0 = proc.cmdline[0] if proc.cmdline else ""
    first = argv0.split()[0].rstrip(":") if argv0.strip() else ""
    exe = proc.exe
    if not exe and first.startswith("/"):
        # Another user's process: the program file is hidden, but argv[0] (resolved through
        # symlinks such as /usr/local/bin/x -> /usr/bin/x) usually names it.
        exe = realpath(first) if os.path.exists(first) else first
    if not exe and first:
        exe = system_which(first)
    names = [os.path.basename(exe or ""), os.path.basename(argv0), proc.comm]
    family = next((interpreter_family(n) for n in names if n and interpreter_family(n)), None)
    if family is None:
        return Target(family=None, path=exe)
    invoked = argv0 if argv0.startswith("/") and argv0 != exe else None
    kind, value = find_script(family, proc.cmdline[1:], proc.cwd)
    target = Target(family=family, path=None, interpreter=exe, invoked=invoked)
    if kind == "path" and value and os.path.exists(value):
        target.path = realpath(value)
    elif kind == "module":
        target.module = value
    elif kind == "inline":
        target.inline = True
    if target.path is None and kind == "none" and first and "/" not in first and exe and first != os.path.basename(exe):
        # Node and Perl daemons often overwrite argv with a process title; look the title up as a command name.
        title = first
        launched = env_value(proc.pid, "_")
        if launched and os.path.basename(launched) == title and os.path.exists(launched):
            target.path = realpath(launched)
            return target
        search = [os.path.dirname(exe), os.path.join(Paths.home, ".local/bin"), os.path.join(Paths.home, ".npm-global/bin"),
                  os.path.join(Paths.home, ".bun/bin"), os.path.join(Paths.home, ".local/share/pnpm")] + list(SYSTEM_BIN_DIRS)
        for directory in search:
            candidate = os.path.join(directory, title)
            if os.path.isfile(candidate):
                target.path = realpath(candidate)
                break
    if target.path is None:
        # Interactive shells, REPLs and inline code are identified by the interpreter itself.
        target.path = exe
    target.runner = runner_name(target.path) if family == "node" else None
    if family in PROJECT_FAMILIES and (target.runner or (target.path == exe and not target.module)):
        # `npm run dev`, `next-server`, and other launches whose script can't be read from argv:
        # the project folder is the best identity available.
        target.project = project_dir(proc)
    return target


# ---------------------------------------------------------------------------
# Provenance: how a program got onto the machine
# ---------------------------------------------------------------------------


@dataclass
class Provenance:
    kind: str                     # stable code, see KIND_LABELS
    name: str                     # program/package name shown to the user
    version: Optional[str] = None
    installed_at: Optional[float] = None
    date_note: str = ""           # how the date was worked out
    source: Optional[str] = None  # URL or origin the install came from
    location: Optional[str] = None
    remove_hint: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    stop_hint: Optional[str] = None     # overrides the generic hint (containers)
    disable_hint: Optional[str] = None
    manual: Optional[bool] = None  # distro package explicitly installed (vs dependency)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.location or ''}:{self.name}"


KIND_LABELS = {
    "system-package": "distro package",
    "pip-user": "pip --user",
    "pip-system": "pip (system-wide)",
    "pip": "pip",
    "pipx": "pipx",
    "uv-tool": "uv tool",
    "venv": "python virtualenv",
    "conda": "conda",
    "npm-global": "npm -g",
    "pnpm-global": "pnpm -g",
    "yarn-global": "yarn global",
    "bun-global": "bun -g",
    "volta": "volta",
    "npx-cache": "npx / pnpm dlx (download cache)",
    "project": "project folder",
    "service": "service you added",
    "node-project": "node project",
    "homebrew": "Homebrew",
    "cargo": "cargo install",
    "rustup": "rustup toolchain",
    "go": "go install",
    "flatpak": "flatpak",
    "snap": "snap",
    "appimage": "AppImage",
    "container": "container",
    "nix": "nix",
    "git-clone": "git clone",
    "manual-local": "manual install (/usr/local)",
    "manual-opt": "manual install (/opt)",
    "manual": "file in your home folder",
    "unknown": "unknown",
}
# Kinds that were added by hand or by side installers rather than the distro.
SIDE_INSTALL_KINDS = set(KIND_LABELS) - {"system-package", "unknown"}

SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/etc/", "/libexec/")


def is_system_path(path: Optional[str]) -> bool:
    return bool(path) and path.startswith(SYSTEM_PREFIXES)


DESKTOP_BUNDLED = re.compile(
    r"^(plasma-|kde|kwin|kf6-|libkf|breeze|kio|kscreen|kwallet|kactivit|kinfocenter|systemsettings|khelpcenter|kmenuedit|"
    r"dolphin|konsole|kate|kwrite|okular|gwenview|ark$|spectacle|kdeconnect|partitionmanager|kcalc|elisa|haruna|sddm|"
    r"gnome-|nautilus|gedit|evince|eog|totem|tracker|localsearch|evolution|ubuntu-|kubuntu-|xdg-|xwayland|pipewire|wireplumber)"
)


class PackageOwners:
    """Ask the distro package manager which package owns a file."""

    def __init__(self) -> None:
        self.manager = self._detect()
        self.cache: Dict[str, Optional[str]] = {}
        self.manual: Optional[Set[str]] = None
        self.apt_history_glob = "/var/log/apt/history.log*"
        self.front = {"dpkg": "sudo apt remove", "pacman": "sudo pacman -Rs"}.get(self.manager or "", "")
        if self.manager == "rpm":
            self.front = "sudo dnf remove" if shutil.which("dnf") else ("sudo zypper remove" if shutil.which("zypper") else "sudo rpm -e")

    @staticmethod
    def _detect() -> Optional[str]:
        if os.path.exists("/var/lib/dpkg/status") and shutil.which("dpkg"):
            return "dpkg"
        if os.path.isdir("/var/lib/pacman/local") and shutil.which("pacman"):
            return "pacman"
        if shutil.which("rpm"):
            return "rpm"
        return None

    def _query(self, path: str) -> Optional[str]:
        candidates = [path]
        # Merged-/usr systems may record files under either /bin or /usr/bin.
        if path.startswith("/usr/"):
            candidates.append(path[4:])
        else:
            candidates.append("/usr" + path)
        for candidate in candidates:
            if self.manager == "dpkg":
                for line in run(["dpkg", "-S", candidate]).splitlines():
                    if ": " in line and not line.startswith("diversion"):
                        return line.split(": ", 1)[0].split(", ")[0].split(":")[0]
            elif self.manager == "rpm":
                for line in run(["rpm", "-qf", "--qf", "%{NAME}\n", candidate]).splitlines():
                    if line and " " not in line:
                        return line.strip()
            elif self.manager == "pacman":
                out = run(["pacman", "-Qqo", candidate]).strip()
                if out:
                    return out.splitlines()[0]
        return None

    def lookup_many(self, paths: Iterable[str]) -> None:
        todo = sorted({p for p in paths if p and p not in self.cache})
        if not self.manager or not todo:
            for path in todo:
                self.cache[path] = None
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for path, owner in zip(todo, pool.map(self._query, todo)):
                self.cache[path] = owner

    def owner(self, path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        if path not in self.cache:
            self.lookup_many([path])
        return self.cache[path]

    def installed_at(self, package: str) -> Optional[float]:
        if self.manager == "dpkg":
            for candidate in glob.glob(f"/var/lib/dpkg/info/{glob.escape(package)}.list") + glob.glob(
                f"/var/lib/dpkg/info/{glob.escape(package)}:*.list"
            ):
                return mtime(candidate)
        elif self.manager == "rpm":
            out = run(["rpm", "-q", "--qf", "%{INSTALLTIME}\n", package]).strip().splitlines()
            if out and out[0].isdigit():
                return float(out[0])
        elif self.manager == "pacman":
            for desc in glob.glob(f"/var/lib/pacman/local/{glob.escape(package)}-*/desc"):
                text = read_text(desc) or ""
                if re.search(rf"%NAME%\n{re.escape(package)}\n", text):
                    match = re.search(r"%INSTALLDATE%\n(\d+)", text)
                    if match:
                        return float(match.group(1))
        return None

    def _apt_history(self) -> Dict[str, Tuple[float, str, str, bool]]:
        """First apt record per package: name -> (date, what ran it, asked|bulk|dependency, part of a burst)."""
        if hasattr(self, "_records"):
            return self._records
        import gzip
        records: Dict[str, Tuple[float, str, str, bool]] = {}
        self.history_start: Optional[float] = None
        transactions: List[Tuple[float, Set[str], Set[str], Set[str], str]] = []
        for path in sorted(glob.glob(self.apt_history_glob), reverse=True):
            try:
                opener = gzip.open if path.endswith(".gz") else open
                with opener(path, "rt", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            for block in text.split("\n\n"):
                fields = dict(line.split(": ", 1) for line in block.strip().splitlines() if ": " in line)
                try:
                    when = dt.datetime.strptime(fields.get("Start-Date", "").replace("  ", " "), "%Y-%m-%d %H:%M:%S").timestamp()
                except ValueError:
                    continue
                command = fields.get("Commandline", "")
                named: Set[str] = set()
                words = command.split()
                if "install" in words:
                    for word in words[words.index("install") + 1:]:
                        if not word.startswith("-"):
                            named.add(os.path.basename(word).split("_")[0] if word.endswith(".deb") else word.split("=")[0].split(":")[0])
                entries = re.findall(r"([^\s,:]+)(?::[^\s,]+)? \(([^)]*)\)", fields.get("Install", ""))
                # apt marks only what was asked for as non-automatic, which also covers local .deb files
                # whose file name differs from the package name and Discover installs.
                asked = named | {name for name, detail in entries if "automatic" not in detail}
                automatic = {name for name, detail in entries if "automatic" in detail}
                if command.startswith("packagekit"):
                    origin = "Discover/PackageKit"
                else:
                    origin = command or ("Discover/PackageKit" if fields.get("Requested-By") else "an automatic update")
                if asked or automatic:
                    transactions.append((when, asked, automatic, named, origin))
        transactions.sort(key=lambda t: t[0])
        if transactions:
            self.history_start = transactions[0][0]
        times = [t[0] for t in transactions if t[1]]
        for when, asked, automatic, named, origin in transactions:
            # Many installs within minutes of each other is an install script, not someone picking packages;
            # one transaction naming many packages is a desktop install, release upgrade or script.
            burst = sum(1 for t in times if abs(t - when) <= 20 * 60) >= 6
            bulk = len(asked) > 8 or burst
            for name, kind in [(n, "bulk" if bulk else "asked") for n in asked] + [(n, "dependency") for n in automatic - asked]:
                if name not in records:
                    records[name] = (when, origin, kind, burst)
                elif kind == "asked" and records[name][2] != "asked":
                    first = records[name]
                    records[name] = (first[0], first[1], "asked", first[3])
        self._records = records
        return records

    def came_with_note(self, package: str) -> Optional[str]:
        record = self._apt_history().get(package) if self.manager == "dpkg" else None
        if not record:
            return None
        when, origin, kind, burst = record
        suffix = " as a dependency" if kind == "dependency" else ""
        burst_note = "; one of a burst of apt installs within minutes (an install script)" if burst else ""
        return f"installed {fmt_date(when)}{suffix} by `{redact_text(origin)[:140]}`{burst_note}"

    def history_covers_install(self) -> bool:
        """True when apt history reaches back to when this system was installed."""
        self._apt_history()
        installed = mtime("/var/log/installer") or mtime("/etc/machine-id")
        return bool(self.history_start and installed and self.history_start <= installed + 3 * 86400)

    def requested_at(self, package: str) -> Optional[float]:
        record = self._apt_history().get(package) if self.manager == "dpkg" else None
        return record[0] if record else None

    def is_manual(self, package: str) -> Optional[bool]:
        record = self._apt_history().get(package) if self.manager == "dpkg" else None
        if record and record[2] == "asked":
            return True
        if self.manager == "dpkg" and DESKTOP_BUNDLED.match(package):
            return None  # most likely came with the desktop install, whatever apt-mark says
        if record and record[2] == "bulk":
            return None  # part of a bulk or scripted install
        if record and record[2] == "dependency":
            return False  # pulled in as a dependency of something else
        if self.manager == "dpkg" and self.history_covers_install():
            return None  # never asked for since the system was installed: it came with the system
        if self.manual is None:
            if self.manager == "dpkg" and shutil.which("apt-mark"):
                self.manual = set(run(["apt-mark", "showmanual"], timeout=30).split())
                # Ubuntu's installer marks everything on the install image as manual; drop those.
                initial = "/var/log/installer/initial-status.gz"
                if os.path.exists(initial):
                    import gzip
                    try:
                        with gzip.open(initial, "rt", errors="replace") as handle:
                            base = {line[9:].strip() for line in handle if line.startswith("Package: ")}
                        self.manual -= base
                    except OSError:
                        pass
            elif self.manager == "pacman":
                self.manual = set(run(["pacman", "-Qqe"], timeout=30).split())
            else:
                self.manual = set()
        if not self.manual:
            return None
        return package in self.manual


@dataclass
class PyDist:
    name: str
    version: Optional[str]
    installer: Optional[str]
    site: str
    installed_at: Optional[float]
    source_url: Optional[str] = None
    editable_dir: Optional[str] = None


class PythonIndex:
    """Map files and top-level modules in a site-packages directory to their distribution."""

    def __init__(self) -> None:
        self.sites: Dict[str, Tuple[Dict[str, PyDist], Dict[str, PyDist]]] = {}

    @staticmethod
    def _headers(text: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for line in text.splitlines():
            if not line.strip():
                break
            if ":" in line and not line.startswith((" ", "\t")):
                key, value = line.split(":", 1)
                headers.setdefault(key.strip().lower(), value.strip())
        return headers

    def _dist(self, site: str, info_dir: str, metadata_name: str) -> PyDist:
        headers = self._headers(read_text(os.path.join(info_dir, metadata_name), limit=65536) or "")
        stem = os.path.basename(info_dir).rsplit(".", 1)[0]
        name = headers.get("name") or stem.split("-")[0]
        version = headers.get("version") or (stem.split("-")[1] if "-" in stem else None)
        installer = (read_text(os.path.join(info_dir, "INSTALLER")) or "").strip() or None
        dist = PyDist(
            name=name, version=version, installer=installer, site=site,
            installed_at=mtime(os.path.join(info_dir, "RECORD")) or mtime(info_dir),
        )
        try:
            direct = json.loads(read_text(os.path.join(info_dir, "direct_url.json")) or "null")
        except ValueError:
            direct = None
        if isinstance(direct, dict) and direct.get("url"):
            url = str(direct["url"])
            if (direct.get("dir_info") or {}).get("editable") and url.startswith("file://"):
                dist.editable_dir = url[len("file://"):]
            else:
                vcs = direct.get("vcs_info") or {}
                commit = vcs.get("commit_id")
                dist.source_url = redact_text(url) + (f" @ {commit[:10]}" if commit else "")
        return dist

    def load(self, site: str) -> Tuple[Dict[str, PyDist], Dict[str, PyDist]]:
        if site in self.sites:
            return self.sites[site]
        files: Dict[str, PyDist] = {}
        modules: Dict[str, PyDist] = {}
        try:
            entries = os.listdir(site)
        except OSError:
            entries = []
        for entry in entries:
            info_dir = os.path.join(site, entry)
            if entry.endswith(".dist-info"):
                dist = self._dist(site, info_dir, "METADATA")
                record = read_text(os.path.join(info_dir, "RECORD"), limit=16 << 20) or ""
                for row in csv.reader(io.StringIO(record)):
                    if not row:
                        continue
                    rel = row[0]
                    files[os.path.normpath(os.path.join(site, rel))] = dist
                    top = rel.split("/")[0]
                    if not top.startswith("..") and not top.endswith((".dist-info", ".pth")) and top != "__pycache__":
                        modules.setdefault(top[:-3] if top.endswith(".py") else top, dist)
            elif entry.endswith(".egg-info") and os.path.isdir(info_dir):
                dist = self._dist(site, info_dir, "PKG-INFO")
                for rel in (read_text(os.path.join(info_dir, "installed-files.txt")) or "").splitlines():
                    files[os.path.normpath(os.path.join(info_dir, rel))] = dist
            else:
                continue
            for name in (read_text(os.path.join(info_dir, "top_level.txt")) or "").split():
                modules[name] = dist
        self.sites[site] = (files, modules)
        return files, modules

    @staticmethod
    def sites_near(path: Optional[str], extra_bins: Iterable[Optional[str]]) -> List[str]:
        sites: List[str] = []
        if path:
            parts = path.split("/")
            for index, segment in enumerate(parts):
                if segment in ("site-packages", "dist-packages"):
                    sites.append("/".join(parts[: index + 1]))
        bins = [os.path.dirname(path)] if path else []
        bins += [os.path.dirname(b) for b in extra_bins if b]
        for bin_dir in bins:
            if os.path.basename(bin_dir) in ("bin", "Scripts"):
                root = os.path.dirname(bin_dir)
                for pattern in ("lib/python*/site-packages", "lib64/python*/site-packages", "lib/python*/dist-packages"):
                    sites += sorted(glob.glob(os.path.join(glob.escape(root), pattern)))
        seen: List[str] = []
        for site in sites:
            if site not in seen and os.path.isdir(site):
                seen.append(site)
        return seen

    def lookup(self, path: Optional[str], module: Optional[str], extra_bins: Iterable[Optional[str]], user_sites: List[str]) -> Optional[PyDist]:
        sites = self.sites_near(path, extra_bins)
        if path:
            for site in sites:
                files, modules = self.load(site)
                if path in files:
                    return files[path]
                if path.startswith(site + "/"):
                    top = path[len(site) + 1:].split("/")[0]
                    top = top[:-3] if top.endswith(".py") else top
                    if top in modules:
                        return modules[top]
        if module:
            top = module.split(".")[0]
            for site in sites + [s for s in user_sites if s not in sites]:
                _, modules = self.load(site)
                if top in modules:
                    return modules[top]
        return None


def env_root_for_site(site: str) -> str:
    # <root>/lib/pythonX.Y/site-packages
    return os.path.dirname(os.path.dirname(os.path.dirname(site)))


def find_upwards(start: Optional[str], marker: str, stop: Iterable[str] = ()) -> Optional[str]:
    if not start:
        return None
    current = start if os.path.isdir(start) else os.path.dirname(start)
    stops = set(stop) | {"/"}
    while current and current not in stops:
        if os.path.exists(os.path.join(current, marker)):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


@dataclass
class GitInfo:
    root: str
    remote: Optional[str]
    cloned_at: Optional[float]
    last_activity: Optional[float]
    how: str


def git_info(path: Optional[str], homes: Iterable[str]) -> Optional[GitInfo]:
    root = find_upwards(path, ".git", stop=homes)
    if not root or root in set(homes):
        return None  # a repository at $HOME is a dotfiles repo, not an install
    git_dir = os.path.join(root, ".git")
    if os.path.isfile(git_dir):
        match = re.match(r"gitdir:\s*(.+)", read_text(git_dir) or "")
        if match:
            git_dir = os.path.normpath(os.path.join(root, match.group(1).strip()))
    remote = None
    config = read_text(os.path.join(git_dir, "config")) or ""
    section = None
    for line in config.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line
        elif section and section.startswith("[remote") and line.startswith("url"):
            remote = redact_text(line.split("=", 1)[1].strip())
            if '"origin"' in section:
                break
    cloned_at = last = None
    how = "folder date"
    log = read_text(os.path.join(git_dir, "logs", "HEAD"), limit=4 << 20)
    if log:
        lines = [l for l in log.splitlines() if l.strip()]
        stamp = re.compile(r"> (\d+) [+-]\d{4}\t(.*)")
        first = stamp.search(lines[0]) if lines else None
        final = stamp.search(lines[-1]) if lines else None
        if first:
            cloned_at = float(first.group(1))
            how = "first git log entry" + (" (clone)" if first.group(2).startswith("clone") else "")
        if final:
            last = float(final.group(1))
    if cloned_at is None:
        cloned_at = mtime(os.path.join(git_dir, "description")) or mtime(git_dir)
    fetch = mtime(os.path.join(git_dir, "FETCH_HEAD"))
    if fetch and (last is None or fetch > last):
        last = fetch
    return GitInfo(root=root, remote=remote, cloned_at=cloned_at, last_activity=last, how=how)


GO_MODINFO = re.compile(rb"path\t([^\n]+)\nmod\t([^\t\n]+)\t([^\t\n]*)")


def go_module(path: str) -> Optional[Tuple[str, str]]:
    try:
        if os.path.getsize(path) > 400 << 20:
            return None
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    if b"\xff Go buildinf:" not in data:
        return None
    match = GO_MODINFO.search(data)
    if not match:
        return ("", "")
    return match.group(2).decode("utf-8", "replace"), match.group(3).decode("utf-8", "replace")


VERSIONISH = re.compile(r"^v?\d+(\.\d+)+([-+._][0-9A-Za-z.]+)?$")
GENERIC_DIRS = {"bin", "sbin", "versions", "version", "current", "latest", "stable", "libexec", "lib", "app", "dist", "build",
                "release", "releases", "target", "out", "usr", "local", "share", "opt", ".local"}


def program_name(path: str) -> Tuple[str, Optional[str]]:
    """Name a loose binary; `~/.local/share/claude/versions/2.1.3` is claude 2.1.3, not "2.1.3"."""
    parts = [p for p in path.split("/") if p]
    version = None
    while parts and (VERSIONISH.match(parts[-1]) or parts[-1] in GENERIC_DIRS):
        if VERSIONISH.match(parts[-1]) and not version:
            version = parts[-1]
        parts.pop()
    if not parts or parts[-1] == os.path.basename(Paths.home):
        return os.path.basename(path), None
    return parts[-1], version if parts[-1] != os.path.basename(path) else None


def landed_at(path: Optional[str]) -> Optional[float]:
    """When a file arrived here: ctime survives archives that preserve (or zero) the original mtime."""
    try:
        st = os.stat(path) if path else None
    except OSError:
        return None
    if not st:
        return None
    # ctime records when the file was written here; archives preserve (or zero) the original mtime.
    for value in (st.st_ctime, st.st_mtime):
        if value > 315532800:  # ignore pre-1980 placeholder dates
            return value
    return None


class ContainerNames:
    """Names, images and compose projects for running containers, when docker/podman can be asked."""

    def __init__(self) -> None:
        self.loaded = False
        self.info: Dict[str, Dict[str, str]] = {}

    def get(self, cid: str) -> Optional[Dict[str, str]]:
        if not self.loaded:
            self.loaded = True
            fmt = '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.CreatedAt}}'
            for engine in ("docker", "podman"):
                if not shutil.which(engine):
                    continue
                for line in run([engine, "ps", "--no-trunc", "--format", fmt], timeout=10).splitlines():
                    fields = line.split("\t")
                    if len(fields) >= 6:
                        self.info[fields[0][:12]] = {"engine": engine, "name": fields[1], "image": fields[2],
                                                     "project": fields[3], "service": fields[4], "created": fields[5]}
        return self.info.get(cid[:12])


class Classifier:
    def __init__(self, owners: PackageOwners, homes: List[str]) -> None:
        self.owners = owners
        self.python = PythonIndex()
        self.homes = homes
        self.cargo: Dict[str, Dict[str, Tuple[str, str, str]]] = {}
        self.containers = ContainerNames()

    @property
    def user_sites(self) -> List[str]:
        return [s for h in self.homes for s in glob.glob(os.path.join(glob.escape(h), ".local/lib/python*/site-packages"))]

    # -- sandboxed / packaged formats identified by cgroup -------------------
    def from_cgroup(self, proc: Proc) -> Optional[Provenance]:
        cg = proc.cgroup
        match = re.search(r"(?:docker-|docker/|libpod-|libpod-conmon-|cri-containerd-|crio-)([0-9a-f]{12,64})", cg)
        if match or "/kubepods" in cg:
            cid = match.group(1)[:12] if match else "kubernetes"
            engine = "podman" if "libpod" in cg else "docker"
            info = self.containers.get(cid) if match else None
            if info:
                created = None
                try:
                    created = dt.datetime.strptime(info["created"][:19], "%Y-%m-%d %H:%M:%S").timestamp()
                except ValueError:
                    pass
                engine, name = info["engine"], info["name"]
                notes = [f"image `{info['image']}`", f"container id {cid}"]
                if info["project"]:
                    project, service = info["project"], info["service"]
                    notes.append(f"compose project `{project}`, service `{service}`")
                    stop = f"`{engine} compose -p {project} stop {service}` (killing its process makes Docker restart it)"
                    keep = (f"remove `restart:` from service `{service}` in the `{project}` compose file, "
                            f"or `{engine} update --restart=no {name}`")
                    remove = f"`{engine} compose -p {project} down` removes the whole `{project}` project"
                else:
                    stop = f"`{engine} stop {name}` (killing its process makes Docker restart it)"
                    keep = f"`{engine} update --restart=no {name}`"
                    remove = f"`{engine} rm -f {name}`"
                return Provenance(kind="container", name=name, location=cid, installed_at=created,
                                  date_note="container created" if created else "", remove_hint=remove, notes=notes,
                                  stop_hint=stop, disable_hint=keep)
            return Provenance(
                kind="container", name=f"{engine} container {cid} ({proc.comm})", location=cid,
                remove_hint=f"`{engine} ps` to identify it, then `{engine} stop {cid}`; remove its restart policy or compose service so it stays off",
                notes=[f"main process `{proc.comm}`; add yourself to the {engine} group (or run with sudo) to see container names"],
            )
        match = re.search(r"/lxc\.payload\.([^/]+)(/.*)?", cg)
        if match:
            raw = match.group(1)
            project, _, name = raw.rpartition("_") if "_" in raw else ("", "", raw)
            inner = (match.group(2) or "").rstrip("/").split("/")[-1]
            cli = "incus" if shutil.which("incus") else "lxc"
            flag = f" --project {project}" if project and project != "default" else ""
            notes = [f"inside the container it runs `{inner}`"] if inner else []
            if project:
                notes.append(f"{cli} project `{project}`")
            return Provenance(kind="container", name=f"{name} (LXC)", location=f"lxc:{raw}", notes=notes,
                              stop_hint=f"`{cli} stop {name}{flag}`",
                              disable_hint=f"`{cli} config set {name}{flag} boot.autostart=false`",
                              remove_hint=f"`{cli} delete {name}{flag}` (deletes the container and its data)")
        flatpak = proc.flatpak_id
        if not flatpak:
            match = re.search(r"app-flatpak-(.+?)-[0-9a-zA-Z]+\.scope", cg)
            if match:
                flatpak = unescape_unit(match.group(1))
        if flatpak:
            return self.flatpak(flatpak)
        match = re.search(r"/snap\.([a-z0-9-]+)\.", cg)
        if match:
            return self.snap(match.group(1))
        return None

    def flatpak(self, app_id: str) -> Provenance:
        where, date = None, None
        user_roots = [os.path.join(h, ".local/share/flatpak/app") for h in self.homes]
        for scope, base in (("user", user_roots), ("system", ["/var/lib/flatpak/app"])):
            for root in base:
                candidate = os.path.join(root, app_id)
                if os.path.isdir(candidate):
                    where, date = scope, mtime(os.path.join(candidate, "current"), follow=False) or mtime(candidate)
                    break
            if where:
                break
        return Provenance(
            kind="flatpak", name=app_id, location=app_id, installed_at=date,
            date_note="last install or update" if date else "",
            remove_hint=f"`flatpak uninstall {'--user ' if where == 'user' else ''}{app_id}`",
            notes=[f"{where} installation"] if where else [],
        )

    def snap(self, name: str) -> Provenance:
        current = realpath(f"/snap/{name}/current")
        rev = os.path.basename(current)
        date = mtime(f"/var/lib/snapd/snaps/{name}_{rev}.snap")
        return Provenance(
            kind="snap", name=name, version=f"rev {rev}" if rev.isdigit() else None, location=name,
            installed_at=date, date_note="current revision downloaded" if date else "",
            remove_hint=f"`sudo snap remove {name}`",
        )

    # -- path based -----------------------------------------------------------
    def classify(self, proc: Proc, target: Target) -> Provenance:
        prov = self.from_cgroup(proc)
        if prov:
            return prov
        if proc.exe and "/.mount_" in proc.exe:
            image = proc.appimage
            name = os.path.basename(image) if image else proc.exe.split("/.mount_")[1].split("/")[0]
            return Provenance(
                kind="appimage", name=re.sub(r"(?i)\.appimage$", "", name), location=image or name,
                installed_at=mtime(image), date_note="file date" if image else "",
                remove_hint=f"delete `{Paths.show(image)}` (and its autostart entry, if any)" if image else "delete the .AppImage file",
            )
        path = target.path
        if target.project:
            if "/node_modules/" in target.project:
                # e.g. an npm -g package serving from its own dist/ folder: same program as the package.
                node = self.node(target.project.rstrip("/") + "/")
                if node:
                    return node
            return self.project(target.project, target.runner, proc)
        if target.module and target.family == "python":
            # `python -m pkg` is identified by the package, not by the interpreter binary.
            python = self.python_program(target)
            if python:
                return python
        if not path:
            return Provenance(kind="unknown", name=proc.comm, notes=["no permission to read this process; run with sudo to identify system processes"])
        if path.startswith("/snap/"):
            return self.snap(path.split("/")[2])
        if path.startswith(("/app/", "/var/lib/flatpak/")) or "/.local/share/flatpak/" in path:
            match = re.search(r"/flatpak/app/([^/]+)/", path)
            if match:
                return self.flatpak(match.group(1))
        match = re.match(r"/nix/store/[a-z0-9]{32}-([^/]+)", path)
        if match:
            return Provenance(kind="nix", name=match.group(1), location=match.group(0),
                              remove_hint="remove it from your nix profile or configuration (`nix profile list`)")
        match = re.search(r"^(.*/Cellar)/([^/]+)/([^/]+)/", path)
        if match:
            return self.homebrew(match.group(1), match.group(2), match.group(3))
        if "/node_modules/" in path:
            node = self.node(path)
            if node:
                return node
        if "/.rustup/toolchains/" in path:
            toolchain = path.split("/.rustup/toolchains/")[1].split("/")[0]
            return Provenance(kind="rustup", name=os.path.basename(path), version=toolchain,
                              location=path, remove_hint=f"`rustup toolchain uninstall {toolchain}`")
        if "/.cargo/bin/" in path:
            return self.cargo_bin(path)
        if re.search(r"/go/bin/[^/]+$", path) or (os.environ.get("GOBIN") and path.startswith(os.environ["GOBIN"] + "/")):
            info = go_module(path)
            if info is not None:
                return Provenance(
                    kind="go", name=os.path.basename(path), version=info[1] or None, source=info[0] or None,
                    location=path, installed_at=mtime(path), date_note="file date", remove_hint=f"`rm {Paths.show(path)}`",
                )
        if is_system_path(path):
            pkg = self.owners.owner(path)
            if pkg:
                asked = self.owners.requested_at(pkg)
                manual = self.owners.is_manual(pkg)
                came = self.owners.came_with_note(pkg)
                return Provenance(
                    kind="system-package", name=pkg, location=pkg, installed_at=asked or self.owners.installed_at(pkg),
                    date_note="you installed it" if asked and manual else ("apt history" if asked else "install or last upgrade"),
                    manual=manual, notes=[came] if came else [],
                    remove_hint=f"`{self.owners.front} {pkg}`" if self.owners.front else None,
                )
        python = self.python_program(target)
        if python:
            return python
        git = git_info(path, self.homes)
        if git:
            return self.from_git(git, path)
        if path.startswith("/usr/local/"):
            name, version = program_name(path)
            return Provenance(kind="manual-local", name=name, version=version, location=path, installed_at=landed_at(path),
                              date_note="file date", remove_hint=f"not owned by any package; delete `{path}` if unused",
                              notes=["copied there by an install script or `make install`, not the package manager"])
        if path.startswith("/opt/"):
            top = "/".join(path.split("/")[:3])
            installed, current = landed_at(top), landed_at(path)
            notes = []
            if installed and current and current - installed > 2 * 86400:
                notes.append(f"the version running now dates from {fmt_date(current)} (updated in place)")
            return Provenance(kind="manual-opt", name=os.path.basename(top), location=top, installed_at=installed or current,
                              date_note="folder date", remove_hint=f"not owned by any package; it lives in `{top}`", notes=notes)
        if any(path.startswith(h + "/") for h in self.homes):
            name, version = program_name(path)
            return Provenance(kind="manual", name=name, version=version, location=path, installed_at=landed_at(path),
                              date_note="file date", remove_hint=f"delete `{Paths.show(path)}` if you don't need it")
        if is_system_path(path):
            return Provenance(kind="unknown", name=os.path.basename(path), location=path, installed_at=mtime(path),
                              date_note="file date", notes=["system file that no package claims"])
        return Provenance(kind="unknown", name=os.path.basename(path), location=path)

    def project(self, folder: str, runner: Optional[str], proc: Proc) -> Provenance:
        notes = []
        if runner:
            notes.append(f"launched through `{runner}`")
        script = env_value(proc.pid, "npm_lifecycle_script")
        if script:
            notes.append(f"runs `{redact_text(script[:120])}`")
        git = git_info(folder, self.homes)
        if git:
            prov = self.from_git(git, folder)
            prov.notes[:0] = notes
            return prov
        name = os.path.basename(folder)
        try:
            manifest = json.loads(read_text(os.path.join(folder, "package.json")) or "{}")
        except ValueError:
            manifest = {}
        if isinstance(manifest, dict) and manifest.get("name") and (re.fullmatch(r"[0-9a-f]{20,}", name) or not name):
            name = str(manifest["name"])
        return Provenance(kind="project", name=name, version=manifest.get("version") if isinstance(manifest, dict) else None,
                          location=folder, installed_at=landed_at(folder), date_note="folder date", notes=notes,
                          remove_hint=f"project folder `{Paths.show(folder)}`; remove whatever starts it, then the folder if unused")

    def homebrew(self, cellar: str, pkg: str, version: str) -> Provenance:
        prov = Provenance(kind="homebrew", name=pkg, version=version, location=f"{cellar}/{pkg}",
                          remove_hint=f"`brew uninstall {pkg}`")
        try:
            receipt = json.loads(read_text(os.path.join(cellar, pkg, version, "INSTALL_RECEIPT.json")) or "{}")
        except ValueError:
            receipt = {}
        if receipt.get("time"):
            prov.installed_at, prov.date_note = float(receipt["time"]), "Homebrew install receipt"
        else:
            prov.installed_at, prov.date_note = mtime(os.path.join(cellar, pkg, version)), "folder date"
        if receipt.get("installed_on_request") is False:
            prov.notes.append("pulled in as a dependency of another brew formula")
        return prov

    def node(self, path: str) -> Optional[Provenance]:
        prefix, rest = path.split("/node_modules/", 1)
        segments = rest.split("/")
        package = "/".join(segments[:2]) if segments[0].startswith("@") else segments[0]
        if package in (".bin", ".pnpm", ".store"):
            return None
        package_dir = f"{prefix}/node_modules/{package}"
        try:
            manifest = json.loads(read_text(os.path.join(package_dir, "package.json")) or "{}")
        except ValueError:
            manifest = {}
        name, version = manifest.get("name") or package, manifest.get("version")
        date = mtime(package_dir)
        repo = manifest.get("repository")
        source = redact_text(repo.get("url") if isinstance(repo, dict) else repo) if repo else None
        def make(kind: str, hint: str, notes: Optional[List[str]] = None) -> Provenance:
            return Provenance(kind=kind, name=name, version=version, installed_at=date, date_note="folder date",
                              source=source, location=package_dir, remove_hint=hint, notes=notes or [])
        if "/_npx/" in prefix or "/dlx/" in prefix or "/.cache/" in prefix:
            return make("npx-cache", "it runs from a download cache (npx / pnpm dlx); stop whatever keeps launching it")
        match = re.search(r"/\.nvm/versions/node/(v[^/]+)/lib$", prefix)
        if match:
            return make("npm-global", f"`nvm use {match.group(1)} && npm uninstall -g {name}`", [f"installed under nvm node {match.group(1)}"])
        if "/.volta/" in prefix:
            return make("volta", f"`volta uninstall {name}`")
        if "/pnpm/global/" in prefix or "/.pnpm-global/" in prefix:
            return make("pnpm-global", f"`pnpm remove -g {name}`")
        if "/.bun/install/global" in prefix:
            return make("bun-global", f"`bun remove -g {name}`")
        if "/yarn/global" in prefix or "/.yarn/global" in prefix:
            return make("yarn-global", f"`yarn global remove {name}`")
        # A global npm prefix looks like <prefix>/lib/node_modules with commands linked from <prefix>/bin.
        if prefix.endswith("/lib") and (prefix in ("/usr/lib", "/usr/local/lib") or os.path.isdir(os.path.join(os.path.dirname(prefix), "bin"))):
            if is_system_path(path) and self.owners.owner(path):
                return None  # the distro packaged this module
            return make("npm-global", f"`{'sudo ' if prefix.startswith('/usr') else ''}npm uninstall -g {name}`")
        # A dependency inside some project's node_modules: identify the project instead.
        git = git_info(prefix, self.homes)
        if git:
            prov = self.from_git(git, path)
            prov.notes.append(f"running its dependency `{name}`")
            return prov
        return Provenance(kind="node-project", name=os.path.basename(prefix), location=prefix, installed_at=mtime(prefix),
                          date_note="folder date", remove_hint=f"node project in `{Paths.show(prefix)}`",
                          notes=[f"running its dependency `{name}`"])

    def cargo_bin(self, path: str) -> Provenance:
        cargo_home = path[: path.index("/.cargo/") + len("/.cargo")]
        if cargo_home not in self.cargo:
            mapping: Dict[str, Tuple[str, str, str]] = {}
            try:
                installs = json.loads(read_text(os.path.join(cargo_home, ".crates2.json")) or "{}").get("installs", {})
            except ValueError:
                installs = {}
            for key, value in installs.items():
                match = re.match(r"(\S+) (\S+) \((.+)\)", key)
                if match:
                    for binary in value.get("bins", []):
                        mapping[binary] = (match.group(1), match.group(2), match.group(3))
            self.cargo[cargo_home] = mapping
        binary = os.path.basename(path)
        info = self.cargo[cargo_home].get(binary)
        if info:
            crate, version, source = info
            source = source.split("+", 1)[-1] if "crates.io" not in source else "crates.io"
            return Provenance(kind="cargo", name=crate, version=version, source=redact_text(source), location=path,
                              installed_at=mtime(path), date_note="file date", remove_hint=f"`cargo uninstall {crate}`")
        return Provenance(kind="rustup", name=binary, location=path, installed_at=mtime(path), date_note="file date",
                          notes=["rustup proxy or a binary copied into ~/.cargo/bin"])

    def python_program(self, target: Target) -> Optional[Provenance]:
        if target.family != "python" and not (target.path and ("/site-packages/" in target.path or "/dist-packages/" in target.path)):
            if not target.path or os.path.basename(os.path.dirname(target.path)) != "bin":
                return None
        dist = self.python.lookup(target.path, target.module, [target.invoked, target.interpreter], self.user_sites)
        if dist:
            return self.from_dist(dist, target)
        venv = find_upwards(target.path, "pyvenv.cfg") or find_upwards(target.invoked, "pyvenv.cfg")
        if venv and target.family == "python":
            git = git_info(os.path.dirname(venv), self.homes)
            if git and target.path and target.path.startswith(git.root + "/"):
                return None  # the project's own script; the git clone is the better answer
            return Provenance(kind="venv", name=target.module or os.path.basename(target.path or venv), location=venv,
                              installed_at=mtime(os.path.join(venv, "pyvenv.cfg")), date_note="virtualenv created",
                              remove_hint=f"lives in the virtualenv `{Paths.show(venv)}`")
        return None

    def from_dist(self, dist: PyDist, target: Target) -> Provenance:
        root = env_root_for_site(dist.site)
        notes: List[str] = []
        if dist.installer and dist.installer not in ("pip", "uv"):
            notes.append(f"installed by {dist.installer}")
        if "/pipx/venvs/" in root:
            kind, hint = "pipx", f"`pipx uninstall {os.path.basename(root)}`"
        elif "/uv/tools/" in root:
            kind, hint = "uv-tool", f"`uv tool uninstall {os.path.basename(root)}`"
        elif os.path.isdir(os.path.join(root, "conda-meta")):
            kind, hint = "conda", f"`conda remove -p {Paths.show(root)} {dist.name}`"
        elif os.path.exists(os.path.join(root, "pyvenv.cfg")):
            kind, hint = "venv", f"inside the virtualenv `{Paths.show(root)}`; `{Paths.show(root)}/bin/pip uninstall {dist.name}` or delete the venv"
            git = git_info(os.path.dirname(root), self.homes)
            if git:
                notes.append(f"virtualenv belongs to the git clone `{Paths.show(git.root)}`" + (f" ({git.remote})" if git.remote else ""))
        elif root.endswith("/.local"):
            kind, hint = "pip-user", f"`python3 -m pip uninstall {dist.name}`"
        elif root in ("/usr", "/usr/local"):
            kind, hint = "pip-system", f"`sudo python3 -m pip uninstall {dist.name}`"
        else:
            kind, hint = "pip", f"`{Paths.show(root)}/bin/python -m pip uninstall {dist.name}`"
        source = dist.source_url
        if dist.editable_dir:
            notes.append(f"editable install pointing at `{Paths.show(dist.editable_dir)}`")
            git = git_info(dist.editable_dir, self.homes)
            if git and git.remote:
                source = git.remote
        if target.module and target.module.split(".")[0] != dist.name.replace("-", "_").lower():
            notes.append(f"run as `python -m {target.module}`")
        return Provenance(kind=kind, name=dist.name, version=dist.version, installed_at=dist.installed_at,
                          date_note="package install record", source=source, location=root,
                          remove_hint=hint, notes=notes)

    def from_git(self, git: GitInfo, path: str) -> Provenance:
        notes = []
        if git.last_activity:
            notes.append(f"last git activity {fmt_date(git.last_activity)}")
        try:
            children = [os.path.join(git.root, c) for c in os.listdir(git.root)]
        except OSError:
            children = []
        if any(os.path.exists(os.path.join(c, "pyvenv.cfg")) for c in children):
            notes.append("has its own python virtualenv")
        if os.path.isdir(os.path.join(git.root, "node_modules")):
            notes.append("has its own node_modules")
        return Provenance(kind="git-clone", name=os.path.basename(git.root), installed_at=git.cloned_at, date_note=git.how,
                          source=git.remote, location=git.root, notes=notes,
                          remove_hint=f"delete the folder `{Paths.show(git.root)}` (after removing whatever starts it)")


# ---------------------------------------------------------------------------
# What started each process
# ---------------------------------------------------------------------------

TERMINALS = {
    "konsole", "yakuake", "kitty", "alacritty", "wezterm-gui", "wezterm", "foot", "gnome-terminal-", "gnome-terminal-server",
    "xterm", "urxvt", "terminator", "tilix", "xfce4-terminal", "ghostty", "kgx", "ptyxis-agent", "qterminal", "lxterminal",
    "sakura", "st", "tabby", "warp", "cool-retro-term", "terminology", "rio", "contour",
}
MULTIPLEXERS = {"tmux", "tmux: server", "screen", "SCREEN", "zellij", "byobu"}
IDES = {"code", "codium", "cursor", "windsurf", "zed", "kate", "idea", "pycharm", "webstorm", "clion", "goland", "rustrover", "nvim", "vim", "emacs", "java"}
ROOT_PARENTS = {"systemd", "init", "kdeinit5", "kdeinit6", "plasmashell", "ksmserver", "startplasma-wayland", "startplasma-x11",
                "plasma_session", "kwin_wayland", "kwin_wayland_wrapper", "sddm-helper", "(sd-pam)"}


@dataclass
class Launch:
    kind: str                  # stable code, see describe()
    detail: str                # human readable
    unit: Optional[str] = None
    scope: Optional[str] = None  # "user" | "system"
    desktop_name: Optional[str] = None
    parent_chain: List[str] = field(default_factory=list)
    leaf: str = ""


def parse_cgroup_launch(cg: str) -> Launch:
    segments = [s for s in cg.split("/") if s]
    last = segments[-1] if segments else ""
    if "/user@" in cg or cg.startswith("/user.slice/user-") and "user@" in cg:
        if last.startswith("app-") and last.endswith("@autostart.service"):
            name = unescape_unit(last[4: -len("@autostart.service")])
            return Launch("autostart", f"autostart entry `{name}`", unit=last, scope="user", desktop_name=name)
        if last.startswith("app-") and last.endswith(".scope"):
            if last.startswith("app-flatpak-"):
                return Launch("app-launched", "started by you (flatpak app)", unit=last, scope="user")
            name = unescape_unit(re.sub(r"-[0-9a-zA-Z]+\.scope$", "", last[4:]))
            name = re.sub(r"^(gnome|kde|cosmic)-", "", name)
            return Launch("app-launched", f"started from `{name}`", unit=last, scope="user", desktop_name=name)
        if last.startswith("app-") and last.endswith(".service"):
            # Apps launched as transient services (KDE_APPLICATIONS_AS_SERVICE and similar).
            name = unescape_unit(re.sub(r"(@[^.]*)?\.service$", "", last[4:]))
            return Launch("app-launched", f"started from `{name}`", unit=last, scope="user", desktop_name=name)
        if last.startswith("dbus-") and last.endswith(".service"):
            name = unescape_unit(re.sub(r"^dbus-:[0-9.]+-|@[^.]*\.service$|\.service$", "", last))
            return Launch("on-demand", f"started on demand over D-Bus (`{name}`)", unit=last, scope="user", desktop_name=name)
        if last.endswith((".service", ".socket", ".timer")):
            if "session.slice" in segments:
                return Launch("session", f"part of the desktop session (`{last}`)", unit=last, scope="user")
            if "background.slice" in segments:
                return Launch("user-service", f"background user service `{last}`", unit=last, scope="user")
            return Launch("user-service", f"systemd user service `{last}`", unit=last, scope="user")
        if last == "init.scope":
            return Launch("session", "your systemd user manager", scope="user")
        if last.startswith("run-") and last.endswith(".scope"):
            return Launch("transient", "started with `systemd-run`", unit=last, scope="user")
        if last.startswith("tmux-spawn-") or last.startswith("tmux"):
            return Launch("terminal", "running inside tmux", unit=last, scope="user")
        match = re.match(r"(vte|ptyxis|gnome-terminal|kgx|wezterm|kitty)-spawn-", last)
        if match:
            return Launch("terminal", f"started from a terminal ({match.group(1)})", unit=last, scope="user")
        if last.endswith(".scope"):
            return Launch("app-launched", f"user session scope `{unescape_unit(last)}`", unit=last, scope="user")
    if re.match(r"/user\.slice/user-\d+\.slice/session-[^/]+\.scope", cg):
        return Launch("login-session", "started directly by your login session")
    if cg.startswith("/system.slice/"):
        # Template units live in their own slice: /system.slice/system-cups.slice/cups.service
        unit = next((seg for seg in reversed(segments) if seg.endswith((".service", ".scope", ".socket"))),
                    segments[1] if len(segments) > 1 else last)
        if unit in ("cron.service", "cronie.service", "crond.service", "fcron.service"):
            return Launch("cron", "a cron job", unit=unit, scope="system")
        if unit.startswith(("docker-", "libpod-")):
            return Launch("container", "a container", unit=unit, scope="system")
        return Launch("system-service", f"system service `{unit}`", unit=unit, scope="system")
    if cg == "/init.scope":
        return Launch("init", "the init system")
    if cg.startswith("/lxc.payload.") or "/lxc.payload." in cg:
        return Launch("container", "an LXC/Incus container", unit=segments[0] if segments else None, scope="system")
    if cg.startswith("/machine.slice/"):
        return Launch("container", "a container or VM", unit=last, scope="system")
    if cg and cg != "/":
        return Launch("unknown", f"unrecognized cgroup `{cg}`")
    return Launch("unknown", "unknown (no systemd information)")


def describe_parents(proc: Proc, table: Dict[int, Proc]) -> List[str]:
    chain: List[str] = []
    seen = set()
    current = table.get(proc.ppid)
    while current and current.pid not in seen and len(chain) < 12:
        seen.add(current.pid)
        chain.append(current.comm)
        if current.pid == 1:
            break
        current = table.get(current.ppid)
    return chain


def refine_launch(launch: Launch, proc: Proc, table: Dict[int, Proc], group_of: Dict[int, str]) -> Launch:
    launch.parent_chain = describe_parents(proc, table)
    launch.leaf = proc.comm
    if launch.unit == "plasma-plasmashell.service" and proc.comm != "plasmashell":
        launch.kind, launch.detail = "widget", "run by Plasma (a panel widget or plasmoid)"
    if launch.kind == "cron" and proc.comm in ("cron", "crond", "cronie", "fcron"):
        launch.kind, launch.detail = "system-service", f"system service `{launch.unit}`"
    chain = launch.parent_chain
    term = next((c for c in chain if c in TERMINALS or c.startswith("gnome-terminal")), None)
    mux = next((c for c in chain if c in MULTIPLEXERS or c.startswith("tmux")), None)
    if "sshd" in chain or any(c.startswith("sshd") for c in chain):
        launch.kind, launch.detail = "ssh", "started from an ssh session"
    elif term and launch.kind in ("app-launched", "login-session", "unknown", "session"):
        via = f" inside {mux}" if mux else ""
        launch.kind, launch.detail = "terminal", f"started from a terminal ({term}{via})"
    elif mux and launch.kind in ("app-launched", "login-session", "unknown", "user-service"):
        launch.kind, launch.detail = "terminal", f"running inside {mux}"
    parent = table.get(proc.ppid)
    if parent and parent.comm not in ROOT_PARENTS and parent.comm not in SHELLS and parent.comm not in TERMINALS:
        mine, theirs = group_of.get(proc.pid), group_of.get(parent.pid)
        if theirs and mine != theirs and parent.comm not in MULTIPLEXERS:
            ide = parent.comm in IDES
            launch.detail += f"; spawned by `{parent.comm}`" + (" (editor/IDE)" if ide else "")
            if launch.kind in ("app-launched", "unknown", "login-session", "terminal"):
                launch.kind = "child"
    return launch


# ---------------------------------------------------------------------------
# What is safe to touch
# ---------------------------------------------------------------------------

CORE_NAMES = {
    "systemd", "dbus-daemon", "dbus-broker", "dbus-broker-launch", "kwin_wayland", "kwin_wayland_wrapper", "kwin_x11",
    "plasmashell", "ksmserver", "kded5", "kded6", "kglobalaccel5", "kglobalacceld", "Xwayland", "Xorg", "X", "sddm", "sddm-helper",
    "startplasma-wayland", "startplasma-x11", "plasma_session", "pipewire", "pipewire-pulse", "wireplumber", "pulseaudio",
    "polkit-kde-authentication-agent-1", "polkit-kde-auth", "polkitd", "kactivitymanagerd", "org_kde_powerdevil", "powerdevil",
    "kscreen_backend_launcher", "NetworkManager", "wpa_supplicant", "iwd", "udisksd", "upowerd", "accounts-daemon", "rtkit-daemon",
    "agetty", "login", "(sd-pam)", "kwalletd5", "kwalletd6", "ksecretd", "xdg-desktop-portal", "xdg-desktop-portal-kde",
    "xdg-desktop-portal-gtk", "xdg-document-portal", "xdg-permission-store", "gvfsd", "at-spi-bus-launcher", "at-spi2-registryd",
    "plasma-kwin_wayland", "kwin_wayland-wrapper", "bluetoothd", "chronyd", "avahi-daemon", "cupsd", "thermald", "irqbalance",
    "power-profiles-daemon", "tuned", "auditd", "firewalld", "ModemManager", "smartd", "colord", "geoclue", "switcheroo-control",
    "fprintd", "iio-sensor-proxy", "low-memory-monitor", "zram-generator", "systemd-oomd", "earlyoom", "lightdm", "gdm", "sshd",
}
CORE_PREFIXES = ("systemd-", "kworker", "xdg-", "at-spi", "gvfs", "ibus", "fcitx", "sddm", "dbus-")

OPTIONAL_TIPS = {
    "baloo_file": "KDE file-search indexer, often the biggest idle hog. Turn off in System Settings > Search > File Search, or `balooctl6 disable` (`balooctl` on Plasma 5).",
    "baloo_file_extractor": "Part of the KDE file indexer (see baloo_file).",
    "baloorunner": "Part of the KDE file indexer (see baloo_file).",
    "akonadiserver": "KDE PIM backend (KMail, Kontact, calendar sync). If you don't use those apps: `akonadictl stop`; uninstalling the kdepim apps keeps it from coming back.",
    "akonadi_control": "KDE PIM backend (see akonadiserver).",
    "kdeconnectd": "KDE Connect (phone integration). Turn off its autostart if you don't use it.",
    "DiscoverNotifier": "Discover's update checker. Turn off in System Settings > Autostart if you update another way.",
    "plasma-discover": "The Discover app store.",
    "xembedsniproxy": "Shows tray icons for old X11 apps. Small; safe to leave.",
    "kaccess": "Accessibility helper. Tiny.",
    "plasma-browser-integration-host": "Plasma browser integration; safe to remove the browser extension if unused.",
    "tracker-miner-fs-3": "GNOME file indexer pulled in by GNOME apps. `systemctl --user mask tracker-miner-fs-3.service` to stop it.",
    "localsearch-3": "GNOME's file indexer (formerly Tracker), pulled in by GNOME apps; KDE doesn't need it. Stop it for good with `systemctl --user mask --now localsearch-3.service localsearch-control-3.service`.",
    "localsearch": "GNOME's file indexer (formerly Tracker); see localsearch-3.",
    "evolution-data-server": "GNOME calendar/contacts backend pulled in by GNOME apps.",
    "evolution-source-registry": "GNOME calendar/contacts backend pulled in by GNOME apps.",
    "evolution-addressbook-factory": "GNOME contacts backend pulled in by GNOME apps.",
    "evolution-calendar-factory": "GNOME calendar backend pulled in by GNOME apps.",
    "goa-daemon": "GNOME online accounts, pulled in by GNOME apps.",
    "packagekitd": "Package-management daemon used by Discover; exits on its own when idle.",
    "fwupd": "Firmware update daemon; runs on demand.",
    "kded6": "KDE background-module host. Individual modules can be switched off in System Settings > Background Services.",
    "ksystemstats": "Feeds System Monitor and Plasma resource widgets.",
    "kalendarac": "KDE calendar reminders (Kalendar/Merkuro).",
    "merkuro-calendar": "KDE calendar reminders.",
    "org.kde.merkuro.contact": "KDE contacts.",
    "kmail": "KMail.",
    "snapd": "Snap daemon. Only needed if you use snaps.",
    "drkonqi-coredump-launcher": "KDE's crash reporter, handling a crash that just happened. It exits on its own.",
    "drkonqi-coredump-processor": "KDE's crash reporter, handling a crash that just happened. It exits on its own.",
    "drkonqi": "KDE's crash reporter. It exits on its own.",
    "intel_gpu_top": "Intel GPU monitor. Something (a Plasma system-monitor widget, Netdata's GPU collector) runs it over and over; each run costs CPU.",
    "mount.ntfs-3g": "FUSE driver serving an NTFS drive you mounted. It stays until you unmount it (`umount <mount point>`).",
    "mount.ntfs": "FUSE driver serving an NTFS drive you mounted. It stays until you unmount it (`umount <mount point>`).",
    "dockerd": "Docker engine. Disable with `sudo systemctl disable --now docker.service docker.socket` if you only use it occasionally.",
    "containerd": "Container runtime used by Docker.",
    "ollama": "Ollama local-model server; holds models in RAM while loaded.",
    "cupsd": "Printing. Safe to disable if you never print: `sudo systemctl disable --now cups.service cups.socket`.",
}

PACKAGE_TIPS = {
    "netdata": "Netdata monitoring agent: per-second metrics for the whole machine, a local dashboard at http://localhost:19999, and the history this report's 'over time' numbers come from. Its plugins are counted in this row.",
    "alloy": "Grafana Alloy telemetry collector: gathers metrics, logs and traces and ships them to a Grafana stack (Prometheus/Mimir, Loki, Grafana Cloud). Its config is in the path on its command line or in /etc/default/alloy.",
    "clamav-daemon": "ClamAV scanner daemon: keeps its whole signature database (about 1 GB) in memory, mostly swapped out when idle. Not needed for occasional `clamscan` runs: `sudo systemctl disable --now clamav-daemon.service clamav-daemon.socket`.",
    "clamav-freshclam": "ClamAV signature updater.",
    "krdp": "KDE's remote-desktop (RDP) server: lets other machines connect to this desktop. Turn it off in System Settings > Remote Desktop if you don't use it.",
    "geoclue-2.0": "The Geoclue *demo* agent: a sample program, not something the desktop needs. Safe to switch off in System Settings > Autostart.",
    "postfix": "Postfix mail server. Postfix, Dovecot, OpenDKIM, greylisting and saslauthd together are a mail-hosting stack, often installed by a hosting control panel such as Virtualmin. Not needed on a desktop that doesn't receive mail.",
    "dovecot-core": "Dovecot IMAP/POP3 mail server (part of a mail-hosting stack; see postfix).",
    "opendkim": "Mail signing for a mail server (part of a mail-hosting stack; see postfix).",
    "milter-greylist": "Spam greylisting for a mail server (part of a mail-hosting stack; see postfix).",
    "postgrey": "Spam greylisting for a mail server (part of a mail-hosting stack; see postfix).",
    "sasl2-bin": "Login checks for a mail server (part of a mail-hosting stack; see postfix).",
    "proftpd-core": "ProFTPD FTP server.",
    "minidlna": "MiniDLNA media server: shares media to TVs and players on your network.",
    "snmpd": "SNMP agent: lets network monitoring tools poll this machine.",
    "apache2-bin": "Apache web server.",
    "nginx": "nginx web server / reverse proxy.",
    "samba": "Samba Windows file sharing (smbd/nmbd).",
    "modemmanager": "Manages mobile-broadband modems. Safe to disable if this machine has none.",
    "cups-browsed": "Finds network printers automatically. Safe to disable if you add printers by hand.",
    "spice-vdagent": "Only useful inside a virtual machine.",
    "tailscale": "Tailscale VPN.",
    "netbird": "NetBird VPN client.",
    "lemonade-server": "Lemonade local-LLM server.",
}

UNIT_NOTES = {
    "cloud-": "cloud-init configures cloud VMs at boot; a desktop doesn't need it (`sudo touch /etc/cloud/cloud-init.disabled` turns it all off)",
    "spice-vdagent": "only useful inside a virtual machine",
    "whoopsie": "sends crash reports to Ubuntu",
    "apport": "crash reporting",
    "motd-news": "fetches news for the terminal login message",
    "ua-timer": "Ubuntu Pro status checks",
    "ubuntu-advantage": "Ubuntu Pro",
    "nvmf-": "NVMe over network fabrics: server storage, not needed on a desktop",
    "nvmefc-": "NVMe over network fabrics: server storage, not needed on a desktop",
    "quota": "disk quotas, used by hosting setups",
    "rpcbind": "needed only for NFS file sharing",
    "konqy_preload": "keeps Konqueror preloaded",
    "certbot": "renews TLS certificates for a web server",
    "phpsessionclean": "cleans PHP sessions for a web server",
    "fcgiwrap": "CGI for a web server",
    "openvpn": "OpenVPN connections configured in /etc/openvpn",
    "qemu-kvm": "KVM virtual machines",
    "sysstat": "collects performance history (sar)",
    "etckeeper": "keeps /etc under version control",
    "emby-server": "Emby media server",
}


def unit_note(name: str) -> str:
    return next((note for prefix, note in UNIT_NOTES.items() if name.startswith(prefix)), "")


IDLE_AVG_CPU = 0.2   # percent of one core since start
IDLE_MIN_UPTIME = 6 * 3600
HOG_KB = 150 * 1024


CORE_PACKAGES = {
    "plasma-workspace", "plasma-workspace-wayland", "plasma-desktop", "kwin-wayland", "kwin-x11", "kwin", "sddm", "pipewire",
    "pipewire-bin", "pipewire-pulse", "wireplumber", "systemd", "systemd-sysv", "dbus", "dbus-daemon", "dbus-broker",
    "dbus-user-session", "xwayland", "xserver-xorg-core", "kded", "kf6-kded", "kded6", "kglobalacceld", "powerdevil",
    "polkit-kde-agent-1", "xdg-desktop-portal", "xdg-desktop-portal-kde", "xdg-desktop-portal-gtk", "plasma-integration",
    "kscreen", "libkscreen-bin", "network-manager", "networkmanager", "policykit-1", "polkitd", "udisks2", "upower",
    "accountsservice", "rtkit", "bluez", "kactivitymanagerd", "plasma-activities", "kde-cli-tools", "at-spi2-core", "gvfs",
    "gvfs-daemons", "xdg-dbus-proxy", "kwallet6", "libkf6wallet-bin", "kwalletmanager", "kwallet", "plasma-nm", "plasma-pa",
    "kinit", "ibus", "fcitx5", "plasma5support", "libplasma", "kio", "kf6-kio", "libkf6kiocore6", "kio-extras", "ksystemstats",
}


def safety_class(name, comm, prov: Provenance, launch_kinds: Set[str]) -> str:
    """Return core | optional | system | yours. `comm` may be a single name or a set of process/binary names."""
    comms = set(comm) if isinstance(comm, (set, list, tuple)) else {comm}
    names = {name} | comms
    if names & CORE_NAMES or any(c.startswith(CORE_PREFIXES) for c in comms) or \
            (prov.kind == "system-package" and prov.name in CORE_PACKAGES):
        return "core"
    if prov.kind in SIDE_INSTALL_KINDS:
        return "yours"
    if names & set(OPTIONAL_TIPS):
        return "optional"
    if launch_kinds == {"session"} and prov.kind == "system-package" and not prov.manual:
        return "core"
    if names & SHELLS:
        return "system"
    if prov.kind == "system-package" and prov.manual and launch_kinds & {"autostart", "user-service", "app-launched", "terminal", "child", "on-demand"}:
        return "yours"
    return "system"


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------


@dataclass
class Group:
    key: str
    name: str
    prov: Provenance
    procs: List[Proc]
    launches: List[Launch]
    targets: List[Target]
    cls: str = "system"
    mem_kb: int = 0
    mem_is_pss: bool = True
    swap_kb: int = 0
    cpu_now: float = 0.0
    cpu_avg: float = 0.0
    cpu_seconds: float = 0.0
    oldest_start: float = NOW
    mentions: List[str] = field(default_factory=list)
    tip: Optional[str] = None
    verdict: str = ""
    seen: Optional[str] = None
    history: Dict[str, object] = field(default_factory=dict)
    stop_hint: Optional[str] = None
    disable_hint: Optional[str] = None
    unit_files: Dict[str, Dict[str, str]] = field(default_factory=dict)

    @property
    def idle(self) -> bool:
        return NOW - self.oldest_start > IDLE_MIN_UPTIME and self.cpu_avg < IDLE_AVG_CPU and self.cpu_now < 0.5


HELPER_PREFIXES = ("/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/lib/", "/lib64/")
CRON_UNITS = {"cron.service", "cronie.service", "crond.service", "fcron.service", "atd.service"}


def _fold(proc: Proc, into: Provenance, provs: Dict[int, Provenance], folded: Set[int]) -> None:
    note = f"includes child process `{proc.comm}` ({provs[proc.pid].name})"
    if note not in into.notes and sum(n.startswith("includes child") for n in into.notes) < 8:
        into.notes.append(note)
    provs[proc.pid] = into
    folded.add(proc.pid)


def fold_by_cgroup(procs: List[Proc], provs: Dict[int, Provenance], targets: Dict[int, Target], folded: Set[int]) -> None:
    """Everything a systemd service runs belongs to that service's program (netdata and its
    plugins, postfix and its workers); app scopes keep only their library helper processes."""
    members: Dict[str, List[Proc]] = {}
    for proc in procs:
        if proc.cgroup:
            members.setdefault(proc.cgroup, []).append(proc)
    for cgroup, group in members.items():
        if len(group) < 2:
            continue
        last = cgroup.rstrip("/").split("/")[-1]
        service = last.endswith(".service") and not last.startswith("user@") and last not in CRON_UNITS
        app_scope = last.startswith("app-") and last.endswith(".scope")
        if not (service or app_scope) or last.startswith(("docker-", "libpod-")):
            continue
        anchor = min(group, key=lambda p: (p.start_epoch, p.pid))
        anchor_names = {anchor.comm, os.path.basename(anchor.exe or "")}
        if anchor_names & (TERMINALS | MULTIPLEXERS | IDES | SHELLS | ROOT_PARENTS):
            continue  # a terminal or editor service runs whatever you start inside it
        into = provs[anchor.pid]
        if into.kind == "container":
            continue
        for proc in group:
            if proc is anchor or provs[proc.pid].key == into.key:
                continue
            path = proc.exe or (targets[proc.pid].path or "")
            if service or path.startswith(HELPER_PREFIXES):
                _fold(proc, into, provs, folded)


def fold_children(procs: List[Proc], table: Dict[int, Proc], provs: Dict[int, Provenance],
                  targets: Optional[Dict[int, Target]] = None, folded: Optional[Set[int]] = None) -> None:
    """Count helper tools (sleep, curl, ffmpeg...) against the side-installed program that started them."""
    folded = folded if folded is not None else set()
    for proc in sorted(procs, key=lambda p: p.start_epoch):
        parent = table.get(proc.ppid)
        if not parent or provs[proc.pid].kind != "system-package" or proc.comm in SHELLS:
            continue
        parent_prov = provs.get(parent.pid)
        path = proc.exe or ((targets or {}).get(proc.pid).path if targets and targets.get(proc.pid) else "") or ""
        helper = path.startswith(HELPER_PREFIXES) or provs[proc.pid].name.startswith("lib")
        own_app = parent.comm not in ROOT_PARENTS and parent.comm not in SHELLS and parent.comm not in TERMINALS and parent.pid != 1
        if parent_prov and parent_prov.kind != "container" and (parent_prov.kind in SIDE_INSTALL_KINDS or (helper and own_app)):
            _fold(proc, parent_prov, provs, folded)


def name_service_rows(procs: List[Proc], provs: Dict[int, Provenance], launches: Dict[int, Launch], unit_info) -> None:
    """A distro program (ssh, cloudflared, python...) run by a service you added is that service:
    show it as its own row named after the unit instead of merging it with every other use of the binary."""
    renamed: Dict[str, Provenance] = {}
    for proc in procs:
        prov, launch = provs[proc.pid], launches[proc.pid]
        if prov.kind not in ("system-package", "unknown") or launch.kind not in ("user-service", "system-service") or not launch.unit:
            continue
        details = unit_info(launch.scope, launch.unit)
        origin = details.get("origin", "")
        if not origin or origin.startswith(("from package", "generated", "unknown", "created by snapd")):
            continue
        stem = re.sub(r"\.service$", "", launch.unit)
        if stem in (prov.name, proc.comm, os.path.basename(proc.exe or "")):
            continue
        if launch.unit not in renamed:
            program = "unknown program" if prov.kind == "unknown" else f"`{proc.comm}` from package `{prov.name}`"
            renamed[launch.unit] = Provenance(
                kind="service", name=stem, location=f"unit:{launch.scope}:{launch.unit}",
                installed_at=mtime(details.get("file")), date_note="unit file date",
                notes=[f"runs {program}", f"service file `{Paths.show(details.get('file'))}` ({origin})"],
                remove_hint=f"this is the service; the program itself comes from {prov.name if prov.kind != 'unknown' else 'elsewhere'}",
            )
        provs[proc.pid] = renamed[launch.unit]


def build_groups(procs: List[Proc], classifier: Classifier, unit_info=None) -> List[Group]:
    table = {p.pid: p for p in procs}
    targets = {p.pid: resolve_target(p) for p in procs}
    classifier.owners.lookup_many(
        path for t in targets.values() for path in (t.path, t.interpreter) if is_system_path(path)
    )
    provs = {p.pid: classifier.classify(p, targets[p.pid]) for p in procs}
    folded: Set[int] = set()
    fold_children(procs, table, provs, targets, folded)
    fold_by_cgroup(procs, provs, targets, folded)
    group_of = {pid: prov.key for pid, prov in provs.items()}
    launches = {p.pid: refine_launch(parse_cgroup_launch(p.cgroup), p, table, group_of) for p in procs}
    if unit_info:
        name_service_rows(procs, provs, launches, unit_info)
    groups: Dict[str, Group] = {}
    for proc in procs:
        prov = provs[proc.pid]
        launch = launches[proc.pid]
        group = groups.get(prov.key)
        if not group:
            group = groups[prov.key] = Group(key=prov.key, name=prov.name, prov=prov, procs=[], launches=[], targets=[])
        group.procs.append(proc)
        group.targets.append(targets[proc.pid])
        if not any(l.kind == launch.kind and l.unit == launch.unit and l.detail == launch.detail for l in group.launches):
            group.launches.append(launch)
    for group in groups.values():
        group.mem_is_pss = all(p.pss_kb is not None for p in group.procs)
        group.mem_kb = sum(p.pss_kb if p.pss_kb is not None else p.rss_kb for p in group.procs)
        group.swap_kb = sum(p.swap_kb for p in group.procs)
        group.cpu_now = sum(p.cpu_now for p in group.procs)
        group.cpu_seconds = sum(p.cpu_ticks for p in group.procs) / CLK_TCK
        group.oldest_start = min(p.start_epoch for p in group.procs)
        uptime = max(NOW - group.oldest_start, 1)
        group.cpu_avg = group.cpu_seconds / uptime * 100
        comm = group.procs[0].comm
        # Only the group's own processes say what it is; folded children (a netdata plugin
        # named systemd-journal.plugin, say) must not make it look like part of the system.
        own = [p for p in group.procs if p.pid not in folded] or group.procs
        every = {p.comm for p in own} | {os.path.basename(p.exe) for p in own if p.exe} | \
            {os.path.basename(p.cmdline[0]) for p in own if p.cmdline and p.cmdline[0]}
        group.cls = safety_class(group.name, every, group.prov, {l.kind for l in group.launches})
        group.tip = OPTIONAL_TIPS.get(group.name) or next((OPTIONAL_TIPS[n] for n in sorted(every) if n in OPTIONAL_TIPS), None) \
            or (PACKAGE_TIPS.get(group.prov.name) if group.prov.kind == "system-package" else None)
        if group.prov.kind == "system-package" and group.name != comm and len({p.comm for p in group.procs}) == 1:
            group.name = f"{comm} ({group.prov.name})"
        if any(p.exe_deleted for p in group.procs):
            group.prov.notes.append("its program file was replaced or deleted since it started (restart it to pick up an update)")
    return sorted(groups.values(), key=lambda g: g.mem_kb + g.swap_kb, reverse=True)


# ---------------------------------------------------------------------------
# systemd unit details, shell rc mentions, startup inventory
# ---------------------------------------------------------------------------


def target_user() -> Tuple[str, str, int]:
    """The desktop user to report on (the sudo caller when run with sudo)."""
    name = os.environ.get("SUDO_USER") if os.geteuid() == 0 else None
    entry = pwd.getpwnam(name) if name else pwd.getpwuid(os.getuid())
    return entry.pw_name, entry.pw_dir, entry.pw_uid


def systemctl(scope: str, args: List[str], user: str) -> str:
    if scope == "user":
        base = ["systemctl", "--user"]
        if os.geteuid() == 0 and user != "root":
            base += ["-M", f"{user}@"]
    else:
        base = ["systemctl"]
    return run(base + ["--no-pager"] + args, timeout=20)


def unit_details(scope: str, units: List[str], user: str) -> Dict[str, Dict[str, str]]:
    if not units or not shutil.which("systemctl"):
        return {}
    out = systemctl(scope, ["show", "-p", "Id,FragmentPath,SourcePath,UnitFileState,Description,ActiveState,TriggeredBy"] + units, user)
    details: Dict[str, Dict[str, str]] = {}
    for block in out.split("\n\n"):
        props = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if props.get("Id"):
            details[props["Id"]] = props
    return details


UNIT_DIRS = {
    "user": ["~/.config/systemd/user", "~/.local/share/systemd/user", "/etc/systemd/user", "/usr/local/lib/systemd/user",
             "/usr/lib/systemd/user", "/lib/systemd/user"],
    "system": ["/etc/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"],
}


def find_unit_file(scope: str, name: str, home: str) -> str:
    """Locate a unit file on disk when systemd itself cannot be asked (no running manager)."""
    template = re.sub(r"@[^.]+\.", "@.", name)
    for directory in UNIT_DIRS[scope]:
        directory = directory.replace("~", home, 1)
        for candidate in (name, template):
            path = os.path.join(directory, candidate)
            if os.path.exists(path):
                return realpath(path) if os.path.islink(path) and not os.path.realpath(path).startswith("/dev/") else path
    return ""


def unit_origin(fragment: str, owners: PackageOwners, home: str) -> str:
    if not fragment:
        return "unknown"
    if os.path.basename(fragment).startswith("snap."):
        return "created by snapd for a snap"
    if fragment.startswith(home + "/"):
        return "added in your home folder (by you or an install script)"
    if fragment.startswith(("/run/", "/tmp/")):
        return "generated at boot"
    if owners.owner(fragment):
        return f"from package {owners.owner(fragment)}"
    if fragment.startswith("/etc/"):
        return "added to /etc by an install script (no package owns it)"
    if fragment.startswith(("/usr/lib/", "/lib/")):
        return "not owned by any package (possibly left behind by a removed package)"
    return "not owned by any package"


RC_FILES = [".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zlogin", ".zshenv",
            ".xprofile", ".xsessionrc", ".xinitrc", ".config/fish/config.fish", ".config/fish/conf.d/*.fish",
            ".config/plasma-workspace/env/*", ".config/autostart-scripts/*"]
GENERIC_TOKENS = {"python", "python3", "node", "bash", "sh", "zsh", "env", "sleep", "java", "ruby", "perl", "bin", "main", "index", "run",
                  "start", "server", "app", "cli", "daemon", "agent", "service", "test", "init", "true", "false", "cat", "less", "git"}


def rc_lines(home: str, user: str) -> List[Tuple[str, int, str]]:
    lines: List[Tuple[str, int, str]] = []
    for pattern in RC_FILES:
        for path in sorted(glob.glob(os.path.join(glob.escape(home), pattern))):
            if not os.path.isfile(path):
                continue
            for number, line in enumerate((read_text(path, limit=1 << 20) or "").splitlines(), 1):
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    lines.append((path, number, stripped))
    if shutil.which("crontab"):
        cmd = ["crontab", "-l"] + (["-u", user] if os.geteuid() == 0 else [])
        for number, line in enumerate(run(cmd).splitlines(), 1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(("crontab", number, stripped))
    return lines


def find_mentions(group: Group, lines: List[Tuple[str, int, str]]) -> List[str]:
    tokens = set()
    for target in group.targets:
        for path in (target.path,):
            if path and not is_system_path(path):
                tokens.add(os.path.basename(path))
        if target.module:
            tokens.add(target.module)
    if group.prov.kind in SIDE_INSTALL_KINDS:
        tokens.add(group.prov.name)
        if group.prov.location and "/" in group.prov.location:
            location = group.prov.location.split(":")[0]
            tokens.update({location, Paths.show(location)})
    tokens = {t for t in tokens if len(t) >= 3 and t.lower() not in GENERIC_TOKENS}
    found: List[str] = []
    for path, number, line in lines:
        for token in tokens:
            if re.search(rf"(?<![\w.-]){re.escape(token)}(?![\w-])", line):
                where = "crontab" if path == "crontab" else Paths.show(path)
                found.append(f"{where} line {number}: `{redact_text(line[:160])}`")
                break
    return found[:6]


@dataclass
class StartupItem:
    kind: str           # user-unit | system-unit | autostart | autostart-system | login-script | cron | shell-background
    name: str
    location: str
    command: str = ""
    enabled: bool = True
    origin: str = ""
    third_party: bool = False
    running: Optional[str] = None
    off_hint: str = ""


def redact_exec(command: str) -> str:
    try:
        return " ".join(redact_argv(shlex.split(command)))
    except ValueError:
        return redact_text(command)


def parse_desktop(path: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    in_entry = False
    for line in (read_text(path, limit=65536) or "").splitlines():
        line = line.strip()
        if line.startswith("["):
            in_entry = line == "[Desktop Entry]"
            continue
        if in_entry and "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values.setdefault(key.strip(), value.strip())
    return values


def desktop_applies(values: Dict[str, str]) -> bool:
    desktops = set((os.environ.get("XDG_CURRENT_DESKTOP") or "KDE").split(":"))
    if values.get("Hidden", "").lower() == "true":
        return False
    if values.get("X-GNOME-Autostart-enabled", "").lower() == "false":
        return False
    only = {d for d in values.get("OnlyShowIn", "").split(";") if d}
    never = {d for d in values.get("NotShowIn", "").split(";") if d}
    if only and not only & desktops:
        return False
    if never & desktops:
        return False
    try_exec = values.get("TryExec")
    if try_exec and not (shutil.which(try_exec) or os.path.exists(try_exec)):
        return False
    return True


BACKGROUND_LINE = re.compile(r"(\bnohup\b|&\s*(#.*)?$|\bdisown\b|\bsetsid\b|tmux\s+new(-session)?\b.*\s-d|screen\s+-[a-zA-Z]*d[a-zA-Z]*m|\bdaemon(ize)?\b|--daemon\b)")


def startup_inventory(owners: PackageOwners, user: str, home: str) -> List[StartupItem]:
    items: List[StartupItem] = []
    if shutil.which("systemctl"):
        for scope in ("user", "system"):
            listing = systemctl(scope, ["list-unit-files", "--state=enabled", "--type=service,timer,socket,path", "--no-legend"], user)
            names = [line.split()[0] for line in listing.splitlines() if line.strip()]
            details = unit_details(scope, names, user)
            fragments = [details.get(n, {}).get("FragmentPath", "") or find_unit_file(scope, n, home) for n in names]
            owners.lookup_many(f for f in fragments if f.startswith(SYSTEM_PREFIXES))
            for name in names:
                props = details.get(name, {})
                fragment = props.get("FragmentPath", "") or find_unit_file(scope, name, home)
                origin = unit_origin(fragment, owners, home)
                third = not origin.startswith("from package") and origin not in ("generated at boot", "unknown")
                sudo = "" if scope == "user" else "sudo "
                flag = "--user " if scope == "user" else ""
                items.append(StartupItem(
                    kind=f"{scope}-unit", name=name, location=fragment, command=props.get("Description", ""),
                    origin=origin, third_party=third,
                    off_hint=f"`{sudo}systemctl {flag}disable --now {name}`" + (f" (or `{sudo}systemctl {flag}mask {name}` if something re-enables it)" if not third else ""),
                ))
    owners.lookup_many(glob.glob("/etc/xdg/autostart/*.desktop"))
    user_dir = os.path.join(home, ".config/autostart")
    overridden = set(os.listdir(user_dir)) if os.path.isdir(user_dir) else set()
    for directory, kind in ((user_dir, "autostart"), ("/etc/xdg/autostart", "autostart-system")):
        for path in sorted(glob.glob(os.path.join(glob.escape(directory), "*.desktop"))):
            base = os.path.basename(path)
            if kind == "autostart-system" and base in overridden:
                continue
            values = parse_desktop(path)
            enabled = desktop_applies(values)
            if not enabled and kind == "autostart-system":
                continue
            origin = "in your home folder"
            if kind == "autostart-system":
                pkg = owners.owner(path)
                origin = f"from package {pkg}" if pkg else "added to /etc by an install script (no package owns it)"
            hint = ("System Settings > Autostart, or delete " + f"`{Paths.show(path)}`") if kind == "autostart" else \
                f"System Settings > Autostart (it writes a `Hidden=true` copy to `~/.config/autostart/{base}`)"
            items.append(StartupItem(
                kind=kind, name=values.get("Name") or base[:-8], location=path, command=redact_exec(values.get("Exec", "")),
                enabled=enabled, origin=origin, third_party=kind == "autostart" or "no package" in origin, off_hint=hint,
            ))
    for pattern in (".config/plasma-workspace/env/*", ".config/autostart-scripts/*", ".config/plasma-workspace/shutdown/*"):
        for path in sorted(glob.glob(os.path.join(glob.escape(home), pattern))):
            when = "logout" if "/shutdown/" in pattern else "login"
            items.append(StartupItem(kind="login-script", name=os.path.basename(path), location=path,
                                     command=f"(runs at every Plasma {when})", origin="in your home folder", third_party=True,
                                     off_hint=f"move `{Paths.show(path)}` out of that folder"))
    for path, number, line in rc_lines(home, user):
        if "/plasma-workspace/" in path or "/autostart-scripts/" in path:
            continue
        if path == "crontab":
            items.append(StartupItem(kind="cron", name=line.split()[0] if line.startswith("@") else "cron job", location=f"crontab line {number}",
                                     command=redact_text(line[:200]), origin="your crontab", third_party=True, off_hint="`crontab -e` and delete or comment the line"))
        elif BACKGROUND_LINE.search(line):
            items.append(StartupItem(kind="shell-background", name=os.path.basename(path), location=f"{path} line {number}",
                                     command=redact_text(line[:200]), origin="your shell startup file", third_party=True,
                                     off_hint=f"comment out line {number} in `{Paths.show(path)}`"))
    return items


def link_startup(items: List[StartupItem], groups: List[Group]) -> None:
    """Mark which startup items are running now, and give running programs the startup item's off switch."""
    by_unit: Dict[str, Group] = {}
    by_desktop: Dict[str, Group] = {}
    by_basename: Dict[str, Group] = {}
    for group in groups:
        for launch in group.launches:
            if launch.unit:
                by_unit.setdefault(launch.unit, group)
            if launch.desktop_name:
                by_desktop.setdefault(launch.desktop_name, group)
        for target in group.targets:
            if target.path:
                by_basename.setdefault(os.path.basename(target.path), group)
    for item in items:
        group = by_unit.get(item.name)
        if not group and item.kind.startswith("autostart"):
            stem = os.path.basename(item.location)[:-8]
            group = by_desktop.get(stem)
            if not group and item.command:
                try:
                    words = [w for w in shlex.split(item.command) if "=" not in w and w not in ("env", "sh", "bash", "-c")]
                except ValueError:
                    words = item.command.split()
                if words:
                    group = by_basename.get(os.path.basename(words[0]))
        if not group and item.kind in ("shell-background", "cron", "login-script") and item.command:
            for candidate in groups:
                names = {os.path.basename(t.path) for t in candidate.targets if t.path and not is_system_path(t.path)}
                if any(len(n) >= 3 and re.search(rf"(?<![\w.-]){re.escape(n)}(?![\w-])", item.command) for n in names):
                    group = candidate
                    break
        if group:
            item.running = f"{group.name} ({fmt_bytes(group.mem_kb)})"
            existing = group.disable_hint or ""
            covered = (item.kind.endswith("-unit") and item.name in existing) or \
                (item.kind.startswith("autostart") and "Autostart" in existing)
            if item.off_hint and item.enabled and not covered:
                group.disable_hint = "; ".join(filter(None, [group.disable_hint, f"{item.off_hint} (startup entry `{item.name}`)"]))


# ---------------------------------------------------------------------------
# Hints, verdicts, history
# ---------------------------------------------------------------------------


def finish_group(group: Group, user_details: Dict[str, Dict[str, str]], system_details: Dict[str, Dict[str, str]],
                 owners: PackageOwners, home: str) -> None:
    pids = " ".join(str(p.pid) for p in sorted(group.procs, key=lambda p: p.pid)[:12])
    stops, disables = [], []
    for launch in group.launches:
        details = (user_details if launch.scope == "user" else system_details).get(launch.unit or "", {})
        if details:
            group.unit_files[launch.unit] = {
                "file": details.get("FragmentPath") or details.get("SourcePath") or "",
                "state": details.get("UnitFileState", ""),
                "origin": unit_origin(details.get("FragmentPath", ""), owners, home),
                "source": details.get("SourcePath", ""),
                "triggered_by": details.get("TriggeredBy", ""),
            }
        if launch.kind in ("user-service", "system-service"):
            ctl = "systemctl --user" if launch.kind == "user-service" else "sudo systemctl"
            stops.append(f"`{ctl} stop {launch.unit}`")
            if details.get("UnitFileState") in ("static", "indirect"):
                # Static units have no [Install] section and are started on demand; disable does nothing.
                disables.append(f"`{ctl} mask --now {launch.unit}` (it starts on demand, so it has to be masked; undo with `unmask`)")
            else:
                disables.append(f"`{ctl} disable --now {launch.unit}`")
            if details.get("TriggeredBy"):
                disables.append(f"also `{ctl} disable --now {details['TriggeredBy']}`")
        elif launch.kind == "autostart":
            source = details.get("SourcePath") or ""
            if source.startswith(home + "/"):
                disables.append(f"System Settings > Autostart, or delete `{Paths.show(source)}`")
            else:
                disables.append("System Settings > Autostart (switch it off there; that writes a `Hidden=true` override in "
                                "`~/.config/autostart` that survives updates; don't delete the file in /etc)")
        elif launch.kind == "cron":
            disables.append("`crontab -e` (or check /etc/cron.d) and remove the job")
        elif launch.kind == "container" and not group.prov.disable_hint:
            disables.append("change the container's restart policy (`docker update --restart=no <name>`) or its compose file")
    if group.prov.kind == "flatpak":
        stops.insert(0, f"`flatpak kill {group.prov.name}`")
    if group.prov.stop_hint:
        stops = [group.prov.stop_hint]
    if group.prov.disable_hint:
        disables.insert(0, group.prov.disable_hint)
    if not stops:
        stops.append(f"quit it normally, or `kill {pids}`")
    if group.mentions and not disables:
        disables.append("edit the line(s) listed under 'mentioned in'")
    group.stop_hint = "; ".join(dict.fromkeys(stops))
    group.disable_hint = "; ".join(dict.fromkeys(disables)) or None

    big = group.mem_kb + group.swap_kb >= HOG_KB
    other_user = os.geteuid() != 0 and all(p.uid != os.geteuid() for p in group.procs)
    if group.prov.kind == "unknown" and other_user:
        group.verdict = "belongs to another user (usually root); run with sudo to identify it"
    elif group.cls == "core":
        group.verdict = "keep: part of the desktop or system"
    elif group.cls == "optional":
        group.verdict = ("optional, idle and big" if group.idle and big else "optional, and idle" if group.idle else "optional") \
            + ("; see tip" if group.tip else "")
    elif group.cls == "system" and group.tip:
        group.verdict = ("idle and big; see tip" if group.idle and big else "system service; see tip")
    elif group.cls == "system" and NOW - group.oldest_start < 120 and {l.kind for l in group.launches} <= {"terminal", "ssh", "child"} and {l.kind for l in group.launches} & {"terminal", "ssh"}:
        group.verdict = "a command you just started in a terminal"
    elif group.cls == "system" and "widget" in {l.kind for l in group.launches}:
        group.verdict = "run by a Plasma widget" + (f"; costs {group.cpu_avg:.1f}% CPU on average" if group.cpu_avg >= 1 else "")
    elif group.cls == "system":
        group.verdict = "system component; leave it unless you know you don't need it"
    elif group.idle and big:
        group.verdict = "IDLE HOG: big and doing nothing; good candidate to stop or disable"
    elif group.idle:
        group.verdict = "idle; candidate if you don't recognize it"
    elif NOW - group.oldest_start < 120 and {l.kind for l in group.launches} <= {"terminal", "ssh", "child"} and {l.kind for l in group.launches} & {"terminal", "ssh"}:
        group.verdict = "a command you just started in a terminal"
    elif group.cpu_now >= 25:
        group.verdict = f"busy right now ({group.cpu_now:.0f}% CPU)"
    else:
        group.verdict = "active"


GENERIC_APP_NAMES = {"node", "nodejs", "java", "python", "python3", "bash", "sh", "dash", "zsh", "ruby", "perl", "php", "bun",
                     "deno", "main", "MainThread", "node-MainThread", "entrypoint", "entrypoint_sh", "docker-entrypoi",
                     "docker-entrypoint", "healthcheck", "healthcheck_sh", "sleep", "cat", "curl", "agent", "cli", "build",
                     "desktop", "daily", "backup", "null", "kernel", "louthenw", "chmod", "sudo"}


class NetdataHistory:
    """Read-only access to a local Netdata agent's stored history for services, containers and programs."""

    def __init__(self, base_url: str = "http://localhost:19999", timeout: float = 4.0) -> None:
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.charts: Set[str] = set()
        self.first_entry: Optional[float] = None
        self.available = False
        self.errors: List[str] = []

    def _get(self, path: str) -> Optional[dict]:
        for attempt in range(2):
            try:
                with urllib.request.urlopen(self.base + path, timeout=self.timeout * (attempt + 1)) as response:
                    return json.loads(response.read().decode("utf-8", "replace"))
            except (OSError, ValueError) as error:
                if attempt:
                    self.errors.append(f"{path.split('?')[0]}: {error}")
        return None

    def connect(self) -> bool:
        charts = self._get("/api/v1/charts")
        if not isinstance(charts, dict) or not isinstance(charts.get("charts"), dict):
            return False
        self.charts = set(charts["charts"])
        meta = self._get("/api/v1/chart?chart=system.cpu") or {}
        self.first_entry = meta.get("first_entry")
        self.available = bool(self.charts)
        return self.available

    def series(self, chart: str, seconds: int, points: int) -> List[float]:
        """Per-interval totals across the chart's dimensions (absolute values), oldest first."""
        query = urllib.parse.urlencode({"chart": chart, "after": -seconds, "points": points, "group": "average",
                                        "format": "json", "options": "abs"})
        data = self._get(f"/api/v1/data?{query}") or {}
        totals = []
        for row in data.get("data") or []:
            values = [v for v in row[1:] if isinstance(v, (int, float))]
            if values:
                totals.append(float(sum(values)))
        return totals

    def charts_for(self, group: "Group", tried: Optional[List[str]] = None) -> List[Tuple[str, str, str]]:
        """(metric, chart id, where the numbers come from) for one program row."""
        found: List[Tuple[str, str, str]] = []
        tried = tried if tried is not None else []
        prov = group.prov
        if prov.kind == "container" and not prov.name.startswith(("docker container", "podman container")):
            name = prov.name.replace(" (LXC)", "")
            prefix = f"cgroup_{name}."
            if prefix + "cpu" in self.charts:
                found.append(("cpu", prefix + "cpu", f"container `{name}`"))
                for chart in sorted(c for c in self.charts if c.startswith(prefix + "net_")):
                    suffix = chart[len(prefix) + 4:]
                    if suffix and not re.match(r"(carrier|drops|errors|events|packets|fifo|operstate|mtu|speed|duplex)_", suffix):
                        found.append(("net", chart, f"container `{name}`"))
                return found
        for launch in group.launches:
            if launch.kind in ("system-service",) and launch.unit and launch.unit.endswith(".service"):
                stem = launch.unit[: -len(".service")].replace("@", "_")
                if f"systemd_{stem}.cpu" in self.charts:
                    found.append(("cpu", f"systemd_{stem}.cpu", f"service `{launch.unit}`"))
                    if f"systemd_{stem}.io" in self.charts:
                        found.append(("disk", f"systemd_{stem}.io", f"service `{launch.unit}`"))
                    return found
        names: List[str] = []
        for proc in group.procs:
            for candidate in (proc.comm, os.path.basename(proc.exe or ""),
                              os.path.basename(proc.cmdline[0].split()[0]) if proc.cmdline and proc.cmdline[0].strip() else ""):
                if candidate and candidate not in names:
                    names.append(candidate)
        names += [n for n in (prov.name, group.name.split(" (")[0]) if n and n not in names]
        for name in names:
            if name in GENERIC_APP_NAMES or len(name) < 3:
                continue
            chart = f"app.{name}_cpu_utilization"
            tried.append(name)
            if chart in self.charts:
                where = f"every process named `{name}`"
                found.append(("cpu", chart, where))
                if f"app.{name}_disk_logical_io" in self.charts:
                    found.append(("disk", f"app.{name}_disk_logical_io", where))
                return found
        return found

    def history_for(self, group: "Group") -> Dict[str, object]:
        tried: List[str] = []
        charts = self.charts_for(group, tried)
        if not charts:
            return {"no_chart": tried} if tried else {}
        out: Dict[str, object] = {"source": charts[0][2], "chart": charts[0][1]}
        spans = (("7d", 7 * 86400, 168), ("30d", 30 * 86400, 120))
        for metric, chart, _ in charts:
            for label, seconds, points in spans:
                values = self.series(chart, seconds, points)
                if not values:
                    continue
                window = seconds / len(values) if values else seconds
                if metric == "cpu":
                    out[f"cpu_avg_{label}"] = round(sum(values) / len(values), 3)
                    out[f"cpu_peak_{label}"] = round(max(values), 2)
                elif metric == "net":
                    # kilobits per second averaged per interval -> bytes moved in the window
                    out[f"net_bytes_{label}"] = out.get(f"net_bytes_{label}", 0) + sum(values) * window * 1000 / 8
                elif metric == "disk":
                    # KiB per second averaged per interval -> bytes read+written in the window
                    out[f"disk_bytes_{label}"] = out.get(f"disk_bytes_{label}", 0) + sum(values) * window * 1024
        if self.first_entry and NOW - self.first_entry < 30 * 86400:
            out["since"] = self.first_entry
        if "cpu_avg_7d" not in out:
            out["no_data"] = True
        return out


def fmt_volume(num_bytes: Optional[float]) -> str:
    return fmt_bytes(num_bytes / 1024) if num_bytes is not None else "?"


def history_text(history: Dict[str, object]) -> str:
    if not history:
        return ""
    if "no_chart" in history:
        return "no matching Netdata chart (looked for program groups: " + ", ".join(f"`{n}`" for n in history["no_chart"][:6]) + ")"
    if history.get("no_data"):
        return f"Netdata has chart `{history['chart']}` but returned no data for it"
    parts = []
    if "cpu_avg_7d" in history:
        parts.append(f"CPU last 7 days avg {history['cpu_avg_7d']:.2f}% (busiest hour {history['cpu_peak_7d']:.1f}%)")
    if "cpu_avg_30d" in history:
        since = f" (since {fmt_date(history['since'])})" if history.get("since") else ""
        parts.append(f"last 30 days avg {history['cpu_avg_30d']:.2f}%{since}")
    if "net_bytes_7d" in history:
        parts.append(f"network last 7 days {fmt_volume(history['net_bytes_7d'])}")
    if "disk_bytes_7d" in history:
        parts.append(f"disk I/O last 7 days {fmt_volume(history['disk_bytes_7d'])}")
    text = "; ".join(parts) + f" (Netdata chart `{history['chart']}`, {history['source']})"
    if history.get("hidden_cpu"):
        text += (f". The processes running now account for only {history['hidden_cpu']:.2f}% on average: most of this CPU is "
                 "spent in short-lived processes it keeps starting (health checks, scripts, helpers), which a snapshot can't see")
    return text


def apply_netdata(groups: List[Group], netdata: NetdataHistory) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for group, history in zip(groups, pool.map(netdata.history_for, groups)):
            group.history = history
            mark_hidden_cpu(group)


def mark_hidden_cpu(group: Group) -> None:
    """Note when Netdata's whole-unit CPU is far above what the live processes have used."""
    avg = group.history.get("cpu_avg_7d") if group.history else None
    if isinstance(avg, float) and group.history.get("source", "").startswith(("service", "container")) \
            and avg >= 3 * group.cpu_avg and avg - group.cpu_avg >= 2:
        group.history["hidden_cpu"] = round(group.cpu_avg, 2)


def state_dir() -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(Paths.home, ".local/state")
    return os.path.join(base, "process-triage")


def load_history(directory: str, limit: int = 60) -> List[dict]:
    snaps = []
    for path in sorted(glob.glob(os.path.join(glob.escape(directory), "scan-*.json")))[-limit:]:
        try:
            with open(path) as handle:
                data = json.load(handle)
            snaps.append({"time": data.get("time"), "programs": {p["key"]: p for p in data.get("programs", [])}})
        except (OSError, ValueError, KeyError):
            continue
    return snaps


def apply_history(groups: List[Group], history: List[dict]) -> None:
    if not history:
        return
    for group in groups:
        hits = [s for s in history if group.key in s["programs"]]
        first = min((s["time"] for s in hits), default=None)
        group.seen = f"running in {len(hits) + 1} of {len(history) + 1} scans" + (f" since {fmt_date(first)}" if first else "")


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str: return self.wrap("1", t)
    def dim(self, t: str) -> str: return self.wrap("2", t)
    def red(self, t: str) -> str: return self.wrap("1;31", t)
    def yellow(self, t: str) -> str: return self.wrap("33", t)
    def green(self, t: str) -> str: return self.wrap("32", t)
    def cyan(self, t: str) -> str: return self.wrap("36", t)


def installed_text(prov: Provenance) -> str:
    via = KIND_LABELS.get(prov.kind, prov.kind)
    if prov.kind == "system-package":
        via = f"{via} `{prov.name}`" + (" (you installed it)" if prov.manual else " (dependency)" if prov.manual is False else "")
    date = f", {fmt_date(prov.installed_at)}" if prov.installed_at else ""
    return via + date


def launch_text(group: Group) -> str:
    texts = [l.detail for l in group.launches]
    return texts[0] + (f" (+{len(texts) - 1} other ways)" if len(texts) > 1 else "")


def print_terminal(groups: List[Group], items: List[StartupItem], meminfo: Dict[str, int], args, style: Style) -> None:
    width = shutil.get_terminal_size((120, 40)).columns
    total, avail = meminfo.get("MemTotal", 0), meminfo.get("MemAvailable", 0)
    swap_used = meminfo.get("SwapTotal", 0) - meminfo.get("SwapFree", 0)
    print(style.bold(f"process-triage {VERSION}") + style.dim(" (read-only, nothing was changed)"))
    where = swap_summary(swap_devices())
    print(f"Memory: {fmt_bytes(total - avail)} used of {fmt_bytes(total)}, swap used {fmt_bytes(swap_used)}"
          + (f" ({where})" if where else "") + ". "
          f"{sum(len(g.procs) for g in groups)} processes in {len(groups)} programs.\n")
    shown = [g for g in groups if not args.mine or g.cls in ("yours", "optional")]
    shown = shown if args.all else shown[: args.top]
    colors = {"core": style.dim, "system": style.dim, "optional": style.cyan, "yours": style.yellow}
    for index, group in enumerate(shown, 1):
        paint = colors.get(group.cls, str)
        mem = fmt_bytes(group.mem_kb) + ("" if group.mem_is_pss else "*")
        swap = f" +{fmt_bytes(group.swap_kb)} swap" if group.swap_kb > 10240 else ""
        head = f"{index:>3}. {mem:>9}  {group.cpu_now:5.1f}%  " + paint(style.bold(group.name)) + f"  {style.dim('·')} {installed_text(group.prov)}"
        print(head[: width + 40] + swap)
        pad = " " * 22
        info = f"started by: {launch_text(group)} · {len(group.procs)} proc · up {fmt_age(NOW - group.oldest_start)} · avg {group.cpu_avg:.2f}% CPU"
        print(pad + style.dim(info[: max(width - 22, 40)]))
        verdict = group.verdict
        if verdict.startswith("IDLE HOG"):
            verdict = style.red(verdict)
        elif group.cls == "yours":
            verdict = style.yellow(verdict)
        print(pad + "→ " + verdict)
        if group.history and "cpu_avg_7d" in group.history:
            h = group.history
            extra = f" · net {fmt_volume(h['net_bytes_7d'])}" if "net_bytes_7d" in h else ""
            if h.get("hidden_cpu") is not None:
                extra += " · mostly in short-lived processes"
            print(pad + "  " + style.dim(f"7 days: avg {h['cpu_avg_7d']:.2f}% CPU, busiest hour {h['cpu_peak_7d']:.1f}%{extra}"))
        if group.tip and (args.tips or group.cls != "core"):
            print(pad + "  " + style.cyan("tip: ") + style.dim(group.tip[: max(width - 30, 60)]))
    hidden = len(groups) - len(shown)
    if hidden > 0:
        print(style.dim(f"\n   … {hidden} more (use --all; --mine shows only things you or side installers added)"))
    third = [i for i in items if i.third_party and i.enabled]
    if third:
        print("\n" + style.bold("Set to start automatically, added outside your package manager:"))
        for item in third[:40]:
            running = style.green(f"running: {item.running}") if item.running else style.dim("not running now")
            print(f"   • {style.bold(item.name)}  {style.dim('[' + item.kind + ']')}  {running}")
            detail = Paths.show(item.location) + (f" — {item.command}" if item.command else "")
            if detail.strip():
                print("     " + style.dim(detail[: max(width - 5, 40)]))
    if any(not g.mem_is_pss for g in shown):
        print(style.dim("\n* memory is RSS (shared pages counted more than once); run with sudo for exact figures on other users' processes."))


def detail_lines(g: Group) -> List[str]:
    """Everything known about one program, as Markdown list lines."""
    p = g.prov
    out: List[str] = [f"- **Verdict:** {g.verdict}"]
    if g.tip:
        out.append(f"- **About it:** {g.tip}")
    out.append(f"- **Installed via:** {installed_text(p).split(',')[0] if p.kind == 'system-package' else KIND_LABELS.get(p.kind, p.kind)}"
               + (f", version {p.version}" if p.version else ""))
    if p.installed_at:
        out.append(f"- **Installed:** {fmt_date(p.installed_at)} ({p.date_note})")
    if p.source:
        out.append(f"- **Came from:** {p.source}")
    if p.location and p.kind != "system-package":
        out.append(f"- **Lives at:** `{Paths.show(p.location)}`")
    out.extend(f"- {note}" for note in p.notes)
    out.append("- **Started by:** " + "; ".join(l.detail for l in g.launches))
    chains = {" › ".join(list(reversed(l.parent_chain)) + [l.leaf or g.procs[0].comm]) for l in g.launches if l.parent_chain}
    out.extend(f"  - process tree: {chain}" for chain in sorted(chains)[:3])
    for unit, info in g.unit_files.items():
        out.append(f"  - `{unit}`: {info['state'] or 'transient'}, file `{Paths.show(info['file'])}` ({info['origin']})")
    out.extend(f"- **Mentioned in:** {mention}" for mention in g.mentions)
    if g.history:
        out.append(f"- **Over time:** {history_text(g.history)}")
    if g.seen:
        out.append(f"- **Scan history:** {g.seen}")
    out.append(f"- **Uses:** {fmt_bytes(g.mem_kb)} memory" + (f" + {fmt_bytes(g.swap_kb)} swap" if g.swap_kb else "") +
               f", {g.cpu_now:.1f}% CPU now, {g.cpu_avg:.2f}% on average since it started {fmt_age(NOW - g.oldest_start)} ago, "
               f"{len(g.procs)} process(es)")
    out.append(f"- **Stop it now:** {g.stop_hint}")
    if g.disable_hint:
        out.append(f"- **Keep it from starting:** {g.disable_hint}")
    if p.remove_hint:
        out.append(f"- **Remove it:** {p.remove_hint}")
    out.append("- **Processes:**")
    for proc in sorted(g.procs, key=lambda x: -(x.pss_kb or x.rss_kb))[:8]:
        cmd = " ".join(redact_argv(proc.cmdline))[:240] or proc.comm
        out.append(f"  - pid {proc.pid}, {fmt_bytes(proc.pss_kb or proc.rss_kb)}: `{Paths.show_all(cmd)}`")
    if len(g.procs) > 8:
        out.append(f"  - … and {len(g.procs) - 8} more")
    return out


def markdown_report(groups: List[Group], items: List[StartupItem], meminfo: Dict[str, int], meta: Dict[str, str]) -> str:
    out = io.StringIO()
    w = out.write
    total, avail = meminfo.get("MemTotal", 0), meminfo.get("MemAvailable", 0)
    w(f"# What's running on {meta['host']}\n\n")
    w(f"Scanned {meta['time_text']} with process-triage {VERSION}. **Read-only: nothing was changed.** "
      "Commands below are suggestions for you to review.\n\n")
    where = swap_summary(swap_devices())
    w(f"Memory in use: {fmt_bytes(total - avail)} of {fmt_bytes(total)}. Swap in use: "
      f"{fmt_bytes(meminfo.get('SwapTotal', 0) - meminfo.get('SwapFree', 0))}" + (f" ({where})" if where else "") +
      f". Desktop: {meta['desktop']}. Distro: {meta['distro']}.\n\n")
    w("## Programs, biggest first\n\n")
    w("| # | Memory | CPU now | Avg CPU | Program | Installed via | Started by | Verdict |\n|---|---|---|---|---|---|---|---|\n")
    for index, g in enumerate(groups, 1):
        cell = lambda t: str(t).replace("|", "\\|")
        w(f"| {index} | {fmt_bytes(g.mem_kb)}{'' if g.mem_is_pss else '*'} | {g.cpu_now:.1f}% | {g.cpu_avg:.2f}% | "
          f"{cell(g.name)} | {cell(installed_text(g.prov))} | {cell(launch_text(g))} | {cell(g.verdict)} |\n")
    w("\n\\* RSS instead of PSS: shared memory is counted more than once (no permission to read exact figures).\n\n")
    w("## Details for things you, a side installer or a service stack added\n\n")
    for g in [g for g in groups if g.cls in ("yours", "optional") or (g.cls == "system" and g.tip)]:
        w(f"### {g.name}\n\n")
        w("".join(line + "\n" for line in detail_lines(g)))
        w("\n")
    w("## Everything set to start automatically\n\n")
    w("| Name | Kind | Running now | Origin | Note | Where | Turn off |\n|---|---|---|---|---|---|---|\n")
    for item in sorted(items, key=lambda i: (not i.third_party, i.kind, i.name.lower())):
        cell = lambda t: str(t).replace("|", "\\|").replace("\n", " ")
        w(f"| {cell(item.name)} | {item.kind}{'' if item.enabled else ' (disabled)'} | {cell(item.running or '—')} | "
          f"{cell(item.origin)} | {cell(unit_note(os.path.basename(item.location) or item.name))} | "
          f"`{cell(Paths.show(item.location))}` | {cell(item.off_hint)} |\n")
    w("\n")
    return out.getvalue()


def json_report(groups: List[Group], items: List[StartupItem], meminfo: Dict[str, int], meta: Dict[str, str]) -> dict:
    programs = []
    for g in groups:
        programs.append({
            "key": g.key, "name": g.name, "class": g.cls, "verdict": g.verdict, "tip": g.tip,
            "memory_kb": g.mem_kb, "memory_is_pss": g.mem_is_pss, "swap_kb": g.swap_kb,
            "cpu_now": round(g.cpu_now, 2), "cpu_avg": round(g.cpu_avg, 3), "cpu_seconds": round(g.cpu_seconds, 1),
            "started": g.oldest_start, "idle": g.idle, "provenance": asdict(g.prov),
            "launches": [asdict(l) for l in g.launches], "unit_files": g.unit_files, "mentions": g.mentions,
            "stop_hint": g.stop_hint, "disable_hint": g.disable_hint, "seen": g.seen, "history": g.history,
            "processes": [{"pid": p.pid, "ppid": p.ppid, "uid": p.uid, "comm": p.comm, "exe": p.exe,
                           "cmdline": redact_argv(p.cmdline)[:40], "memory_kb": p.pss_kb or p.rss_kb, "cpu_now": round(p.cpu_now, 2),
                           "cgroup": p.cgroup, "cwd": Paths.show(p.cwd) if p.cwd else None} for p in g.procs],
        })
    return {"tool": "process-triage", "version": VERSION, "time": NOW, "meta": meta, "meminfo_kb": meminfo,
            "programs": programs, "startup": [asdict(i) for i in items]}


def swap_devices(swaps_text: Optional[str] = None) -> List[Dict[str, object]]:
    """Swap devices from /proc/swaps, marking zram (compressed RAM) with its real RAM cost."""
    text = swaps_text if swaps_text is not None else (read_text("/proc/swaps") or "")
    devices = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        name, kind, used_kb = fields[0], fields[1], int(fields[3]) if fields[3].isdigit() else 0
        device = {"name": name, "type": kind, "used_kb": used_kb, "zram": os.path.basename(name).startswith("zram")}
        if device["zram"]:
            stat = (read_text(f"/sys/block/{os.path.basename(name)}/mm_stat") or "").split()
            if len(stat) >= 3 and stat[2].isdigit():
                device["ram_kb"] = int(stat[2]) // 1024
        devices.append(device)
    return devices


def swap_summary(devices: List[Dict[str, object]]) -> str:
    zram = [d for d in devices if d["zram"]]
    disk = [d for d in devices if not d["zram"]]
    parts = []
    if zram:
        used = sum(d["used_kb"] for d in zram)
        ram = sum(d.get("ram_kb", 0) for d in zram)
        parts.append(f"{fmt_bytes(used)} on zram (compressed RAM" + (f", really using {fmt_bytes(ram)} of RAM" if ram else "") + ")")
    if disk:
        parts.append(f"{fmt_bytes(sum(d['used_kb'] for d in disk))} on disk")
    return ", ".join(parts)


def read_meminfo() -> Dict[str, int]:
    values = {}
    for line in (read_text("/proc/meminfo") or "").splitlines():
        parts = line.replace(":", " ").split()
        if len(parts) >= 2 and parts[1].isdigit():
            values[parts[0]] = int(parts[1])
    return values


def distro_name() -> str:
    text = read_text("/etc/os-release") or ""
    match = re.search(r'(?m)^PRETTY_NAME="?([^"\n]+)', text)
    return match.group(1) if match else "unknown"


def explain(groups: List[Group], query: str, style: Style) -> None:
    needle = query.lower()

    def matches(g: Group) -> bool:
        if query.isdigit():
            return any(p.pid == int(query) for p in g.procs)
        names = [g.name, g.prov.name] + [p.comm for p in g.procs] + [p.cmdline[0] for p in g.procs if p.cmdline]
        return any(needle in n.lower() for n in names)

    hits = [g for g in groups if matches(g)]
    if not hits:
        print(f"Nothing running matches {query!r}.")
        return
    for g in hits[:5]:
        print(style.bold(g.name))
        for line in detail_lines(g):
            print("  " + line.replace("**", ""))
        print()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only report of what is running and where it came from.")
    parser.add_argument("--top", type=int, default=40, help="how many programs to list in the terminal (default 40)")
    parser.add_argument("--all", action="store_true", help="list every program in the terminal")
    parser.add_argument("--mine", action="store_true", help="only list things you or side installers added")
    parser.add_argument("--tips", action="store_true", help="show tips for known optional desktop components")
    parser.add_argument("--explain", metavar="PID|NAME", help="show everything known about one program")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds to measure current CPU use (default 2)")
    parser.add_argument("--out", metavar="DIR", help=f"where to save the report (default {state_dir()})")
    parser.add_argument("--no-save", action="store_true", help="print only; don't save report or history")
    parser.add_argument("--netdata", metavar="URL", default=os.environ.get("PROCESS_TRIAGE_NETDATA", "http://localhost:19999"),
                        help="Netdata agent to read history from (default http://localhost:19999)")
    parser.add_argument("--no-netdata", action="store_true", help="don't read history from Netdata")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)

    user, home, _uid = target_user()
    Paths.home = home
    style = Style(sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR"))
    homes = sorted({home} | {pwd.getpwuid(os.getuid()).pw_dir})

    print(style.dim(f"Scanning (measuring CPU for {args.interval:g}s)…"), file=sys.stderr)
    procs = snapshot(args.interval)
    owners = PackageOwners()
    classifier = Classifier(owners, homes)
    # Unit details are needed while grouping (service rows) and later for hints.
    units = {"user": set(), "system": set()}
    for proc in procs:
        launch = parse_cgroup_launch(proc.cgroup)
        if launch.unit and launch.scope in units:
            units[launch.scope].add(launch.unit)
    user_details = unit_details("user", sorted(units["user"]), user)
    system_details = unit_details("system", sorted(units["system"]), user)
    owners.lookup_many(d.get("FragmentPath", "") for d in list(user_details.values()) + list(system_details.values())
                       if d.get("FragmentPath", "").startswith(SYSTEM_PREFIXES))

    def unit_info(scope: str, unit: str) -> Dict[str, str]:
        details = (user_details if scope == "user" else system_details).get(unit, {})
        fragment = details.get("FragmentPath", "") or find_unit_file(scope, unit, home)
        return {"file": fragment, "origin": unit_origin(fragment, owners, home) if fragment else ""}

    groups = build_groups(procs, classifier, unit_info)
    lines = rc_lines(home, user)
    for group in groups:
        group.mentions = find_mentions(group, lines) if group.cls in ("yours", "optional") else []
        finish_group(group, user_details, system_details, owners, home)

    items = startup_inventory(owners, user, home)
    link_startup(items, groups)

    out_dir = args.out or state_dir()
    if not args.no_save:
        apply_history(groups, load_history(out_dir))
    if not args.no_netdata:
        netdata = NetdataHistory(args.netdata)
        if netdata.connect():
            print(style.dim(f"Reading history from Netdata ({len(netdata.charts)} charts)…"), file=sys.stderr)
            apply_netdata(groups, netdata)
            if netdata.errors:
                print(style.dim(f"Netdata: {len(netdata.errors)} queries failed (first: {netdata.errors[0]})"), file=sys.stderr)

    if args.explain:
        explain(groups, args.explain, style)
        return 0

    meminfo = read_meminfo()
    print_terminal(groups, items, meminfo, args, style)
    if args.no_save:
        return 0
    meta = {"host": socket.gethostname(), "time_text": dt.datetime.fromtimestamp(NOW).strftime("%Y-%m-%d %H:%M"),
            "desktop": os.environ.get("XDG_CURRENT_DESKTOP", "unknown"), "distro": distro_name(),
            "package_manager": owners.manager or "none", "as_root": str(os.geteuid() == 0)}
    os.makedirs(out_dir, exist_ok=True)
    stamp = dt.datetime.fromtimestamp(NOW).strftime("%Y%m%d-%H%M%S")
    md_path = os.path.join(out_dir, f"report-{stamp}.md")
    json_path = os.path.join(out_dir, f"scan-{stamp}.json")
    with open(md_path, "w") as handle:
        handle.write(markdown_report(groups, items, meminfo, meta))
    with open(json_path, "w") as handle:
        json.dump(json_report(groups, items, meminfo, meta), handle, indent=1, default=str)
    if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"]))
        for path in (out_dir, md_path, json_path):
            try:
                os.chown(path, uid, gid)
            except OSError:
                pass
    print(f"\nFull report: {style.bold(Paths.show(md_path))}\nData (for history and the MangoDisk port): {Paths.show(json_path)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
