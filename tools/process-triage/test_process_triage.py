"""Tests for the pure parsing and classification logic in process_triage.

Run with: python3 -m unittest discover -s tools/process-triage
"""

import http.server
import json
import os
import tempfile
import threading
import unittest
import urllib.parse

import process_triage as pt


def make_proc(pid, ppid, comm, cgroup="", cmdline=None, exe=None):
    return pt.Proc(
        pid=pid, ppid=ppid, uid=1000, comm=comm, cmdline=cmdline or [comm], exe=exe, exe_deleted=False, cwd=None,
        cgroup=cgroup, start_epoch=0.0, cpu_ticks=0, rss_kb=0, pss_kb=0, swap_kb=0,
    )


class CgroupParsing(unittest.TestCase):
    def test_prefers_unified_hierarchy(self):
        text = "1:name=systemd:/old\n0::/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service\n"
        self.assertEqual(pt.parse_cgroup(text), "/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service")

    def test_falls_back_to_v1_when_unified_is_root(self):
        self.assertEqual(pt.parse_cgroup("0::/\n1:name=systemd:/system.slice/cron.service\n"), "/system.slice/cron.service")
        self.assertEqual(pt.parse_cgroup("1:name=systemd:/system.slice/cron.service\n0::/\n"), "/system.slice/cron.service")


USER = "/user.slice/user-1000.slice/user@1000.service"


class LaunchParsing(unittest.TestCase):
    def test_kde_autostart_unit_is_unescaped(self):
        launch = pt.parse_cgroup_launch(USER + "/app.slice/app-org.kde.kdeconnect.daemon\\x2dhelper@autostart.service")
        self.assertEqual(launch.kind, "autostart")
        self.assertEqual(launch.desktop_name, "org.kde.kdeconnect.daemon-helper")

    def test_app_scope_names_the_launcher(self):
        launch = pt.parse_cgroup_launch(USER + "/app.slice/app-org.kde.konsole-12345.scope")
        self.assertEqual(launch.kind, "app-launched")
        self.assertEqual(launch.desktop_name, "org.kde.konsole")

    def test_user_service(self):
        launch = pt.parse_cgroup_launch(USER + "/app.slice/syncthing.service")
        self.assertEqual((launch.kind, launch.unit, launch.scope), ("user-service", "syncthing.service", "user"))

    def test_session_and_background_slices(self):
        self.assertEqual(pt.parse_cgroup_launch(USER + "/session.slice/plasma-plasmashell.service").kind, "session")
        self.assertEqual(pt.parse_cgroup_launch(USER + "/background.slice/plasma-kglobalaccel.service").kind, "user-service")

    def test_dbus_activation(self):
        launch = pt.parse_cgroup_launch(USER + "/app.slice/dbus-:1.2-org.kde.KSplash@0.service")
        self.assertEqual(launch.kind, "on-demand")

    def test_system_service_and_cron(self):
        self.assertEqual(pt.parse_cgroup_launch("/system.slice/ollama.service").kind, "system-service")
        self.assertEqual(pt.parse_cgroup_launch("/system.slice/cronie.service").kind, "cron")

    def test_login_session_scope(self):
        self.assertEqual(pt.parse_cgroup_launch("/user.slice/user-1000.slice/session-2.scope").kind, "login-session")

    def test_terminal_refinement(self):
        table = {
            1: make_proc(1, 0, "systemd"),
            10: make_proc(10, 1, "konsole"),
            11: make_proc(11, 10, "zsh"),
            12: make_proc(12, 11, "node", cgroup=USER + "/app.slice/app-org.kde.konsole-99.scope"),
        }
        launch = pt.refine_launch(pt.parse_cgroup_launch(table[12].cgroup), table[12], table, {})
        self.assertEqual(launch.kind, "terminal")
        self.assertIn("konsole", launch.detail)

    def test_spawned_by_another_program(self):
        table = {
            1: make_proc(1, 0, "systemd"),
            20: make_proc(20, 1, "code"),
            21: make_proc(21, 20, "node", cgroup=USER + "/app.slice/app-code-55.scope"),
        }
        launch = pt.refine_launch(pt.parse_cgroup_launch(table[21].cgroup), table[21], table, {20: "a", 21: "b"})
        self.assertEqual(launch.kind, "child")
        self.assertIn("editor/IDE", launch.detail)


class ScriptResolution(unittest.TestCase):
    def test_python_module(self):
        self.assertEqual(pt.find_script("python", ["-u", "-m", "http.server", "8000"], "/tmp"), ("module", "http.server"))

    def test_python_inline(self):
        self.assertEqual(pt.find_script("python", ["-c", "print(1)"], None), ("inline", None))

    def test_node_skips_option_arguments(self):
        self.assertEqual(pt.find_script("node", ["-r", "dotenv/config", "--inspect=9229", "server.js"], "/srv/app"),
                         ("path", "/srv/app/server.js"))

    def test_bun_run(self):
        self.assertEqual(pt.find_script("node", ["run", "/a/b.ts"], None), ("path", "/a/b.ts"))

    def test_java_jar(self):
        self.assertEqual(pt.find_script("java", ["-Xmx2g", "-jar", "app.jar"], "/opt/x"), ("path", "/opt/x/app.jar"))

    def test_shell_dash_c_with_path(self):
        self.assertEqual(pt.find_script("shell", ["-c", "exec /home/u/bin/sync.sh --loop"], None), ("path", "/home/u/bin/sync.sh"))

    def test_interpreter_family(self):
        self.assertEqual(pt.interpreter_family("python3.12"), "python")
        self.assertEqual(pt.interpreter_family("nodejs"), "node")
        self.assertIsNone(pt.interpreter_family("firefox"))


class Redaction(unittest.TestCase):
    def test_flag_values(self):
        self.assertEqual(pt.redact_argv(["app", "--token", "abc", "--password=hunter2", "--port", "80"]),
                         ["app", "--token", "***", "--password=***", "--port", "80"])

    def test_url_credentials_and_long_tokens(self):
        out = pt.redact_text("https://me:ghp_x@github.com/a/b " + "A" * 45)
        self.assertEqual(out, "https://***@github.com/a/b ***")

    def test_paths_are_kept(self):
        self.assertEqual(pt.redact_argv(["/home/u/.config/auth/helper"]), ["/home/u/.config/auth/helper"])


class DesktopEntries(unittest.TestCase):
    def test_hidden_and_desktop_filters(self):
        os.environ["XDG_CURRENT_DESKTOP"] = "KDE"
        self.assertFalse(pt.desktop_applies({"Hidden": "true"}))
        self.assertFalse(pt.desktop_applies({"OnlyShowIn": "GNOME;"}))
        self.assertFalse(pt.desktop_applies({"NotShowIn": "KDE;"}))
        self.assertTrue(pt.desktop_applies({"OnlyShowIn": "KDE;XFCE;"}))


class FileBasedClassification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = self.tmp.name
        self.owners = pt.PackageOwners()
        self.owners.manager = None
        self.classifier = pt.Classifier(self.owners, [self.home])

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text="", mode=0o644):
        path = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write(text)
        os.chmod(path, mode)
        return path

    def test_pip_user_console_script(self):
        site = ".local/lib/python3.12/site-packages"
        script = self.write(".local/bin/yt-sync", "#!/usr/bin/python3\n", 0o755)
        self.write(f"{site}/yt_sync-2.1.0.dist-info/METADATA", "Name: yt-sync\nVersion: 2.1.0\n\n")
        self.write(f"{site}/yt_sync-2.1.0.dist-info/INSTALLER", "pip\n")
        self.write(f"{site}/yt_sync-2.1.0.dist-info/RECORD", "yt_sync/__init__.py,,\n../../../bin/yt-sync,,\n")
        self.write(f"{site}/yt_sync-2.1.0.dist-info/direct_url.json",
                   json.dumps({"url": "https://github.com/me/yt-sync.git", "vcs_info": {"vcs": "git", "commit_id": "0123456789abcdef"}}))
        target = pt.Target(family="python", path=script, interpreter="/usr/bin/python3.12")
        prov = self.classifier.classify(make_proc(5, 1, "yt-sync"), target)
        self.assertEqual((prov.kind, prov.name, prov.version), ("pip-user", "yt-sync", "2.1.0"))
        self.assertEqual(prov.source, "https://github.com/me/yt-sync.git @ 0123456789")
        module = self.classifier.classify(make_proc(6, 1, "python3"), pt.Target(family="python", path="/usr/bin/python3.12", module="yt_sync"))
        self.assertEqual(module.key, prov.key)

    def test_git_clone_uses_reflog_clone_date(self):
        root = os.path.join(self.home, "src/tool")
        self.write("src/tool/run.py", "print(1)\n")
        self.write("src/tool/.git/config", '[remote "origin"]\n\turl = https://u:secret@github.com/x/tool.git\n')
        self.write("src/tool/.git/logs/HEAD",
                   "0000 1111 Me <m@e> 1700000000 +0000\tclone: from https://github.com/x/tool.git\n"
                   "1111 2222 Me <m@e> 1750000000 +0000\tpull: Fast-forward\n")
        prov = self.classifier.classify(make_proc(7, 1, "python3"), pt.Target(family="python", path=os.path.join(root, "run.py")))
        self.assertEqual(prov.kind, "git-clone")
        self.assertEqual(prov.installed_at, 1700000000)
        self.assertEqual(prov.source, "https://***@github.com/x/tool.git")

    def test_dotfiles_repo_in_home_is_not_an_install(self):
        self.write(".git/config", "")
        script = self.write("bin/thing.sh", "#!/bin/sh\n", 0o755)
        prov = self.classifier.classify(make_proc(8, 1, "thing.sh"), pt.Target(family="shell", path=script))
        self.assertEqual(prov.kind, "manual")

    def test_nvm_global_package(self):
        pkg = ".nvm/versions/node/v20.11.0/lib/node_modules/@scope/cli"
        self.write(f"{pkg}/package.json", json.dumps({"name": "@scope/cli", "version": "3.0.1"}))
        entry = self.write(f"{pkg}/bin/cli.js", "")
        prov = self.classifier.classify(make_proc(9, 1, "node"), pt.Target(family="node", path=entry))
        self.assertEqual((prov.kind, prov.name, prov.version), ("npm-global", "@scope/cli", "3.0.1"))
        self.assertIn("nvm use v20.11.0", prov.remove_hint)

    def test_project_dependency_maps_to_project(self):
        entry = self.write("work/site/node_modules/vite/bin/vite.js", "")
        self.write("work/site/node_modules/vite/package.json", json.dumps({"name": "vite", "version": "5.0.0"}))
        prov = self.classifier.classify(make_proc(10, 1, "node"), pt.Target(family="node", path=entry))
        self.assertEqual((prov.kind, prov.name), ("node-project", "site"))

    def test_homebrew_receipt(self):
        binary = self.write(".linuxbrew/Cellar/btop/1.3.2/bin/btop", "", 0o755)
        self.write(".linuxbrew/Cellar/btop/1.3.2/INSTALL_RECEIPT.json", json.dumps({"time": 1712345678, "installed_on_request": False}))
        prov = self.classifier.classify(make_proc(11, 1, "btop"), pt.Target(family=None, path=binary))
        self.assertEqual((prov.kind, prov.name, prov.installed_at), ("homebrew", "btop", 1712345678))
        self.assertTrue(any("dependency" in n for n in prov.notes))

    def test_cgroup_identifies_flatpak_snap_and_containers(self):
        flatpak = make_proc(12, 1, "firefox", cgroup=USER + "/app.slice/app-flatpak-org.mozilla.firefox-4242.scope")
        self.assertEqual(self.classifier.from_cgroup(flatpak).name, "org.mozilla.firefox")
        snap = make_proc(13, 1, "spotify", cgroup=USER + "/app.slice/snap.spotify.spotify-1a2b.scope")
        self.assertEqual(self.classifier.from_cgroup(snap).name, "spotify")
        docker = make_proc(14, 1, "postgres", cgroup="/system.slice/docker-0123456789abcdef0123.scope")
        self.assertEqual(self.classifier.from_cgroup(docker).kind, "container")

    def test_safety_classes(self):
        side = pt.Provenance(kind="pip-user", name="x")
        distro = pt.Provenance(kind="system-package", name="plasma-workspace")
        self.assertEqual(pt.safety_class("plasmashell", "plasmashell", distro, {"session"}), "core")
        self.assertEqual(pt.safety_class("x", "x", side, {"autostart"}), "yours")
        baloo = pt.Provenance(kind="system-package", name="baloo-kf6")
        self.assertEqual(pt.safety_class("baloo_file", "baloo_file", baloo, {"user-service"}), "optional")
        # Truncated comm names still match core packages and full binary names.
        self.assertEqual(pt.safety_class("plasma-workspace", {"startplasma-way", "startplasma-wayland"}, distro, {"login-session"}), "core")
        self.assertEqual(pt.safety_class("bash", "bash", pt.Provenance(kind="system-package", name="bash", manual=True), {"terminal"}), "system")


class RealScanRegressions(unittest.TestCase):
    """Cases seen on a real KDE desktop scan."""

    def test_versioned_binary_is_named_after_its_folder(self):
        pt.Paths.home = "/home/u"
        self.assertEqual(pt.program_name("/home/u/.local/share/claude/versions/2.1.328"), ("claude", "2.1.328"))
        self.assertEqual(pt.program_name("/home/u/bin/prime-agent"), ("prime-agent", None))

    def test_package_manager_runners(self):
        self.assertEqual(pt.runner_name("/home/linuxbrew/.linuxbrew/Cellar/node/24.1.0/lib/node_modules/npm/bin/npm-cli.js"), "npm")
        self.assertEqual(pt.runner_name("/home/linuxbrew/.linuxbrew/Cellar/pnpm/10.2.0/libexec/bin/pnpm.cjs"), "pnpm")
        self.assertIsNone(pt.runner_name("/home/u/src/app/server.js"))

    def test_unrecognized_cgroup_is_shown(self):
        self.assertIn("/prime.slice/agent.service", pt.parse_cgroup_launch("/prime.slice/agent.service").detail)
        self.assertEqual(pt.parse_cgroup_launch(USER + "/app.slice/tmux-spawn-1234.scope").kind, "terminal")

    def test_library_helpers_fold_into_the_app(self):
        app = make_proc(30, 1, "mangodisk", exe="/usr/bin/mangodisk")
        helper = make_proc(31, 30, "WebKitWebProces", exe="/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebProcess")
        provs = {30: pt.Provenance(kind="system-package", name="mango-disk"),
                 31: pt.Provenance(kind="system-package", name="libwebkit2gtk-4.1-0")}
        pt.fold_children([app, helper], {30: app, 31: helper}, provs)
        self.assertEqual(provs[31].name, "mango-disk")

    def test_dev_server_without_script_maps_to_project(self):
        with tempfile.TemporaryDirectory() as home:
            pt.Paths.home = home
            project = os.path.join(home, "koda")
            os.makedirs(os.path.join(project, ".next"))
            with open(os.path.join(project, "package.json"), "w") as handle:
                handle.write(json.dumps({"name": "koda-ui"}))
            proc = make_proc(40, 1, "next-server", cmdline=["next-server (v15.1.0)"], exe="/home/linuxbrew/.linuxbrew/Cellar/node/24.1.0/bin/node")
            proc.cwd = os.path.join(project, ".next")
            target = pt.resolve_target(proc)
            self.assertEqual(target.project, project)
            owners = pt.PackageOwners()
            owners.manager = None
            prov = pt.Classifier(owners, [home]).classify(proc, target)
            self.assertEqual((prov.kind, prov.name), ("project", "koda"))


class SecondScanRegressions(unittest.TestCase):
    def test_lxc_container(self):
        owners = pt.PackageOwners()
        owners.manager = None
        proc = make_proc(50, 1, "python3", cgroup="/lxc.payload.user-982_taos-agent-ops/system.slice/hermes-gateway.service")
        prov = pt.Classifier(owners, ["/home/u"]).from_cgroup(proc)
        self.assertEqual((prov.kind, prov.name), ("container", "taos-agent-ops (LXC)"))
        self.assertIn("--project user-982", prov.remove_hint)
        self.assertEqual(pt.parse_cgroup_launch(proc.cgroup).kind, "container")

    def test_terminal_spawn_scope(self):
        launch = pt.parse_cgroup_launch(USER + "/app.slice/ptyxis-spawn-94a0be42-1832-42e5-abd5-261a63ac5363.scope")
        self.assertEqual(launch.kind, "terminal")

    def test_npm_package_serving_from_dist(self):
        with tempfile.TemporaryDirectory() as root:
            pkg = os.path.join(root, ".npm-global/lib/node_modules/omniroute")
            os.makedirs(os.path.join(pkg, "dist"))
            os.makedirs(os.path.join(root, ".npm-global/bin"))
            for folder, name in ((pkg, "omniroute"), (os.path.join(pkg, "dist"), "omniroute-dist")):
                with open(os.path.join(folder, "package.json"), "w") as handle:
                    handle.write(json.dumps({"name": name, "version": "1.0.0"}))
            pt.Paths.home = root
            proc = make_proc(51, 1, "node-MainThread", cmdline=["node-MainThread"], exe="/usr/bin/node")
            proc.cwd = os.path.join(pkg, "dist")
            target = pt.resolve_target(proc)
            self.assertEqual(target.project, pkg)
            owners = pt.PackageOwners()
            owners.manager = None
            prov = pt.Classifier(owners, [root]).classify(proc, target)
            self.assertEqual((prov.kind, prov.name), ("npm-global", "omniroute"))

    def test_apt_history_marks_what_you_asked_for(self):
        with tempfile.TemporaryDirectory() as root:
            log = os.path.join(root, "history.log")
            with open(log, "w") as handle:
                handle.write(
                    "Start-Date: 2026-09-18  10:00:00\nCommandline: apt install ptyxis ./google-chrome-stable_131_amd64.deb\n"
                    "Install: ptyxis:amd64 (47.0), libvte:amd64 (0.78, automatic)\nEnd-Date: 2026-09-18  10:00:05\n\n"
                    "Start-Date: 2026-09-20  09:00:00\nRequested-By: me (1000)\n"
                    "Install: netbird-ui:amd64 (0.30), libayatana:amd64 (1.0, automatic)\nEnd-Date: 2026-09-20  09:00:03\n"
                )
            owners = pt.PackageOwners()
            owners.manager = "dpkg"
            owners.apt_history_glob = log
            owners.manual = set()
            self.assertTrue(owners.is_manual("ptyxis"))
            self.assertTrue(owners.is_manual("google-chrome-stable"))
            self.assertTrue(owners.is_manual("netbird-ui"))
            self.assertFalse(owners.is_manual("libayatana"))  # pulled in automatically: a dependency
            self.assertIsNone(owners.is_manual("dolphin"))
            self.assertIsNotNone(owners.requested_at("ptyxis"))

    def test_bulk_transactions_are_not_hand_picked(self):
        with tempfile.TemporaryDirectory() as root:
            log = os.path.join(root, "history.log")
            many = " ".join(f"pkg{i}" for i in range(20))
            with open(log, "w") as handle:
                handle.write(f"Start-Date: 2026-09-18  10:00:00\nCommandline: apt install dolphin {many}\nEnd-Date: x\n\n"
                             "Start-Date: 2026-09-19  10:00:00\nCommandline: apt install pkg3\nEnd-Date: x\n")
            owners = pt.PackageOwners()
            owners.manager, owners.apt_history_glob, owners.manual = "dpkg", log, set()
            self.assertIsNone(owners.is_manual("dolphin"))
            self.assertIsNotNone(owners.requested_at("dolphin"))
            self.assertTrue(owners.is_manual("pkg3"))

    def test_gjs_script(self):
        self.assertEqual(pt.interpreter_family("gjs"), "gjs")
        self.assertEqual(pt.find_script("gjs", ["-I", "/opt/x/lib", "/opt/Surfshark/surfsharkd.js"], None),
                         ("path", "/opt/Surfshark/surfsharkd.js"))


class FullRunRegressions(unittest.TestCase):
    """Cases from running --all, sudo, --explain and the full report on a real desktop."""

    def test_other_users_argv0_resolves_through_symlinks(self):
        with tempfile.TemporaryDirectory() as root:
            real = os.path.join(root, "usr-bin-cloudflared")
            open(real, "w").close()
            link = os.path.join(root, "local-cloudflared")
            os.symlink(real, link)
            proc = make_proc(60, 1, "cloudflared", cmdline=[link, "tunnel", "run"], exe=None)
            self.assertEqual(pt.resolve_target(proc).path, real)

    def test_process_title_with_arguments(self):
        proc = make_proc(61, 1, "sh", cmdline=["sh --inet"], exe=None)
        self.assertTrue(pt.resolve_target(proc).path.endswith("/sh") or pt.resolve_target(proc).path.endswith("dash"))

    def test_template_slice_unit(self):
        self.assertEqual(pt.parse_cgroup_launch("/system.slice/system-cups.slice/cups.service").unit, "cups.service")
        self.assertEqual(pt.parse_cgroup_launch("/system.slice/system-postgresql.slice/postgresql@17-main.service").unit,
                         "postgresql@17-main.service")

    def test_cron_daemon_is_a_service(self):
        cron = make_proc(62, 1, "cron", cgroup="/system.slice/cron.service")
        launch = pt.refine_launch(pt.parse_cgroup_launch(cron.cgroup), cron, {62: cron}, {})
        self.assertEqual(launch.kind, "system-service")

    def test_control_characters_are_flattened(self):
        self.assertNotIn("\n", " ".join(pt.redact_argv(["python", "-c", "import x\n# comment\nrun()"])))

    def test_service_cgroup_folds_plugins_but_not_terminal_children(self):
        cg = "/system.slice/netdata.service"
        main = make_proc(70, 1, "netdata", cgroup=cg, exe="/usr/sbin/netdata")
        plugin = make_proc(71, 70, "sd-jrnl.plugin", cgroup=cg, exe="/usr/libexec/netdata/plugins.d/systemd-journal.plugin")
        plugin.start_epoch = 5
        term_cg = USER + "/app.slice/app-org.kde.konsole@abc.service"
        konsole = make_proc(80, 1, "konsole", cgroup=term_cg, exe="/usr/bin/konsole")
        vim = make_proc(81, 80, "vim", cgroup=term_cg, exe="/usr/bin/vim")
        vim.start_epoch = 5
        provs = {70: pt.Provenance(kind="system-package", name="netdata"),
                 71: pt.Provenance(kind="system-package", name="netdata-plugin-systemd-journal"),
                 80: pt.Provenance(kind="system-package", name="konsole"),
                 81: pt.Provenance(kind="system-package", name="vim")}
        targets = {pid: pt.Target(family=None, path=None) for pid in provs}
        folded = set()
        pt.fold_by_cgroup([main, plugin, konsole, vim], provs, targets, folded)
        self.assertEqual(provs[71].name, "netdata")
        self.assertEqual(provs[81].name, "vim")
        self.assertEqual(folded, {71})
        # The folded plugin's name must not make netdata look like part of the system.
        self.assertEqual(pt.safety_class("netdata", {"netdata"}, provs[70], {"system-service"}), "system")

    def test_app_scope_folds_only_library_helpers(self):
        cg = USER + "/app.slice/app-org.kde.dolphin-42.scope"
        dolphin = make_proc(90, 1, "dolphin", cgroup=cg, exe="/usr/bin/dolphin")
        worker = make_proc(91, 90, "kioworker", cgroup=cg, exe="/usr/lib/x86_64-linux-gnu/libexec/kf6/kioworker")
        opened = make_proc(92, 90, "okular", cgroup=cg, exe="/usr/bin/okular")
        worker.start_epoch = opened.start_epoch = 5
        provs = {90: pt.Provenance(kind="system-package", name="dolphin"), 91: pt.Provenance(kind="system-package", name="kio6"),
                 92: pt.Provenance(kind="system-package", name="okular")}
        pt.fold_by_cgroup([dolphin, worker, opened], provs, {pid: pt.Target(family=None, path=None) for pid in provs}, set())
        self.assertEqual((provs[91].name, provs[92].name), ("dolphin", "okular"))

    def test_service_you_added_gets_its_own_row(self):
        ssh = make_proc(100, 1, "ssh", cgroup=USER + "/app.slice/mitmproxy-capture-ui-tunnel.service", exe="/usr/bin/ssh")
        tunnel = make_proc(101, 1, "cloudflared", cgroup="/system.slice/cloudflared.service", exe="/usr/bin/cloudflared")
        provs = {100: pt.Provenance(kind="system-package", name="openssh-client"),
                 101: pt.Provenance(kind="system-package", name="cloudflared")}
        launches = {p.pid: pt.parse_cgroup_launch(p.cgroup) for p in (ssh, tunnel)}
        info = lambda scope, unit: {"file": f"/home/u/.config/systemd/user/{unit}", "origin": "added in your home folder"}
        pt.name_service_rows([ssh, tunnel], provs, launches, info)
        self.assertEqual((provs[100].kind, provs[100].name), ("service", "mitmproxy-capture-ui-tunnel"))
        self.assertEqual(provs[101].name, "cloudflared")

    def test_static_units_are_masked_and_package_autostart_is_overridden(self):
        prov = pt.Provenance(kind="system-package", name="evolution-data-server")
        group = pt.Group(key="k", name="eds", prov=prov, procs=[make_proc(110, 1, "evolution-sourc")], targets=[],
                         launches=[pt.Launch("user-service", "x", unit="evolution-source-registry.service", scope="user"),
                                   pt.Launch("autostart", "y", unit="app-kup@autostart.service", scope="user", desktop_name="kup")])
        details = {"evolution-source-registry.service": {"UnitFileState": "static"},
                   "app-kup@autostart.service": {"SourcePath": "/etc/xdg/autostart/kup-daemon.desktop"}}
        owners = pt.PackageOwners()
        owners.manager = None
        pt.finish_group(group, details, {}, owners, "/home/u")
        self.assertIn("mask --now evolution-source-registry.service", group.disable_hint)
        self.assertIn("System Settings > Autostart", group.disable_hint)
        self.assertNotIn("remove `/etc/xdg", group.disable_hint)

    def test_install_script_bursts_are_not_hand_picked(self):
        with tempfile.TemporaryDirectory() as root:
            log = os.path.join(root, "history.log")
            blocks = [f"Start-Date: 2026-09-18  10:{minute:02d}:00\nCommandline: apt-get -y install {name}\n"
                      f"Install: {name}:amd64 (1.0), libdep{minute}:amd64 (1.0, automatic)\nEnd-Date: x\n"
                      for minute, name in zip(range(0, 14, 2), ["postfix", "dovecot-core", "opendkim", "proftpd-core", "snmpd", "apache2", "nginx"])]
            with open(log, "w") as handle:
                handle.write("\n".join(blocks))
            owners = pt.PackageOwners()
            owners.manager, owners.apt_history_glob, owners.manual = "dpkg", log, set()
            self.assertIsNone(owners.is_manual("postfix"))
            self.assertIn("burst", owners.came_with_note("postfix"))
            self.assertFalse(owners.is_manual("libdep0"))


class SwapTests(unittest.TestCase):
    def test_zram_and_disk_swap(self):
        text = ("Filename Type Size Used Priority\n/dev/zram0 partition 16000000 14000000 100\n"
                "/swap.img file 8000000 1000 -2\n")
        summary = pt.swap_summary(pt.swap_devices(text))
        self.assertIn("on zram (compressed RAM", summary)
        self.assertIn("on disk", summary)


class WordingTests(unittest.TestCase):
    def test_verdicts_state_facts(self):
        g = pt.Group(key="k", name="surfshark", prov=pt.Provenance(kind="system-package", name="surfshark"),
                     procs=[make_proc(30, 0, "surfshark")], targets=[], launches=[])
        g.cls, g.mem_kb, g.swap_kb, g.oldest_start = "yours", 70 * 1024, 88 * 1024, pt.NOW - 9 * 86400
        pt.set_verdict(g)
        self.assertEqual(g.verdict, "idle, holding 158 MB")
        with open(pt.__file__) as handle:
            source = handle.read()
        for phrase in ("IDLE HOG", "good candidate", "candidate if you don't", "biggest idle hog"):
            self.assertNotIn(phrase, source)

    def test_scan_history_shows_memory_change(self):
        g = pt.Group(key="k", name="x", prov=pt.Provenance(kind="manual", name="x"), procs=[], targets=[], launches=[])
        g.mem_kb, g.swap_kb = 900 * 1024, 300 * 1024
        pt.apply_history([g], [{"time": pt.NOW - 3600, "programs": {"k": {"memory_kb": 400 * 1024, "swap_kb": 0}}}])
        self.assertIn("400 MB at the first of these scans", g.seen)
        self.assertIn("1.2 GB now", g.seen)

    def test_zram_ratio(self):
        devices = [{"name": "/dev/zram0", "type": "partition", "used_kb": 16 * 1024 ** 2, "zram": True, "ram_kb": 4 * 1024 ** 2}]
        self.assertIn("about 4.0 to 1", pt.swap_summary(devices))


class FourthRunRegressions(unittest.TestCase):
    def test_apt_history_uses_install_flags_and_first_date(self):
        with tempfile.TemporaryDirectory() as root:
            log = os.path.join(root, "history.log")
            with open(log, "w") as handle:
                handle.write(
                    "Start-Date: 2025-11-17  09:00:00\nCommandline: packagekit role='install-files'\nRequested-By: me (1000)\n"
                    "Install: google-chrome-stable:amd64 (131), libnss3:amd64 (3.1, automatic)\nEnd-Date: x\n\n"
                    "Start-Date: 2026-08-23  09:00:00\nCommandline: apt install google-chrome-stable\n"
                    "Upgrade: google-chrome-stable:amd64 (131, 140)\nEnd-Date: x\n\n"
                    "Start-Date: 2026-11-17  12:00:00\nCommandline: apt-get install -y ./MangoDisk_2.0.0_amd64.deb\n"
                    "Install: mango-disk:amd64 (2.0.0), libwebkit:amd64 (1.0, automatic)\nEnd-Date: x\n"
                )
            owners = pt.PackageOwners()
            owners.manager, owners.apt_history_glob, owners.manual = "dpkg", log, set()
            self.assertTrue(owners.is_manual("mango-disk"))       # .deb file name differs from the package
            self.assertTrue(owners.is_manual("google-chrome-stable"))
            self.assertEqual(pt.fmt_date(owners.requested_at("google-chrome-stable")), "2025-11-17")
            self.assertIn("Discover/PackageKit", owners.came_with_note("google-chrome-stable"))
            self.assertFalse(owners.is_manual("libnss3"))

    def test_plasma_widget_commands(self):
        cg = USER + "/session.slice/plasma-plasmashell.service"
        shell = make_proc(120, 1, "plasmashell", cgroup=cg)
        probe = make_proc(121, 120, "intel_gpu_top", cgroup=cg)
        table = {120: shell, 121: probe}
        self.assertEqual(pt.refine_launch(pt.parse_cgroup_launch(cg), probe, table, {}).kind, "widget")
        self.assertEqual(pt.refine_launch(pt.parse_cgroup_launch(cg), shell, table, {}).kind, "session")
        # A distro tool run by a widget is not part of the core desktop.
        self.assertNotEqual(pt.safety_class("rust-coreutils", {"sleep"}, pt.Provenance(kind="system-package", name="rust-coreutils"),
                                            {"widget", "terminal"}), "core")

    def test_container_hints_use_the_engine(self):
        owners = pt.PackageOwners()
        owners.manager = None
        classifier = pt.Classifier(owners, ["/home/u"])
        classifier.containers.loaded = True
        classifier.containers.info["15615e12e214"] = {"engine": "docker", "name": "datahub-opensearch-1", "image": "opensearch",
                                                      "project": "datahub", "service": "opensearch", "created": "2026-11-15 10:00:00 -0500 EST"}
        proc = make_proc(130, 1, "java", cgroup="/system.slice/docker-15615e12e214959e2592dce404c0708787aa9ee1b7cbd4f3c0e0cdf803b22b58.scope")
        group = pt.Group(key="k", name="x", prov=classifier.from_cgroup(proc), procs=[proc], targets=[],
                         launches=[pt.parse_cgroup_launch(proc.cgroup)])
        pt.finish_group(group, {}, {}, owners, "/home/u")
        self.assertIn("docker compose -p datahub stop opensearch", group.stop_hint)
        self.assertNotIn("kill", group.stop_hint.split("(")[0])
        self.assertIn("restart:", group.disable_hint)

    def test_startup_hints_are_not_repeated(self):
        prov = pt.Provenance(kind="system-package", name="containerd.io")
        group = pt.Group(key="k", name="containerd.io", prov=prov, procs=[make_proc(140, 1, "containerd")], targets=[],
                         launches=[pt.Launch("system-service", "x", unit="containerd.service", scope="system")])
        group.disable_hint = "`sudo systemctl disable --now containerd.service`"
        item = pt.StartupItem(kind="system-unit", name="containerd.service", location="/usr/lib/systemd/system/containerd.service",
                              off_hint="`sudo systemctl disable --now containerd.service` (or mask)")
        pt.link_startup([item], [group])
        self.assertEqual(group.disable_hint.count("containerd.service"), 1)

    def test_unit_notes(self):
        self.assertIn("cloud", pt.unit_note("cloud-init-local.service"))
        self.assertEqual(pt.unit_note("NetworkManager.service"), "")


class FakeNetdata(http.server.BaseHTTPRequestHandler):
    charts = ["system.cpu", "systemd_netdata.cpu", "systemd_netdata.io", "cgroup_datahub-opensearch-1.cpu",
              "cgroup_datahub-opensearch-1.net_eth0", "cgroup_datahub-opensearch-1.net_drops_eth0", "app.omniroute_cpu_utilization",
              "cgroup_datahub-opensearch-1.mem_usage", "cgroup_helicone-ai-gateway.cpu", "cgroup_helicone-ai-gateway.net_eth0",
              "app.cloudflared_cpu_utilization", "app.ydotoold_cpu_utilization", "app.mango_cpu_utilization",
              "cgroup_user.slice_app.slice_omniroute.service.cpu", "system.ram", "mem.swap"]
    values = {"systemd_netdata.cpu": [20.0, 10.0], "systemd_netdata.io": [100.0, 28.0],
              "cgroup_datahub-opensearch-1.cpu": [1.0, 0.5], "cgroup_datahub-opensearch-1.net_eth0": [8.0, 8.0],
              "cgroup_datahub-opensearch-1.net_drops_eth0": [999.0], "app.omniroute_cpu_utilization": [2.0, 0.0],
              "cgroup_helicone-ai-gateway.cpu": [0.05], "cgroup_helicone-ai-gateway.net_eth0": [100.0],
              "app.cloudflared_cpu_utilization": [0.2], "app.ydotoold_cpu_utilization": [0.0],
              "app.mango_cpu_utilization": [1.0], "cgroup_user.slice_app.slice_omniroute.service.cpu": [3.0]}
    # oldest first; served newest first like Netdata does
    daily = {"cgroup_datahub-opensearch-1.mem_usage": [0.0, 600.0, 700.0, 800.0, 900.0, 1000.0, 1100.0],
             "system.ram": [10000.0, 12000.0, 14000.0], "mem.swap": [8000.0, 12000.0, 17000.0]}
    missing = {"app.omniroute_cpu_utilization"}

    def log_message(self, *args):
        pass

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        query = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/api/v1/charts":
            body = {"charts": {c: {} for c in self.charts}}
        elif url.path == "/api/v1/chart":
            body = {"first_entry": 1700000000, "last_entry": 1800000000}
        elif url.path == "/api/v1/data" and query["chart"] in self.missing:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Chart is not found: " + query["chart"].encode())
            return
        elif url.path == "/api/v1/data" and query["chart"] in self.daily:
            values = self.daily[query["chart"]]
            body = {"labels": ["time", "used"], "data": [[1800000000 + i * 86400, v] for i, v in reversed(list(enumerate(values)))]}
        elif url.path == "/api/v1/data":
            points = int(query["points"])
            row = self.values.get(query["chart"], [0.0])
            body = {"labels": ["time"] + ["d"] * len(row), "data": [[1800000000 - i] + row for i in range(points)]}
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


class NetdataHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeNetdata)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.netdata = pt.NetdataHistory(f"http://127.0.0.1:{cls.server.server_port}")
        assert cls.netdata.connect()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def group(self, prov, launches, procs):
        return pt.Group(key="k", name=prov.name, prov=prov, procs=procs, targets=[], launches=launches)

    def test_service_history(self):
        g = self.group(pt.Provenance(kind="system-package", name="netdata"),
                       [pt.Launch("system-service", "x", unit="netdata.service", scope="system")], [make_proc(1, 0, "netdata")])
        h = self.netdata.history_for(g)
        self.assertEqual(h["cpu_avg_7d"], 30.0)
        self.assertAlmostEqual(h["disk_bytes_7d"], 128 * 1024 * 7 * 86400, delta=1)
        self.assertIn("netdata.service", pt.history_text(h))

    def test_container_network_ignores_drop_counters(self):
        g = self.group(pt.Provenance(kind="container", name="datahub-opensearch-1"), [], [make_proc(2, 0, "java")])
        h = self.netdata.history_for(g)
        self.assertEqual(h["cpu_avg_30d"], 1.5)
        self.assertAlmostEqual(h["net_bytes_7d"], 16 * 1000 / 8 * 7 * 86400, delta=1)

    def test_program_groups_skip_generic_names(self):
        mango = self.group(pt.Provenance(kind="npm-global", name="mango"), [], [make_proc(3, 0, "node-MainThread")])
        self.assertEqual(self.netdata.history_for(mango)["cpu_avg_7d"], 1.0)
        node = self.group(pt.Provenance(kind="npm-global", name="node"), [], [make_proc(4, 0, "node")])
        self.assertEqual(self.netdata.history_for(node), {})

    def test_failed_chart_gives_netdata_reason_and_user_service_chart_is_used(self):
        omni = self.group(pt.Provenance(kind="npm-global", name="omniroute"), [], [make_proc(3, 0, "node-MainThread")])
        h = self.netdata.history_for(omni)
        self.assertIn("HTTP 404: Chart is not found", pt.history_text(h))
        unit = pt.Launch("user-service", "x", unit="omniroute.service", scope="user")
        h = self.netdata.history_for(self.group(pt.Provenance(kind="npm-global", name="omniroute"), [unit],
                                                [make_proc(3, 0, "node-MainThread")]))
        self.assertEqual(h["cpu_avg_7d"], 3.0)
        self.assertIn("user service `omniroute.service`", pt.history_text(h))

    def test_children_do_not_lend_their_chart(self):
        parent = make_proc(10, 1, "python")
        child = make_proc(11, 10, "ydotoold")
        g = self.group(pt.Provenance(kind="venv", name="main.py"), [], [parent, child])
        self.assertNotIn("cpu_avg_7d", self.netdata.history_for(g))

    def test_memory_trend_and_system_memory(self):
        g = self.group(pt.Provenance(kind="container", name="datahub-opensearch-1"), [], [make_proc(2, 0, "java")])
        g.history = self.netdata.history_for(g)
        trend = pt.memory_trend(g.history["mem_daily"])
        self.assertEqual((trend["from"], trend["to"], trend["growing"]), (600.0, 1100.0, True))
        self.assertIn("rising steadily", pt.history_text(g.history))
        system = self.netdata.system_memory()
        self.assertEqual([v for _, v in system["swap"]], [8000.0, 12000.0, 17000.0])
        lines = pt.memory_week_lines(system, [g])
        self.assertTrue(lines[1].startswith("Swap in use"))
        self.assertTrue(lines[2].startswith("growing: datahub-opensearch-1 600 MB"))

    def test_quiet_snapshot_but_busy_week_is_not_idle(self):
        proc = make_proc(12, 0, "ai-gateway")
        g = self.group(pt.Provenance(kind="container", name="helicone-ai-gateway"), [], [proc])
        g.cls, g.mem_kb, g.cpu_avg, g.cpu_now, g.oldest_start = "yours", 300 * 1024, 0.0, 0.0, pt.NOW - 9 * 86400
        pt.set_verdict(g)
        self.assertTrue(g.verdict.startswith("idle, holding"))
        g.history = self.netdata.history_for(g)
        pt.set_verdict(g)
        self.assertIn("quiet right now, but", g.verdict)
        self.assertIn("network traffic", g.verdict)

    def test_shared_app_chart_is_named(self):
        tunnel = self.group(pt.Provenance(kind="unit", name="cloudflared-openmuse-helicone"), [], [make_proc(20, 0, "cloudflared")])
        other = self.group(pt.Provenance(kind="container", name="netbird-cloudflared"), [], [make_proc(21, 0, "cloudflared")])
        other.name = "netbird-cloudflared"
        pt.apply_netdata([tunnel, other], self.netdata)
        self.assertIn("`netbird-cloudflared`", pt.history_text(tunnel.history))

    def test_missing_charts_and_hidden_cpu_are_explained(self):
        lone = self.group(pt.Provenance(kind="manual", name="mystery-tool"), [], [make_proc(5, 0, "mystery-tool")])
        h = self.netdata.history_for(lone)
        self.assertIn("`mystery-tool`", pt.history_text(h))
        g = self.group(pt.Provenance(kind="system-package", name="netdata"),
                       [pt.Launch("system-service", "x", unit="netdata.service", scope="system")], [make_proc(6, 0, "netdata")])
        g.history = self.netdata.history_for(g)
        g.cpu_avg = 1.0
        pt.mark_hidden_cpu(g)
        self.assertIn("short-lived", pt.history_text(g.history))
        self.assertIn("systemd_netdata.cpu", pt.history_text(g.history))

    def test_unreachable_netdata_is_skipped(self):
        self.assertFalse(pt.NetdataHistory("http://127.0.0.1:9", timeout=0.5).connect())


if __name__ == "__main__":
    unittest.main()
