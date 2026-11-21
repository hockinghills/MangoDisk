"""Tests for the pure parsing and classification logic in process_triage.

Run with: python3 -m unittest discover -s tools/process-triage
"""

import json
import os
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
