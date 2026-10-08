import gi
import json
import subprocess
import sys

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

HELPER = "/usr/lib/nls-manager/nls-manager-helper"


def run_privileged(action, args=None):
    cmd = ["pkexec", HELPER, action]
    if args:
        cmd.extend(args)
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
        if p.returncode != 0:
            return False, p.stderr.strip() or p.stdout.strip() or "Operation cancelled."
        return True, p.stdout.strip()
    except Exception as exc:
        return False, str(exc)


class NLSManager(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.nlsxnetos.NLSManager")
        self.status_labels = {}

    def do_activate(self):
        win = Gtk.ApplicationWindow(application=self, title="NLS Manager", default_width=900, default_height=620)
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        win.set_child(root)
        header = Gtk.HeaderBar()
        header.set_title_widget(Gtk.Label(label="NLS Manager"))
        refresh = Gtk.Button(label="Refresh")
        refresh.connect("clicked", lambda *_: self.refresh_status())
        header.pack_end(refresh)
        root.append(header)

        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        root.append(body)
        nav = Gtk.ListBox()
        nav.set_selection_mode(Gtk.SelectionMode.SINGLE)
        nav.set_size_request(190, -1)
        for name in ("Dashboard", "NLS", "Network", "Router-CA", "Logs"):
            row = Gtk.ListBoxRow()
            row.set_child(Gtk.Label(label=name, xalign=0, margin_start=18, margin_top=12, margin_bottom=12))
            nav.append(row)
        body.append(nav)

        stack = Gtk.Stack(hexpand=True, vexpand=True)
        stack.set_margin_top(20); stack.set_margin_bottom(20); stack.set_margin_start(24); stack.set_margin_end(24)
        body.append(stack)
        stack.add_named(self.dashboard_page(), "Dashboard")
        stack.add_named(self.nls_page(), "NLS")
        stack.add_named(self.network_page(), "Network")
        stack.add_named(self.ca_page(), "Router-CA")
        stack.add_named(self.logs_page(), "Logs")
        nav.connect("row-selected", lambda _nav, row: stack.set_visible_child_name(row.get_child().get_text()) if row else None)
        nav.select_row(nav.get_row_at_index(0))
        win.present()
        self.window = win
        self.refresh_status()

    def card(self, title, key):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_top(8); box.set_margin_bottom(8); box.set_margin_start(8); box.set_margin_end(8)
        frame = Gtk.Frame(label=title)
        frame.set_child(box)
        value = Gtk.Label(label="Checking…", xalign=0)
        value.add_css_class("title-3")
        box.append(value)
        self.status_labels[key] = value
        return frame

    def dashboard_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(Gtk.Label(label="NLS Network Layer Security", xalign=0))
        grid = Gtk.Grid(column_spacing=12, row_spacing=12)
        grid.attach(self.card("NLS Router", "router"), 0, 0, 1, 1)
        grid.attach(self.card("NLS Service", "nls"), 1, 0, 1, 1)
        grid.attach(self.card("FRRouting", "frr"), 0, 1, 1, 1)
        grid.attach(self.card("Router-CA", "ca"), 1, 1, 1, 1)
        box.append(grid)
        box.append(Gtk.Label(label="Use the navigation panel to configure NLS, inspect interfaces, manage Router-CA trust, and view logs.", xalign=0, wrap=True))
        return box

    def nls_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(Gtk.Label(label="NLS Service", xalign=0))
        for label, action in (("Enable NLS", "enable"), ("Disable NLS", "disable"), ("Initialize NLS", "init")):
            b = Gtk.Button(label=label)
            b.connect("clicked", lambda _, a=action: self.action(a))
            box.append(b)
        return box

    def network_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(Gtk.Label(label="Network and Router", xalign=0))
        b = Gtk.Button(label="Validate FRRouting configuration")
        b.connect("clicked", lambda *_: self.action("frr-validate"))
        box.append(b)
        b = Gtk.Button(label="Show routing status")
        b.connect("clicked", lambda *_: self.action("status"))
        box.append(b)
        return box

    def ca_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(Gtk.Label(label="Router-CA", xalign=0))
        b = Gtk.Button(label="Validate Router-CA configuration")
        b.connect("clicked", lambda *_: self.action("ca-status"))
        box.append(b)
        return box

    def logs_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(Gtk.Label(label="Diagnostics", xalign=0))
        b = Gtk.Button(label="Read NLS service status")
        b.connect("clicked", lambda *_: self.action("status"))
        box.append(b)
        return box

    def action(self, action):
        ok, out = run_privileged(action)
        self.message(out if ok else f"Error: {out}")
        self.refresh_status()

    def refresh_status(self):
        def worker():
            ok, out = run_privileged("status-json")
            data = {}
            if ok:
                try:
                    data = json.loads(out)
                except json.JSONDecodeError:
                    pass
            GLib.idle_add(self.update_status, data)
        import threading
        threading.Thread(target=worker, daemon=True).start()

    def update_status(self, data):
        for key in self.status_labels:
            self.status_labels[key].set_text(data.get(key, "Unknown"))
        return GLib.SOURCE_REMOVE

    def message(self, text):
        dialog = Gtk.MessageDialog(transient_for=self.window, modal=True, buttons=Gtk.ButtonsType.OK, text=text[:2000])
        dialog.connect("response", lambda d, _: d.destroy())
        dialog.present()


def main():
    app = NLSManager()
    return app.run(sys.argv)


if __name__ == "__main__":
    main()
