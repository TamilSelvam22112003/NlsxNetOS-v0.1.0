import gi
import json
import subprocess
import sys
import threading

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Pango, Gdk

HELPER = "/usr/lib/nls-manager/nls-manager-helper"

CSS = """
window { background: #f6f7fb; }
.header-title { font-size: 20px; font-weight: 700; }
.page-title { font-size: 26px; font-weight: 700; }
.page-subtitle { color: #5f6368; font-size: 13px; }
.metric-title { color: #5f6368; font-size: 12px; }
.metric-value { font-size: 20px; font-weight: 700; }
.status-ready { color: #188038; font-weight: 700; }
.status-warn { color: #b06000; font-weight: 700; }
.status-error { color: #c5221f; font-weight: 700; }
.status-muted { color: #5f6368; font-weight: 700; }
.card { background: white; border-radius: 12px; padding: 16px; }
.sidebar { background: #ffffff; }
"""

def run_privileged(action, args=None, timeout=30):
    cmd = ["pkexec", HELPER, action]
    if args:
        cmd.extend(args)
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        if p.returncode != 0:
            return False, p.stderr.strip() or p.stdout.strip() or "Operation cancelled."
        return True, p.stdout.strip()
    except Exception as exc:
        return False, str(exc)

def status_text(value):
    return str(value or "unknown").replace("_", " ").title()

class NLSManager(Gtk.Application):
    NAV = [
        ("Dashboard", "Overview"),
        ("NLS", "NLS"),
        ("Network", "Network"),
        ("Router-CA", "Router-CA"),
        ("Identity", "Identity"),
        ("Security", "Security"),
        ("Logs", "Logs"),
    ]

    def __init__(self):
        super().__init__(application_id="org.nlsxnetos.NLSManager")
        self.value_labels = {}
        self.window = None

    def do_activate(self):
        if self.window:
            self.window.present()
            return
        css = Gtk.CssProvider()
        css.load_from_data(CSS.encode())
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        self.window = Gtk.ApplicationWindow(application=self, title="NLS Manager", default_width=1180, default_height=760)
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.window.set_child(root)

        header = Gtk.HeaderBar()
        title = Gtk.Label(label="NLS Manager")
        title.add_css_class("header-title")
        header.set_title_widget(title)
        self.global_status = Gtk.Label(label="Checking system…")
        self.global_status.add_css_class("status-muted")
        header.pack_start(self.global_status)
        refresh = Gtk.Button(label="Refresh")
        refresh.connect("clicked", lambda *_: self.refresh_status())
        header.pack_end(refresh)
        root.append(header)

        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        root.append(body)
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        sidebar.set_size_request(220, -1)
        sidebar.add_css_class("sidebar")
        body.append(sidebar)
        nav = Gtk.ListBox()
        nav.set_selection_mode(Gtk.SelectionMode.SINGLE)
        sidebar.append(nav)
        for page, label in self.NAV:
            row = Gtk.ListBoxRow()
            row.set_child(Gtk.Label(label=label, xalign=0, margin_start=16, margin_top=12, margin_bottom=12))
            row.page_name = page
            nav.append(row)

        self.stack = Gtk.Stack(hexpand=True, vexpand=True, transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_margin_top(24); self.stack.set_margin_bottom(24)
        self.stack.set_margin_start(28); self.stack.set_margin_end(28)
        body.append(self.stack)
        self.stack.add_named(self.dashboard_page(), "Dashboard")
        self.stack.add_named(self.nls_page(), "NLS")
        self.stack.add_named(self.network_page(), "Network")
        self.stack.add_named(self.ca_page(), "Router-CA")
        self.stack.add_named(self.identity_page(), "Identity")
        self.stack.add_named(self.security_page(), "Security")
        self.stack.add_named(self.logs_page(), "Logs")
        nav.connect("row-selected", self.on_nav)
        nav.select_row(nav.get_row_at_index(0))
        self.window.present()
        self.refresh_status()

    def on_nav(self, _nav, row):
        if row:
            self.stack.set_visible_child_name(row.page_name)

    def heading(self, title, subtitle):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        t = Gtk.Label(label=title, xalign=0); t.add_css_class("page-title")
        s = Gtk.Label(label=subtitle, xalign=0, wrap=True); s.add_css_class("page-subtitle")
        box.append(t); box.append(s)
        return box

    def card(self, title, key, detail_key):
        frame = Gtk.Frame(); frame.add_css_class("card")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5); frame.set_child(box)
        t = Gtk.Label(label=title, xalign=0); t.add_css_class("metric-title")
        value = Gtk.Label(label="Checking…", xalign=0); value.add_css_class("metric-value")
        detail = Gtk.Label(label="", xalign=0, wrap=True); detail.add_css_class("page-subtitle")
        box.append(t); box.append(value); box.append(detail)
        self.value_labels[key] = value; self.value_labels[detail_key] = detail
        return frame

    def dashboard_page(self):
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        root.append(self.heading("Dashboard", "Live operational state of the NLS control plane and router services."))
        grid = Gtk.Grid(column_spacing=14, row_spacing=14)
        grid.attach(self.card("Operational readiness", "ready", "ready_detail"), 0, 0, 2, 1)
        grid.attach(self.card("NLS Router", "router", "router_detail"), 0, 1, 1, 1)
        grid.attach(self.card("Configuration", "config", "config_detail"), 1, 1, 1, 1)
        grid.attach(self.card("FRRouting", "frr", "frr_detail"), 0, 2, 1, 1)
        grid.attach(self.card("Router-CA trust", "ca", "ca_detail"), 1, 2, 1, 1)
        root.append(grid)
        actions = Gtk.Box(spacing=10)
        for label, action in (("Validate System", "validate"), ("Enable NLS", "enable"), ("Disable NLS", "disable")):
            b = Gtk.Button(label=label); b.connect("clicked", lambda _, a=action: self.action(a)); actions.append(b)
        root.append(actions)
        return root

    def nls_page(self):
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        root.append(self.heading("NLS Configuration", "Protocol settings and the NLS router service lifecycle."))
        grid = Gtk.Grid(column_spacing=18, row_spacing=10)
        fields = [("Router ID","router_id"),("Listen address","listen_address"),("Listen port","listen_port"),
                  ("Protocol version","protocol_version"),("Replay window","replay_window"),
                  ("Max clock skew","max_clock_skew_seconds"),("Session timeout","session_timeout_seconds")]
        for row,(label,key) in enumerate(fields):
            grid.attach(Gtk.Label(label=label,xalign=0),0,row,1,1)
            value=Gtk.Label(label="—",xalign=0); self.value_labels["cfg_"+key]=value; grid.attach(value,1,row,1,1)
        root.append(grid)
        actions=Gtk.Box(spacing=10)
        for label,action in (("Initialize","init"),("Enable NLS","enable"),("Disable NLS","disable"),("Restart Router","restart")):
            b=Gtk.Button(label=label); b.connect("clicked",lambda _,a=action:self.action(a)); actions.append(b)
        root.append(actions)
        return root

    def network_page(self):
        root=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=16)
        root.append(self.heading("Network","Live Linux networking and FRRouting state used by NlsxNetOS."))
        grid=Gtk.Grid(column_spacing=18,row_spacing=10)
        for row,(label,key) in enumerate([("IPv4 forwarding","ipv4_forwarding"),("IPv6 forwarding","ipv6_forwarding"),("FRRouting service","frr"),("NLS listen socket","listen_socket")]):
            grid.attach(Gtk.Label(label=label,xalign=0),0,row,1,1)
            value=Gtk.Label(label="—",xalign=0); self.value_labels["net_"+key]=value; grid.attach(value,1,row,1,1)
        root.append(grid)
        b=Gtk.Button(label="Validate FRRouting"); b.connect("clicked",lambda *_:self.action("frr-validate")); root.append(b)
        self.interface_view=Gtk.Label(label="Loading interfaces…",xalign=0,wrap=True); root.append(self.interface_view)
        return root

    def ca_page(self):
        root=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=16)
        root.append(self.heading("Router-CA","Router-CA is a trust anchor. Validation is a one-shot operation, not a persistent daemon."))
        grid=Gtk.Grid(column_spacing=18,row_spacing=10)
        for row,(label,key) in enumerate([("Trust status","ca"),("Trust entries","ca_entries"),("Validation","ca_validation")]):
            grid.attach(Gtk.Label(label=label,xalign=0),0,row,1,1)
            value=Gtk.Label(label="—",xalign=0); self.value_labels["ca_"+key]=value; grid.attach(value,1,row,1,1)
        root.append(grid)
        b=Gtk.Button(label="Validate Router-CA Now"); b.connect("clicked",lambda *_:self.action("ca-validate")); root.append(b)
        return root

    def identity_page(self):
        root=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=16)
        root.append(self.heading("Router Identity","Private key material is never displayed; only availability and protection are reported."))
        grid=Gtk.Grid(column_spacing=18,row_spacing=10)
        for row,(label,key) in enumerate([("Router identity key","identity"),("Encryption private key","encryption_key"),("Identity directory","identity_dir")]):
            grid.attach(Gtk.Label(label=label,xalign=0),0,row,1,1)
            value=Gtk.Label(label="—",xalign=0); self.value_labels["id_"+key]=value; grid.attach(value,1,row,1,1)
        root.append(grid); return root

    def security_page(self):
        root=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=16)
        root.append(self.heading("Security","Configured cryptographic and session-protection mechanisms."))
        items=[("Identity","Ed25519"),("Key exchange","X25519"),("Encryption","AES-256-GCM"),("Key derivation","HKDF"),("Hash","SHA-256"),("Replay protection","Sequence/timestamp window")]
        grid=Gtk.Grid(column_spacing=24,row_spacing=12)
        for row,(label,value) in enumerate(items):
            grid.attach(Gtk.Label(label=label,xalign=0),0,row,1,1); grid.attach(Gtk.Label(label=value,xalign=0),1,row,1,1)
        root.append(grid); return root

    def logs_page(self):
        root=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=12)
        root.append(self.heading("Diagnostics","Recent NLS Router and Router-CA events."))
        self.log_view=Gtk.Label(label="Loading logs…",xalign=0,wrap=True); self.log_view.set_selectable(True); self.log_view.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        root.append(self.log_view)
        b=Gtk.Button(label="Refresh Logs"); b.connect("clicked",lambda *_:self.load_logs()); root.append(b)
        return root

    def action(self, action):
        ok,out=run_privileged(action)
        self.message(out or ("Operation completed successfully." if ok else "Operation failed."), error=not ok)
        self.refresh_status()

    def refresh_status(self):
        def worker():
            ok,out=run_privileged("status-json")
            try: data=json.loads(out) if ok else {"error":out}
            except json.JSONDecodeError: data={"error":"Invalid status response from NLS Manager helper."}
            GLib.idle_add(self.update_status,data)
        threading.Thread(target=worker,daemon=True).start()

    def load_logs(self):
        def worker():
            ok,out=run_privileged("logs")
            GLib.idle_add(self.update_logs,out if ok else "Error: "+out)
        threading.Thread(target=worker,daemon=True).start()

    def update_logs(self,text):
        self.log_view.set_text(text[-12000:]); return GLib.SOURCE_REMOVE

    def set_value(self,key,value):
        label=self.value_labels.get(key)
        if not label:return
        label.set_text(status_text(value))
        for c in ("status-ready","status-warn","status-error","status-muted"):label.remove_css_class(c)
        v=str(value).lower()
        label.add_css_class("status-ready" if v in ("active","running","enabled","valid","ready","ok","up","passed","available") else "status-muted" if v in ("inactive","disabled","unknown","not configured","not established","dead") else "status-warn")

    def update_status(self,data):
        if "error" in data:
            self.global_status.set_text("Status unavailable"); self.set_value("ready","unknown"); return GLib.SOURCE_REMOVE
        self.set_value("ready",data.get("readiness","unknown"))
        self.set_value("router",data.get("nls_service","unknown"))
        self.set_value("config",data.get("config_enabled","unknown"))
        self.set_value("frr",data.get("frr","unknown"))
        self.set_value("ca",data.get("ca_validation","unknown"))
        self.value_labels["ready_detail"].set_text(data.get("readiness_reason",""))
        self.value_labels["router_detail"].set_text(f"PID: {data.get('nls_pid','—')}  •  Port: {data.get('listen_port','—')}")
        self.value_labels["config_detail"].set_text(f"Router ID: {data.get('router_id','—')}  •  Protocol: {data.get('protocol_version','—')}")
        self.value_labels["frr_detail"].set_text(f"Service: {data.get('frr','—')}  •  Forwarding: {data.get('ipv4_forwarding','—')}/{data.get('ipv6_forwarding','—')}")
        self.value_labels["ca_detail"].set_text(f"Trust entries: {data.get('ca_entries','—')}")
        for key in ("router_id","listen_address","listen_port","protocol_version","replay_window","max_clock_skew_seconds","session_timeout_seconds"):
            self.value_labels["cfg_"+key].set_text(str(data.get(key,"—")))
        for key in ("ipv4_forwarding","ipv6_forwarding","frr","listen_socket"): self.set_value("net_"+key,data.get(key,"unknown"))
        for key in ("ca","ca_entries","ca_validation"): self.set_value("ca_"+key,data.get(key,"unknown"))
        for key in ("identity","encryption_key","identity_dir"): self.set_value("id_"+key,data.get(key,"unknown"))
        self.interface_view.set_text(data.get("interfaces","No interface data."))
        self.global_status.set_text("System: "+status_text(data.get("readiness","unknown")))
        self.load_logs()
        return GLib.SOURCE_REMOVE

    def message(self,text,error=False):
        dialog=Gtk.MessageDialog(transient_for=self.window,modal=True,buttons=Gtk.ButtonsType.OK,text=text[:4000])
        dialog.set_message_type(Gtk.MessageType.ERROR if error else Gtk.MessageType.INFO)
        dialog.connect("response",lambda d,_:d.destroy()); dialog.present()

def main():
    return NLSManager().run(sys.argv)

if __name__=="__main__":
    main()
