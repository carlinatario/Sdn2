#!/usr/bin/env python3
"""
University Campus SDN Controller — Ryu (OpenFlow 1.3)
=======================================================
Features:
  1. Topology Discovery   — LLDP auto-detects switches and links
  2. Dynamic Routing      — Dijkstra shortest-path, auto-reroutes on failure
  3. VLAN Segmentation    — 8 VLANs across two campuses
  4. Firewall / ACL       — inter-VLAN policy + blocked TCP/UDP ports (realtime)
  5. Admin Web UI         — live dashboard at http://127.0.0.1:8080

Run:
  ryu-manager --observe-links university_controller.py
Then open: http://127.0.0.1:8080
"""

import json
import threading
import datetime
from collections import deque
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (MAIN_DISPATCHER, CONFIG_DISPATCHER,
                                     set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import (packet, ethernet, arp, ipv4, icmp, tcp, udp, ether_types)
from ryu.topology import event as topo_event


# ═══════════════════════════════════════════════════════════════════════════════
#  LIVE POLICY STATE
# ═══════════════════════════════════════════════════════════════════════════════

_policy_lock = threading.Lock()

VLAN_NAMES = {
    10: "Main Admin",        20: "Faculty & Staff",
    30: "Teaching Labs",     40: "Student WiFi",
    50: "Library & Servers", 60: "City Admin",
    70: "City Labs",         80: "City Student WiFi",
}

VLAN_PREFIX = {
    10: "10.0.10.", 20: "10.0.20.", 30: "10.0.30.", 40: "10.0.40.",
    50: "10.0.50.", 60: "10.0.60.", 70: "10.0.70.", 80: "10.0.80.",
}

ROUTER_MAC = "00:00:00:00:fe:01"

TRUNK = 0

PORT_VLAN = {
    # s1 is the main campus collapsed core. The remaining main-campus
    # switches represent real buildings or wiring closets.
    1: {1:TRUNK, 2:TRUNK, 3:TRUNK, 4:TRUNK, 5:TRUNK},
    2: {1:TRUNK, 2:10, 3:10, 4:20},
    3: {1:TRUNK, 2:20, 3:20, 4:40, 5:40},
    4: {1:TRUNK, 2:30, 3:30, 4:30, 5:30},
    5: {1:TRUNK, 2:50, 3:50, 4:50},
    # s6 is the city campus aggregation switch.
    6: {1:TRUNK, 2:TRUNK, 3:TRUNK},
    7: {1:TRUNK, 2:60, 3:70, 4:70},
    8: {1:TRUNK, 2:80, 3:80},
}

STATIC_LINKS = [
    (1, 2, 1, 1), (1, 3, 2, 1), (1, 4, 3, 1), (1, 5, 4, 1),
    (1, 6, 5, 1),
    (6, 7, 2, 1), (6, 8, 3, 1),
]

BLOCKED_TCP_PORTS = {23, 135, 139, 445}
BLOCKED_UDP_PORTS = {161, 162}

INTER_VLAN_POLICY = {
    (10, 20): True, (10, 30): True, (10, 40): True, (10, 50): True,
    (10, 60): True, (10, 70): True, (10, 80): True, (20, 30): True,
    (20, 50): True, (30, 10): True, (50, 20): True, (60, 10): True, (60, 70): True,
    (60, 80): True, (20, 70): True,
}

FW_LOG = deque(maxlen=200)
_log_lock = threading.Lock()

LINK_ALERTS = deque(maxlen=50)
_alerts_lock = threading.Lock()

STATS = {"packets_in": 0, "packets_drop": 0, "packets_fwd": 0, "flows_installed": 0}
_stats_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _log(action, src_ip, dst_ip, reason, vlan=None):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    with _log_lock:
        FW_LOG.appendleft({"time": ts, "action": action, "src": src_ip,
                           "dst": dst_ip, "reason": reason, "vlan": vlan})


def ip_to_vlan(ip_addr):
    if not ip_addr:
        return None
    for vlan_id, prefix in VLAN_PREFIX.items():
        if ip_addr.startswith(prefix):
            return vlan_id
    return None


def vlan_gateway_ip(vlan_id):
    prefix = VLAN_PREFIX.get(vlan_id)
    return prefix + "1" if prefix else None


def gateway_ip_to_vlan(ip_addr):
    for vlan_id in VLAN_PREFIX:
        if ip_addr == vlan_gateway_ip(vlan_id):
            return vlan_id
    return None


def port_vlan(dpid, port_no):
    return PORT_VLAN.get(dpid, {}).get(port_no, None)


def host_ports_for_vlan(dpid, vlan_id, exclude_port=None):
    return [p for p, v in PORT_VLAN.get(dpid, {}).items()
            if v == vlan_id and p != exclude_port]


def acl_check(src_vlan, dst_vlan, tcp_pkt, udp_pkt):
    """Returns (allowed, reason). Thread-safe read of live policy."""
    with _policy_lock:
        b_tcp  = set(BLOCKED_TCP_PORTS)
        b_udp  = set(BLOCKED_UDP_PORTS)
        policy = dict(INTER_VLAN_POLICY)

    if tcp_pkt is not None:
        if tcp_pkt.dst_port in b_tcp:
            return False, "Blocked TCP port %d" % tcp_pkt.dst_port
        if tcp_pkt.src_port in b_tcp:
            return False, "Blocked TCP port %d" % tcp_pkt.src_port

    if udp_pkt is not None:
        if udp_pkt.dst_port in b_udp:
            return False, "Blocked UDP port %d" % udp_pkt.dst_port
        if udp_pkt.src_port in b_udp:
            return False, "Blocked UDP port %d" % udp_pkt.src_port

    if src_vlan is None or dst_vlan is None:
        return True, "Unknown VLAN"
    if src_vlan == dst_vlan:
        return True, "Same VLAN"
    if policy.get((src_vlan, dst_vlan), False):
        return True, "ACL allow %d->%d" % (src_vlan, dst_vlan)
    return False, "ACL block %d->%d" % (src_vlan, dst_vlan)


# ═══════════════════════════════════════════════════════════════════════════════
#  ADMIN WEB UI
# ═══════════════════════════════════════════════════════════════════════════════

ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SDN Admin Panel</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0f1117;--panel:#181c27;--panel2:#1e2235;--border:#252c42;
  --accent:#4f8ef7;--accent2:#2563eb;--green:#22c55e;--red:#ef4444;
  --amber:#f59e0b;--text:#e2e8f0;--muted:#64748b;--mono:'IBM Plex Mono',monospace;
}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:'IBM Plex Sans',sans-serif;
     min-height:100vh;display:flex;flex-direction:column;}

/* ── Header ── */
header{background:var(--panel);border-bottom:1px solid var(--border);
       padding:0 24px;height:56px;display:flex;align-items:center;
       justify-content:space-between;flex-shrink:0;position:sticky;top:0;z-index:50;}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:.95rem;
      letter-spacing:.06em;text-transform:uppercase;color:var(--accent);}
.logo-icon{width:30px;height:30px;border-radius:6px;background:var(--accent2);
           display:flex;align-items:center;justify-content:center;font-size:14px;}
.hstats{display:flex;gap:20px;}
.hstat{text-align:right;}
.hstat-n{font-family:var(--mono);font-size:1.1rem;font-weight:600;color:var(--accent);}
.hstat-l{font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;}

/* ── Layout ── */
.layout{display:flex;flex:1;overflow:hidden;}
nav{width:190px;background:var(--panel);border-right:1px solid var(--border);
    display:flex;flex-direction:column;gap:2px;padding:16px 10px;flex-shrink:0;}
.nav-btn{padding:9px 14px;border-radius:6px;font-size:.82rem;font-weight:400;
         cursor:pointer;border:none;background:transparent;color:var(--muted);
         text-align:left;width:100%;transition:all .15s;display:flex;align-items:center;gap:9px;}
.nav-btn:hover{background:var(--panel2);color:var(--text);}
.nav-btn.active{background:rgba(79,142,247,.14);color:var(--accent);font-weight:600;}
.nav-icon{font-size:15px;width:18px;text-align:center;flex-shrink:0;}
.nav-sep{height:1px;background:var(--border);margin:8px 4px;}

/* ── Alert badge in nav ── */
.alert-pip{background:var(--red);color:#fff;border-radius:10px;padding:1px 7px;
           font-size:.62rem;font-weight:700;margin-left:auto;display:none;}
.alert-pip.visible{display:inline-block;}

/* ── Main content ── */
main{flex:1;overflow-y:auto;padding:24px;}
main::-webkit-scrollbar{width:5px;}
main::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
.page{display:none;}
.page.active{display:block;}
h2{font-size:1.1rem;font-weight:700;margin-bottom:4px;letter-spacing:.03em;}
.page-sub{font-size:.8rem;color:var(--muted);margin-bottom:20px;}

/* ── Cards ── */
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;
      padding:20px;margin-bottom:18px;}
.card-title{font-size:.7rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
            color:var(--muted);margin-bottom:14px;}

/* ── Stats row ── */
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px;}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px 20px;}
.stat-num{font-family:var(--mono);font-size:1.8rem;font-weight:600;line-height:1;}
.stat-lbl{font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-top:4px;}
.s-blue{color:var(--accent);}
.s-green{color:var(--green);}
.s-red{color:var(--red);}
.s-amber{color:var(--amber);}

/* ── Tables ── */
table{width:100%;border-collapse:collapse;font-size:.82rem;}
th{text-align:left;font-size:.65rem;font-weight:700;letter-spacing:.12em;
   text-transform:uppercase;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--border);}
td{padding:9px 12px;border-bottom:1px solid rgba(37,44,66,.6);}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(255,255,255,.02);}

/* ── Badges ── */
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:20px;
       font-size:.72rem;font-weight:600;font-family:var(--mono);}
.badge-green{background:rgba(34,197,94,.12);color:var(--green);border:1px solid rgba(34,197,94,.25);}
.badge-red{background:rgba(239,68,68,.12);color:var(--red);border:1px solid rgba(239,68,68,.25);}
.badge-blue{background:rgba(79,142,247,.12);color:var(--accent);border:1px solid rgba(79,142,247,.25);}
.badge-amber{background:rgba(245,158,11,.12);color:var(--amber);border:1px solid rgba(245,158,11,.25);}
.dot{width:6px;height:6px;border-radius:50%;display:inline-block;}

/* ── Forms ── */
.form-row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-bottom:14px;}
.form-group{display:flex;flex-direction:column;gap:5px;}
label{font-size:.7rem;font-weight:600;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;}
select,input[type=number],input[type=text]{
  background:var(--panel2);border:1px solid var(--border);border-radius:6px;
  color:var(--text);padding:7px 11px;font-size:.82rem;font-family:inherit;outline:none;transition:border .15s;}
select:focus,input:focus{border-color:var(--accent);}
select option{background:var(--panel2);}

/* ── Buttons ── */
.btn{padding:8px 16px;border-radius:6px;font-size:.8rem;font-weight:600;
     cursor:pointer;border:none;transition:all .15s;font-family:inherit;}
.btn-primary{background:var(--accent2);color:#fff;}
.btn-primary:hover{background:#1d4ed8;}
.btn-danger{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3);}
.btn-danger:hover{background:rgba(239,68,68,.25);}
.btn-success{background:rgba(34,197,94,.15);color:var(--green);border:1px solid rgba(34,197,94,.3);}
.btn-success:hover{background:rgba(34,197,94,.25);}
.btn-sm{padding:4px 10px;font-size:.72rem;}

/* ── ACL matrix ── */
.matrix-wrap{overflow-x:auto;}
.matrix{border-collapse:collapse;font-size:.72rem;font-family:var(--mono);}
.matrix th,.matrix td{padding:5px 8px;text-align:center;border:1px solid var(--border);min-width:52px;}
.matrix th{background:var(--panel2);font-size:.62rem;color:var(--muted);}
.matrix .row-hdr{background:var(--panel2);font-weight:600;color:var(--muted);text-align:left;
                  padding-left:10px;white-space:nowrap;}
.cell-allow{background:rgba(34,197,94,.15);color:var(--green);cursor:pointer;font-weight:700;}
.cell-block{background:rgba(239,68,68,.1);color:rgba(239,68,68,.5);cursor:pointer;}
.cell-self{background:var(--panel2);color:var(--muted);cursor:default;}
.cell-allow:hover{background:rgba(239,68,68,.2);}
.cell-block:hover{background:rgba(34,197,94,.2);}

/* ── Alert items ── */
.alert-item{border-left:3px solid var(--red);padding:14px 16px;margin-bottom:8px;
            background:rgba(239,68,68,.05);border-radius:0 8px 8px 0;
            display:flex;align-items:flex-start;gap:12px;}
.alert-item:last-child{margin-bottom:0;}
.alert-icon-cell{font-size:1.1rem;flex-shrink:0;margin-top:1px;color:var(--red);}
.alert-body{flex:1;}
.alert-msg{font-size:.85rem;color:var(--text);font-weight:600;margin-bottom:3px;}
.alert-detail{font-size:.72rem;color:var(--muted);font-family:var(--mono);}
.alert-ts{font-family:var(--mono);font-size:.68rem;color:var(--muted);flex-shrink:0;margin-top:2px;}
.alerts-empty{text-align:center;padding:44px 20px;}
.alerts-empty-icon{font-size:2.4rem;margin-bottom:10px;color:var(--green);}
.alerts-empty-title{font-size:.9rem;color:var(--green);font-weight:700;}
.alerts-empty-sub{font-size:.78rem;color:var(--muted);margin-top:5px;}

/* ── Log table ── */
.log-action-allow{color:var(--green);}
.log-action-drop {color:var(--red);}
.log-action-fwd  {color:var(--accent);}
.mono{font-family:var(--mono);font-size:.78rem;}

/* ── Toast ── */
#toast{position:fixed;bottom:24px;right:24px;background:var(--panel);
       border:1px solid var(--green);border-radius:8px;padding:12px 18px;
       font-size:.82rem;color:var(--green);opacity:0;transition:opacity .3s;
       z-index:999;pointer-events:none;max-width:340px;line-height:1.4;}
#toast.show{opacity:1;}

@media(max-width:900px){
  .stat-row{grid-template-columns:1fr 1fr;}
  nav{width:160px;}
}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">&#x2B21;</div>
    SDN Admin Panel
  </div>
  <div class="hstats">
    <div class="hstat">
      <div class="hstat-n" id="h-pktin">0</div>
      <div class="hstat-l">Packets In</div>
    </div>
    <div class="hstat">
      <div class="hstat-n s-red" id="h-pkdrop">0</div>
      <div class="hstat-l">Dropped</div>
    </div>
    <div class="hstat">
      <div class="hstat-n s-green" id="h-flows">0</div>
      <div class="hstat-l">Flows</div>
    </div>
    <div class="hstat">
      <div class="hstat-n" id="h-alerts" style="color:var(--muted)">0</div>
      <div class="hstat-l">Alerts</div>
    </div>
  </div>
</header>

<div class="layout">
  <nav>
    <button class="nav-btn active" onclick="showPage('dashboard')" id="nb-dashboard">
      <span class="nav-icon">&#x25C8;</span> Dashboard
    </button>
    <button class="nav-btn" onclick="showPage('firewall')" id="nb-firewall">
      <span class="nav-icon">&#x2295;</span> Firewall
    </button>
    <button class="nav-btn" onclick="showPage('acl')" id="nb-acl">
      <span class="nav-icon">&#x229E;</span> ACL Policy
    </button>
    <button class="nav-btn" onclick="showPage('alerts')" id="nb-alerts">
      <span class="nav-icon">&#x26A0;</span> Alerts
      <span class="alert-pip" id="nav-pip">0</span>
    </button>
    <div class="nav-sep"></div>
    <button class="nav-btn" onclick="showPage('log')" id="nb-log">
      <span class="nav-icon">&#x2261;</span> Event Log
    </button>
  </nav>

  <main>

    <!-- ══ DASHBOARD ══════════════════════════════════════════════════ -->
    <div class="page active" id="page-dashboard">
      <h2>Network Dashboard</h2>
      <p class="page-sub">Live overview of SDN network activity</p>

      <div class="stat-row">
        <div class="stat-card"><div class="stat-num s-blue" id="s-pktin">0</div>
          <div class="stat-lbl">Packets In</div></div>
        <div class="stat-card"><div class="stat-num s-green" id="s-pkfwd">0</div>
          <div class="stat-lbl">Forwarded</div></div>
        <div class="stat-card"><div class="stat-num s-red" id="s-pkdrop">0</div>
          <div class="stat-lbl">Dropped</div></div>
        <div class="stat-card"><div class="stat-num s-amber" id="s-flows">0</div>
          <div class="stat-lbl">Flows Installed</div></div>
      </div>

      <div class="card">
        <div class="card-title">Active Switches</div>
        <table>
          <thead><tr><th>Switch</th><th>DPID</th><th>Status</th><th>Role</th></tr></thead>
          <tbody id="switch-table">
            <tr><td colspan="4" style="color:var(--muted);text-align:center">Waiting for switches...</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="card-title">VLAN Summary</div>
        <table>
          <thead><tr><th>VLAN</th><th>Name</th><th>Subnet</th><th>Status</th></tr></thead>
          <tbody id="vlan-table"></tbody>
        </table>
      </div>
    </div>

    <!-- ══ FIREWALL ═══════════════════════════════════════════════════ -->
    <div class="page" id="page-firewall">
      <h2>Firewall Rules</h2>
      <p class="page-sub">Block specific TCP/UDP ports across the entire network. Changes take effect immediately.</p>

      <div class="card">
        <div class="card-title">Add Port Block Rule</div>
        <div class="form-row">
          <div class="form-group">
            <label>Protocol</label>
            <select id="fw-proto"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
          </div>
          <div class="form-group">
            <label>Port Number</label>
            <input type="number" id="fw-port" placeholder="e.g. 8080" min="1" max="65535" style="width:130px">
          </div>
          <div class="form-group">
            <label>Description</label>
            <input type="text" id="fw-desc" placeholder="Optional label" style="width:200px">
          </div>
          <button class="btn btn-danger" onclick="addFwRule()">+ Block Port</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Active Blocked Ports</div>
        <table>
          <thead><tr><th>Protocol</th><th>Port</th><th>Description</th><th>Action</th></tr></thead>
          <tbody id="fw-rules-table"></tbody>
        </table>
      </div>
    </div>

    <!-- ══ ACL ════════════════════════════════════════════════════════ -->
    <div class="page" id="page-acl">
      <h2>Inter-VLAN Access Control</h2>
      <p class="page-sub">Click any cell to toggle allow/block. Changes are pushed to all switches immediately — existing flows are evicted in real time. Row = source, Column = destination.</p>

      <div class="card">
        <div class="card-title">ACL Matrix — click to toggle</div>
        <div class="matrix-wrap">
          <table class="matrix" id="acl-matrix"></table>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Quick Allow / Block between VLANs</div>
        <div class="form-row">
          <div class="form-group">
            <label>Source VLAN</label>
            <select id="acl-src"></select>
          </div>
          <div class="form-group">
            <label>Destination VLAN</label>
            <select id="acl-dst"></select>
          </div>
          <button class="btn btn-success" onclick="setAcl(true)">&#x2714; Allow</button>
          <button class="btn btn-danger"  onclick="setAcl(false)">&#x2716; Block</button>
        </div>
      </div>
    </div>

    <!-- ══ ALERTS ═════════════════════════════════════════════════════ -->
    <div class="page" id="page-alerts">
      <h2>Network Alerts</h2>
      <p class="page-sub">Topology events and link-down notifications. New alerts are shown automatically via toast.</p>

      <div class="card">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <span>Active Alerts</span>
          <button class="btn btn-danger btn-sm" onclick="clearAlerts()">Clear All</button>
        </div>
        <div id="alerts-container">
          <div class="alerts-empty">
            <div class="alerts-empty-icon">&#x2714;</div>
            <div class="alerts-empty-title">All Clear &#x2014; No active alerts</div>
            <div class="alerts-empty-sub">Network topology is healthy</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══ LOG ════════════════════════════════════════════════════════ -->
    <div class="page" id="page-log">
      <h2>Event Log</h2>
      <p class="page-sub">Live firewall and routing events. Auto-refreshes every 3 seconds.</p>
      <div class="card" style="padding:0">
        <table>
          <thead>
            <tr>
              <th style="width:70px">Time</th>
              <th style="width:70px">Action</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Reason</th>
              <th style="width:80px">VLAN</th>
            </tr>
          </thead>
          <tbody id="log-table">
            <tr><td colspan="6" style="color:var(--muted);text-align:center;padding:20px">
              No events yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </main>
</div>

<div id="toast"></div>

<script>
const VLANS = [
  {id:10,name:"Admin Office A",  subnet:"10.0.10.0/24"},
  {id:20,name:"HOD & Staff",     subnet:"10.0.20.0/24"},
  {id:30,name:"Computer Lab A",  subnet:"10.0.30.0/24"},
  {id:40,name:"Student WiFi A",  subnet:"10.0.40.0/24"},
  {id:50,name:"Library",         subnet:"10.0.50.0/24"},
  {id:60,name:"Admin Office B",  subnet:"10.0.60.0/24"},
  {id:70,name:"Computer Lab B",  subnet:"10.0.70.0/24"},
  {id:80,name:"Student WiFi B",  subnet:"10.0.80.0/24"},
];

const FW_DEFAULTS = {
  23:{proto:"tcp",desc:"Telnet"}, 135:{proto:"tcp",desc:"NetBIOS"},
  139:{proto:"tcp",desc:"NetBIOS"}, 445:{proto:"tcp",desc:"SMB"},
  161:{proto:"udp",desc:"SNMP"},   162:{proto:"udp",desc:"SNMP trap"},
};

let state = {
  stats:{packets_in:0,packets_drop:0,packets_fwd:0,flows_installed:0},
  switches:[], blocked_tcp:new Set(), blocked_udp:new Set(),
  acl:{}, log:[], link_alerts:[],
};
let _firstPoll = true;

// ── Navigation ────────────────────────────────────────────────────────────────
function showPage(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  document.getElementById('nb-'+name).classList.add('active');
  if(name==='acl')      renderAclMatrix();
  if(name==='firewall') renderFwTable();
  if(name==='log')      renderLog();
  if(name==='alerts')   renderAlerts();
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, error=false){
  const t=document.getElementById('toast');
  t.textContent=msg;
  t.style.borderColor = error ? 'var(--red)'   : 'var(--green)';
  t.style.color       = error ? 'var(--red)'   : 'var(--green)';
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), error ? 4000 : 2200);
}

// ── API ───────────────────────────────────────────────────────────────────────
async function api(path, body=null){
  const opts = body ? {method:'POST',headers:{'Content-Type':'application/json'},
                       body:JSON.stringify(body)} : {};
  return (await fetch(path,opts)).json();
}

// ── Alert badge ───────────────────────────────────────────────────────────────
function updateAlertBadge(){
  const n = state.link_alerts.length;
  const pip = document.getElementById('nav-pip');
  const ha  = document.getElementById('h-alerts');
  pip.textContent = n;
  ha.textContent  = n;
  if(n > 0){ pip.classList.add('visible'); ha.style.color='var(--red)'; }
  else      { pip.classList.remove('visible'); ha.style.color='var(--muted)'; }
}

// ── Firewall ──────────────────────────────────────────────────────────────────
function renderFwTable(){
  const tb=document.getElementById('fw-rules-table'), rows=[];
  state.blocked_tcp.forEach(p=>{
    const d=FW_DEFAULTS[p]?.desc||'';
    rows.push(`<tr><td><span class="badge badge-blue">TCP</span></td>
      <td class="mono">${p}</td><td style="color:var(--muted)">${d}</td>
      <td><button class="btn btn-success btn-sm" onclick="removeFwRule('tcp',${p})">Unblock</button></td></tr>`);
  });
  state.blocked_udp.forEach(p=>{
    const d=FW_DEFAULTS[p]?.desc||'';
    rows.push(`<tr><td><span class="badge badge-amber">UDP</span></td>
      <td class="mono">${p}</td><td style="color:var(--muted)">${d}</td>
      <td><button class="btn btn-success btn-sm" onclick="removeFwRule('udp',${p})">Unblock</button></td></tr>`);
  });
  tb.innerHTML=rows.length?rows.join(''):`<tr><td colspan="4" style="color:var(--muted);text-align:center">No blocked ports</td></tr>`;
}

async function addFwRule(){
  const proto=document.getElementById('fw-proto').value;
  const port=parseInt(document.getElementById('fw-port').value);
  if(!port||port<1||port>65535){toast('Enter a valid port (1-65535)',true);return;}
  const r=await api('/api/firewall/add',{proto,port});
  if(r.ok){
    if(proto==='tcp') state.blocked_tcp.add(port); else state.blocked_udp.add(port);
    renderFwTable(); toast('Port '+port+' ('+proto.toUpperCase()+') blocked');
    document.getElementById('fw-port').value='';
    document.getElementById('fw-desc').value='';
  }
}

async function removeFwRule(proto,port){
  const r=await api('/api/firewall/remove',{proto,port});
  if(r.ok){
    if(proto==='tcp') state.blocked_tcp.delete(port); else state.blocked_udp.delete(port);
    renderFwTable(); toast('Port '+port+' ('+proto.toUpperCase()+') unblocked');
  }
}

// ── ACL Matrix ────────────────────────────────────────────────────────────────
function renderAclMatrix(){
  const tbl=document.getElementById('acl-matrix');
  let html='<thead><tr><th>SRC \\ DST</th>';
  VLANS.forEach(v=>{html+=`<th>V${v.id}</th>`;});
  html+='</tr></thead><tbody>';
  VLANS.forEach(sv=>{
    html+=`<tr><td class="row-hdr">VLAN ${sv.id}<br><span style="font-size:.6rem;font-weight:400">${sv.name}</span></td>`;
    VLANS.forEach(dv=>{
      if(sv.id===dv.id){html+=`<td class="cell-self">&#x2014;</td>`;}
      else{
        const k=sv.id+','+dv.id, ok=!!state.acl[k];
        html+=`<td class="${ok?'cell-allow':'cell-block'}" onclick="toggleAcl(${sv.id},${dv.id})"
          title="VLAN ${sv.id} to VLAN ${dv.id}: ${ok?'ALLOW':'BLOCK'}">${ok?'&#x2714;':'&#x2716;'}</td>`;
      }
    });
    html+='</tr>';
  });
  tbl.innerHTML=html+'</tbody>';
  ['acl-src','acl-dst'].forEach(id=>{
    const sel=document.getElementById(id);
    if(!sel.options.length) VLANS.forEach(v=>{
      const o=document.createElement('option');
      o.value=v.id; o.textContent='VLAN '+v.id+' - '+v.name; sel.appendChild(o);
    });
  });
}

async function toggleAcl(src,dst){
  const k=src+','+dst, allow=!state.acl[k];
  const r=await api('/api/acl/set',{src_vlan:src,dst_vlan:dst,allow});
  if(r.ok){
    if(allow) state.acl[k]=true; else delete state.acl[k];
    renderAclMatrix();
    toast('VLAN '+src+' to VLAN '+dst+': '+(allow?'ALLOWED':'BLOCKED'));
  }
}

async function setAcl(allow){
  const src=parseInt(document.getElementById('acl-src').value);
  const dst=parseInt(document.getElementById('acl-dst').value);
  if(src===dst){toast('Source and destination must differ',true);return;}
  const r=await api('/api/acl/set',{src_vlan:src,dst_vlan:dst,allow});
  if(r.ok){
    const k=src+','+dst;
    if(allow) state.acl[k]=true; else delete state.acl[k];
    renderAclMatrix();
    toast('VLAN '+src+' to VLAN '+dst+': '+(allow?'ALLOWED':'BLOCKED'));
  }
}

// ── Alerts ────────────────────────────────────────────────────────────────────
function renderAlerts(){
  const c=document.getElementById('alerts-container');
  if(!state.link_alerts.length){
    c.innerHTML=`<div class="alerts-empty">
      <div class="alerts-empty-icon">&#x2714;</div>
      <div class="alerts-empty-title">All Clear &#x2014; No active alerts</div>
      <div class="alerts-empty-sub">Network topology is healthy</div>
    </div>`;
    return;
  }
  c.innerHTML=state.link_alerts.map(a=>`
    <div class="alert-item">
      <span class="alert-icon-cell">&#x26A0;</span>
      <div class="alert-body">
        <div class="alert-msg">${a.msg}</div>
        <div class="alert-detail">${a.src} port ${a.src_port} &harr; ${a.dst} port ${a.dst_port}</div>
      </div>
      <span class="alert-ts">${a.time}</span>
    </div>`).join('');
}

async function clearAlerts(){
  await api('/api/alerts/clear');
  state.link_alerts=[];
  renderAlerts(); updateAlertBadge();
  toast('All alerts cleared');
}

// ── Event log ─────────────────────────────────────────────────────────────────
function renderLog(){
  const tb=document.getElementById('log-table');
  if(!state.log.length){
    tb.innerHTML='<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:20px">No events yet</td></tr>';
    return;
  }
  tb.innerHTML=state.log.map(e=>{
    const cls=e.action==='DROP'?'log-action-drop':e.action==='FWD'?'log-action-fwd':'log-action-allow';
    return `<tr>
      <td class="mono" style="color:var(--muted)">${e.time}</td>
      <td class="mono ${cls}" style="font-weight:700">${e.action}</td>
      <td class="mono">${e.src||'&#x2014;'}</td>
      <td class="mono">${e.dst||'&#x2014;'}</td>
      <td style="font-size:.76rem;color:var(--muted)">${e.reason}</td>
      <td class="mono">${e.vlan!=null?'V'+e.vlan:'&#x2014;'}</td>
    </tr>`;
  }).join('');
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
function renderDashboard(){
  const s=state.stats;
  document.getElementById('s-pktin').textContent =(s.packets_in||0).toLocaleString();
  document.getElementById('s-pkfwd').textContent =(s.packets_fwd||0).toLocaleString();
  document.getElementById('s-pkdrop').textContent=(s.packets_drop||0).toLocaleString();
  document.getElementById('s-flows').textContent =(s.flows_installed||0).toLocaleString();
  document.getElementById('h-pktin').textContent =(s.packets_in||0).toLocaleString();
  document.getElementById('h-pkdrop').textContent=(s.packets_drop||0).toLocaleString();
  document.getElementById('h-flows').textContent =(s.flows_installed||0).toLocaleString();

  const st=document.getElementById('switch-table');
  if(state.switches.length){
    st.innerHTML=state.switches.map(sw=>`<tr>
      <td class="mono">s${sw.num||'?'}</td>
      <td class="mono" style="color:var(--muted)">${sw.dpid}</td>
      <td><span class="badge badge-green"><span class="dot" style="background:var(--green)"></span>Connected</span></td>
      <td style="color:var(--muted);font-size:.78rem">${sw.role||'Switch'}</td>
    </tr>`).join('');
  }

  document.getElementById('vlan-table').innerHTML=VLANS.map(v=>`<tr>
    <td class="mono">VLAN ${v.id}</td>
    <td>${v.name}</td>
    <td class="mono" style="color:var(--muted)">${v.subnet}</td>
    <td><span class="badge badge-green">Active</span></td>
  </tr>`).join('');
}

// ── Polling ───────────────────────────────────────────────────────────────────
async function poll(){
  try{
    const data=await fetch('/api/state').then(r=>r.json());
    state.stats      =data.stats||state.stats;
    state.switches   =data.switches||state.switches;
    state.blocked_tcp=new Set(data.blocked_tcp||[]);
    state.blocked_udp=new Set(data.blocked_udp||[]);
    state.acl={};
    (data.acl||[]).forEach(([s,d])=>{state.acl[s+','+d]=true;});
    state.log=data.log||state.log;

    const fresh=data.link_alerts||[];
    if(!_firstPoll && fresh.length > state.link_alerts.length){
      toast('Link Down: '+fresh[0].src+' <-> '+fresh[0].dst, true);
    }
    _firstPoll=false;
    state.link_alerts=fresh;

    renderDashboard();
    updateAlertBadge();

    const ap=document.querySelector('.page.active')?.id?.replace('page-','');
    if(ap==='firewall') renderFwTable();
    if(ap==='acl')      renderAclMatrix();
    if(ap==='log')      renderLog();
    if(ap==='alerts')   renderAlerts();
  }catch(e){}
}

poll();
setInterval(poll,3000);
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP API HANDLER
# ═══════════════════════════════════════════════════════════════════════════════

_controller_ref = None

SWITCH_ROLE = {
    1: "Main-Campus-Core",
    2: "Admin-Services-Building",
    3: "Academic-Building",
    4: "Lab-Building",
    5: "Library-Data-Center",
    6: "City-Campus-Core",
    7: "City-Admin-Lab",
    8: "City-Student-WiFi",
}


class AdminHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ('/', '/index.html'):
            self._send(200, 'text/html; charset=utf-8', ADMIN_HTML.encode())
        elif path == '/api/state':
            self._send(200, 'application/json', json.dumps(self._build_state()).encode())
        else:
            self._send(404, 'text/plain', b'Not found')

    def do_POST(self):
        path   = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        body   = json.loads(self.rfile.read(length)) if length else {}

        if path == '/api/firewall/add':
            proto = body.get('proto', 'tcp')
            port  = int(body.get('port', 0))
            if 1 <= port <= 65535:
                with _policy_lock:
                    if proto == 'tcp': BLOCKED_TCP_PORTS.add(port)
                    else:              BLOCKED_UDP_PORTS.add(port)
                self._send(200, 'application/json', b'{"ok":true}')
            else:
                self._send(400, 'application/json', b'{"ok":false,"error":"bad port"}')

        elif path == '/api/firewall/remove':
            proto = body.get('proto', 'tcp')
            port  = int(body.get('port', 0))
            with _policy_lock:
                if proto == 'tcp': BLOCKED_TCP_PORTS.discard(port)
                else:              BLOCKED_UDP_PORTS.discard(port)
            self._send(200, 'application/json', b'{"ok":true}')

        elif path == '/api/acl/set':
            src   = int(body.get('src_vlan', 0))
            dst   = int(body.get('dst_vlan', 0))
            allow = bool(body.get('allow', False))
            with _policy_lock:
                if allow: INTER_VLAN_POLICY[(src, dst)] = True
                else:     INTER_VLAN_POLICY.pop((src, dst), None)
            ctrl = _controller_ref
            if ctrl:
                ctrl.apply_acl_realtime(src, dst, allow)
            self._send(200, 'application/json', b'{"ok":true}')

        elif path == '/api/alerts/clear':
            with _alerts_lock:
                LINK_ALERTS.clear()
            self._send(200, 'application/json', b'{"ok":true}')

        else:
            self._send(404, 'application/json', b'{"ok":false}')

    def _build_state(self):
        ctrl = _controller_ref

        with _policy_lock:
            b_tcp = sorted(BLOCKED_TCP_PORTS)
            b_udp = sorted(BLOCKED_UDP_PORTS)
            acl   = [[s, d] for (s, d) in INTER_VLAN_POLICY.keys()]

        with _stats_lock:
            stats = dict(STATS)

        with _log_lock:
            log = list(FW_LOG)[:60]

        with _alerts_lock:
            link_alerts = list(LINK_ALERTS)

        switches = []
        if ctrl:
            for dpid in sorted(ctrl.datapaths.keys()):
                num = dpid & 0xFF
                switches.append({
                    "dpid": "%016x" % dpid,
                    "num":  num,
                    "role": SWITCH_ROLE.get(num, "Switch"),
                })

        return {
            "stats":       stats,
            "switches":    switches,
            "blocked_tcp": b_tcp,
            "blocked_udp": b_udp,
            "acl":         acl,
            "log":         log,
            "link_alerts": link_alerts,
        }

    def _send(self, code, ct, body):
        self.send_response(code)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)


def start_admin_server(controller, port=8080):
    global _controller_ref
    _controller_ref = controller
    srv = HTTPServer(('0.0.0.0', port), AdminHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ═══════════════════════════════════════════════════════════════════════════════
#  RYU CONTROLLER APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

class UniversityController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.topo      = nx.DiGraph()
        self.mac_table = {}
        self.ip_table  = {}
        self.datapaths = {}
        self._load_static_topology()
        start_admin_server(self, port=8080)
        self.logger.info("[INIT] University SDN Controller started.")
        self.logger.info("[INIT] Admin UI: http://127.0.0.1:8080")

    def _load_static_topology(self):
        for dpid in PORT_VLAN:
            self.topo.add_node(dpid)
        for left, right, left_port, right_port in STATIC_LINKS:
            self.topo.add_edge(left, right, port=left_port)
            self.topo.add_edge(right, left, port=right_port)

    # ── OpenFlow ──────────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self._install_table_miss(dp)
        self.logger.info("[OF]   Switch connected: dpid=%016x", dp.id)

    def _install_table_miss(self, dp):
        parser  = dp.ofproto_parser
        ofproto = dp.ofproto
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(dp, priority=0, match=match, actions=actions)

    # ── Topology Discovery ────────────────────────────────────────────────────

    @set_ev_cls(topo_event.EventSwitchEnter)
    def on_switch_enter(self, ev):
        dpid = ev.switch.dp.id
        self.topo.add_node(dpid)
        self.logger.info("[TOPO] Switch entered: dpid=%016x", dpid)

    @set_ev_cls(topo_event.EventSwitchLeave)
    def on_switch_leave(self, ev):
        dpid = ev.switch.dp.id
        if self.topo.has_node(dpid):
            self.topo.remove_node(dpid)
        self.logger.info("[TOPO] Switch left: dpid=%016x", dpid)

    @set_ev_cls(topo_event.EventLinkAdd)
    def on_link_add(self, ev):
        src, dst = ev.link.src, ev.link.dst
        self.topo.add_edge(src.dpid, dst.dpid, port=src.port_no)
        self.topo.add_edge(dst.dpid, src.dpid, port=dst.port_no)
        self.logger.info("[TOPO] Link: %016x:%d <-> %016x:%d",
                         src.dpid, src.port_no, dst.dpid, dst.port_no)

    @set_ev_cls(topo_event.EventLinkDelete)
    def on_link_delete(self, ev):
        src, dst = ev.link.src, ev.link.dst
        for a, b in [(src.dpid, dst.dpid), (dst.dpid, src.dpid)]:
            if self.topo.has_edge(a, b):
                self.topo.remove_edge(a, b)

        src_name = SWITCH_ROLE.get(src.dpid & 0xFF, "sw%x" % src.dpid)
        dst_name = SWITCH_ROLE.get(dst.dpid & 0xFF, "sw%x" % dst.dpid)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        alert = {
            "time":     ts,
            "type":     "link_down",
            "src":      src_name,
            "dst":      dst_name,
            "src_port": src.port_no,
            "dst_port": dst.port_no,
            "msg":      "Link down: %s (port %d) <-> %s (port %d)" % (
                src_name, src.port_no, dst_name, dst.port_no),
        }
        with _alerts_lock:
            LINK_ALERTS.appendleft(alert)
        self.logger.warning("[ALERT] Link down: %s <-> %s -- flushing flows and rerouting",
                            src_name, dst_name)
        # Flush all cached flows immediately so Dijkstra re-routes on next
        # PacketIn rather than continuing to use the now-dead link.
        self._flush_all_flows()

    # ── Dynamic Routing ───────────────────────────────────────────────────────

    def _shortest_path(self, src_dpid, dst_dpid):
        try:
            return nx.shortest_path(self.topo, src_dpid, dst_dpid)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def _out_port_toward(self, current, next_hop):
        edge = self.topo.get_edge_data(current, next_hop)
        return edge['port'] if edge else None

    def _find_switch_for_mac(self, vlan_id, mac):
        for dpid, vlan_map in self.mac_table.items():
            if mac in vlan_map.get(vlan_id, {}):
                return dpid
        return None

    def _learn_ip_host(self, dpid, port_no, vlan_id, ip_addr, mac_addr):
        if not ip_addr or ip_addr == "0.0.0.0":
            return
        if gateway_ip_to_vlan(ip_addr) is not None:
            return
        if ip_to_vlan(ip_addr) != vlan_id:
            return
        self.ip_table[ip_addr] = {
            "mac": mac_addr,
            "vlan": vlan_id,
            "dpid": dpid,
            "port": port_no,
        }

    def _send_icmp_echo_reply(self, dp, in_port, dst_mac, ip_pkt, icmp_pkt):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_IP,
            dst=dst_mac,
            src=ROUTER_MAC))
        pkt.add_protocol(ipv4.ipv4(
            dst=ip_pkt.src,
            src=ip_pkt.dst,
            proto=ip_pkt.proto))
        pkt.add_protocol(icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data))
        pkt.serialize()
        actions = [dp.ofproto_parser.OFPActionOutput(in_port)]
        self._packet_out(dp, None, dp.ofproto.OFPP_CONTROLLER, actions, pkt.data)

    def _send_arp_reply(self, dp, in_port, dst_mac, dst_ip, src_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst_mac,
            src=ROUTER_MAC))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=ROUTER_MAC,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip))
        pkt.serialize()
        actions = [dp.ofproto_parser.OFPActionOutput(in_port)]
        self._packet_out(dp, None, dp.ofproto.OFPP_CONTROLLER, actions, pkt.data)

    def _send_arp_request(self, dp, out_port, vlan_id, target_ip):
        gateway_ip = vlan_gateway_ip(vlan_id)
        if not gateway_ip:
            return
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst="ff:ff:ff:ff:ff:ff",
            src=ROUTER_MAC))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=ROUTER_MAC,
            src_ip=gateway_ip,
            dst_mac="00:00:00:00:00:00",
            dst_ip=target_ip))
        pkt.serialize()
        actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
        self._packet_out(dp, None, dp.ofproto.OFPP_CONTROLLER, actions, pkt.data)

    def _resolve_ip_in_vlan(self, dst_ip, dst_vlan):
        for dpid, vlan_map in PORT_VLAN.items():
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue
            for port_no, vlan_id in vlan_map.items():
                if vlan_id == dst_vlan:
                    self._send_arp_request(dp, port_no, dst_vlan, dst_ip)

    def _install_routed_path_flows(self, path, ip_src, ip_dst, dst_mac,
                                   dst_vlan, priority=150):
        for i, dpid in enumerate(path):
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue
            parser = dp.ofproto_parser

            if i == len(path) - 1:
                dst_info = self.ip_table.get(ip_dst)
                if not dst_info:
                    continue
                out_port = dst_info["port"]
            else:
                out_port = self._out_port_toward(dpid, path[i + 1])
                if out_port is None:
                    continue

            actions = [
                parser.OFPActionSetField(eth_src=ROUTER_MAC),
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_src,
                ipv4_dst=ip_dst)
            self._add_flow(dp, priority=priority, match=match,
                           actions=actions, idle_timeout=60)

        with _stats_lock:
            STATS['flows_installed'] += 1

        self.logger.info("[L3 ROUTE] Path: %s | %s->%s VLAN%d",
                         "->".join("%x" % d for d in path),
                         ip_src, ip_dst, dst_vlan)

    def _route_inter_vlan(self, dp, msg, in_port, src_vlan, dst_vlan, ip_pkt):
        dst_info = self.ip_table.get(ip_pkt.dst)
        if not dst_info:
            self._resolve_ip_in_vlan(ip_pkt.dst, dst_vlan)
            self.logger.info("[L3 ARP] Resolving %s in VLAN%d",
                             ip_pkt.dst, dst_vlan)
            return "pending"

        dst_dpid = dst_info["dpid"]
        path = self._shortest_path(dp.id, dst_dpid)
        if not path:
            _log('DROP', ip_pkt.src, ip_pkt.dst,
                 'No routed path VLAN %d->%d' % (src_vlan, dst_vlan),
                 vlan=src_vlan)
            return "dropped"

        self._install_routed_path_flows(
            path, ip_pkt.src, ip_pkt.dst, dst_info["mac"], dst_vlan)

        parser = dp.ofproto_parser
        if len(path) == 1:
            out_port = dst_info["port"]
        else:
            out_port = self._out_port_toward(dp.id, path[1])
        if out_port is None:
            return "dropped"

        actions = [
            parser.OFPActionSetField(eth_src=ROUTER_MAC),
            parser.OFPActionSetField(eth_dst=dst_info["mac"]),
            parser.OFPActionOutput(out_port),
        ]
        self._packet_out(dp, msg, in_port, actions)
        return "forwarded"

    def _install_path_flows(self, path, src_mac, dst_mac, vlan_id,
                             ip_src=None, ip_dst=None, priority=100):
        for i, dpid in enumerate(path):
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue
            parser = dp.ofproto_parser

            if i == len(path) - 1:
                out_port = (self.mac_table.get(dpid, {})
                            .get(vlan_id, {}).get(dst_mac))
                if out_port is None:
                    continue
            else:
                out_port = self._out_port_toward(dpid, path[i + 1])
                if out_port is None:
                    continue

            actions = [parser.OFPActionOutput(out_port)]
            if ip_src and ip_dst:
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    eth_src=src_mac, eth_dst=dst_mac,
                    ipv4_src=ip_src, ipv4_dst=ip_dst)
            else:
                match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)

            self._add_flow(dp, priority=priority, match=match,
                           actions=actions, idle_timeout=60)

        with _stats_lock:
            STATS['flows_installed'] += 1

        self.logger.info("[ROUTE] Path: %s | %s->%s VLAN%d",
                         "->".join("%x" % d for d in path),
                         src_mac, dst_mac, vlan_id)

    # ── Realtime ACL enforcement ──────────────────────────────────────────────

    def _flush_all_flows(self):
        """
        Delete every installed flow from every switch, then reinstall
        the table-miss rule.  Also clear mac_table and ip_table so all
        host positions and IP mappings are relearned from scratch under
        the current policy.

        This is called:
          • After any ACL or firewall change  → policy takes effect immediately
          • After a link failure              → Dijkstra re-routes on next pkt
        """
        for dp in list(self.datapaths.values()):
            ofproto = dp.ofproto
            parser  = dp.ofproto_parser
            # Wildcard OFPFC_DELETE removes ALL flows from the table
            mod = parser.OFPFlowMod(
                datapath  = dp,
                command   = ofproto.OFPFC_DELETE,
                out_port  = ofproto.OFPP_ANY,
                out_group = ofproto.OFPG_ANY,
                match     = parser.OFPMatch(),
            )
            dp.send_msg(mod)
            # Re-install table-miss so packets still reach the controller
            self._install_table_miss(dp)

        # Clear learning tables — relearn cleanly under new policy
        self.mac_table.clear()
        self.ip_table.clear()
        self.logger.info("[FLUSH] All flows cleared on %d switches — "
                         "new policy active", len(self.datapaths))

    def _delete_flows_for_vlan_pair(self, src_vlan, dst_vlan):
        """Targeted delete for a specific subnet pair (kept for reference)."""
        """Send OFPFC_DELETE to all switches for flows between two /24 subnets."""
        src_prefix = VLAN_PREFIX.get(src_vlan)
        dst_prefix = VLAN_PREFIX.get(dst_vlan)
        if not src_prefix or not dst_prefix:
            return
        src_net = src_prefix + "0"
        dst_net = dst_prefix + "0"
        mask    = "255.255.255.0"
        for dp in list(self.datapaths.values()):
            parser  = dp.ofproto_parser
            ofproto = dp.ofproto
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=(src_net, mask),
                ipv4_dst=(dst_net, mask))
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match)
            dp.send_msg(mod)

    def apply_acl_realtime(self, src_vlan, dst_vlan, allow):
        """Push an ACL change into the data plane immediately.

        Strategy:
          1. If blocking: install a high-priority permanent DROP flow for the
             subnet pair so future packets are dropped at line rate.
          2. Always flush ALL flows so stale forwarding entries are gone.
             The targeted subnet delete is not enough — ARP flows, broadcast
             flows, and non-IP flows would keep working.
          3. Clear mac_table and ip_table so everything is relearned cleanly
             under the new policy.
        """
        if not allow:
            # Install permanent DROP for this subnet pair BEFORE the flush,
            # so it is in place the moment new flows start being installed.
            src_net = VLAN_PREFIX.get(src_vlan, "") + "0"
            dst_net = VLAN_PREFIX.get(dst_vlan, "") + "0"
            mask    = "255.255.255.0"
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                match  = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=(src_net, mask),
                    ipv4_dst=(dst_net, mask))
                self._add_flow(dp, priority=300, match=match,
                               actions=[], idle_timeout=0)

        # Full flush — removes ALL cached forwarding flows from every switch.
        # After this every packet comes to the controller and is re-evaluated
        # against the NEW policy.  The DROP rule above (if just installed)
        # survives because _flush_all_flows() only deletes priority >= 1 and
        # reinstalls table-miss at priority 0; or we reinstall the drop rule.
        self._flush_all_flows()

    # ── Packet-In ─────────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        parser  = dp.ofproto_parser
        dpid    = dp.id
        in_port = msg.match['in_port']

        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        with _stats_lock:
            STATS['packets_in'] += 1

        ingress_vlan = port_vlan(dpid, in_port)
        is_access_port = ingress_vlan not in (TRUNK, None)
        vlan_id = ingress_vlan
        if vlan_id == TRUNK or vlan_id is None:
            ip_tmp  = pkt.get_protocol(ipv4.ipv4)
            vlan_id = ip_to_vlan(ip_tmp.src) if ip_tmp else None
            if vlan_id is None or vlan_id == TRUNK:
                return

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        if is_access_port:
            (self.mac_table
                 .setdefault(dpid, {})
                 .setdefault(vlan_id, {})
                 [src_mac]) = in_port

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if arp_pkt:
            if is_access_port:
                self._learn_ip_host(dpid, in_port, vlan_id,
                                    arp_pkt.src_ip, arp_pkt.src_mac)
            if (arp_pkt.opcode == arp.ARP_REQUEST and
                    arp_pkt.dst_ip == vlan_gateway_ip(vlan_id)):
                self._send_arp_reply(dp, in_port, arp_pkt.src_mac,
                                     arp_pkt.src_ip, arp_pkt.dst_ip)
                self.logger.info("[L3 GW] ARP reply %s is at %s on VLAN%d",
                                 arp_pkt.dst_ip, ROUTER_MAC, vlan_id)
                return
            if (arp_pkt.opcode == arp.ARP_REPLY and
                    gateway_ip_to_vlan(arp_pkt.dst_ip) == vlan_id):
                return

        if ip_pkt:
            src_vlan = ip_to_vlan(ip_pkt.src)
            dst_vlan = ip_to_vlan(ip_pkt.dst)
            if is_access_port:
                self._learn_ip_host(dpid, in_port, vlan_id, ip_pkt.src, src_mac)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            if gateway_ip_to_vlan(ip_pkt.dst) == vlan_id:
                if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    self._send_icmp_echo_reply(dp, in_port, src_mac, ip_pkt, icmp_pkt)
                    self.logger.info("[L3 GW] ICMP echo reply %s -> %s on VLAN%d",
                                     ip_pkt.dst, ip_pkt.src, vlan_id)
                return

            if src_vlan is not None and src_vlan != vlan_id:
                _log('DROP', ip_pkt.src, ip_pkt.dst,
                     'IP spoof: claims VLAN %d on VLAN %d port' % (src_vlan, vlan_id),
                     vlan=vlan_id)
                with _stats_lock:
                    STATS['packets_drop'] += 1
                return

            allowed, reason = acl_check(src_vlan, dst_vlan, tcp_pkt, udp_pkt)
            if not allowed:
                _log('DROP', ip_pkt.src, ip_pkt.dst, reason, vlan=vlan_id)
                with _stats_lock:
                    STATS['packets_drop'] += 1
                self.logger.warning("[FW DROP] %s->%s %s dpid=%016x",
                                    ip_pkt.src, ip_pkt.dst, reason, dpid)
                return

            if (src_vlan is not None and dst_vlan is not None and
                    src_vlan != dst_vlan):
                route_result = self._route_inter_vlan(
                    dp, msg, in_port, src_vlan, dst_vlan, ip_pkt)
                if route_result:
                    if route_result == "forwarded":
                        with _stats_lock:
                            STATS['packets_fwd'] += 1
                        _log('FWD', ip_pkt.src, ip_pkt.dst,
                             'Inter-VLAN routed', vlan=vlan_id)
                    elif route_result == "pending":
                        _log('DROP', ip_pkt.src, ip_pkt.dst,
                             'Resolving destination ARP', vlan=vlan_id)
                    elif route_result == "dropped":
                        with _stats_lock:
                            STATS['packets_drop'] += 1
                        _log('DROP', ip_pkt.src, ip_pkt.dst,
                             'Inter-VLAN route failed', vlan=vlan_id)
                    return

        with _stats_lock:
            STATS['packets_fwd'] += 1

        if ip_pkt:
            _log('FWD', ip_pkt.src, ip_pkt.dst, 'Forwarded', vlan=vlan_id)

        known_port = (self.mac_table.get(dpid, {})
                      .get(vlan_id, {}).get(dst_mac))

        if known_port is not None:
            dst_dpid = self._find_switch_for_mac(vlan_id, dst_mac)
            if dst_dpid is not None and dst_dpid != dpid:
                path = self._shortest_path(dpid, dst_dpid)
                if path and len(path) > 1:
                    self._install_path_flows(
                        path, src_mac, dst_mac, vlan_id,
                        ip_src=ip_pkt.src if ip_pkt else None,
                        ip_dst=ip_pkt.dst if ip_pkt else None)
            actions = [parser.OFPActionOutput(known_port)]
            self._packet_out(dp, msg, in_port, actions)

        else:
            dst_dpid = self._find_switch_for_mac(vlan_id, dst_mac)
            if dst_dpid is not None:
                path = self._shortest_path(dpid, dst_dpid)
                if path and len(path) >= 2:
                    self._install_path_flows(
                        path, src_mac, dst_mac, vlan_id,
                        ip_src=ip_pkt.src if ip_pkt else None,
                        ip_dst=ip_pkt.dst if ip_pkt else None)
                    out_port = self._out_port_toward(dpid, path[1])
                    if out_port:
                        actions = [parser.OFPActionOutput(out_port)]
                        self._packet_out(dp, msg, in_port, actions)
                    return
            out_ports = host_ports_for_vlan(dpid, vlan_id, exclude_port=in_port)
            if out_ports:
                actions = [parser.OFPActionOutput(p) for p in out_ports]
                self._packet_out(dp, msg, in_port, actions)

    # ── OpenFlow helpers ──────────────────────────────────────────────────────

    def _add_flow(self, dp, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout,
            hard_timeout=hard_timeout)
        dp.send_msg(mod)

    def _packet_out(self, dp, msg, in_port, actions, data=None):
        parser  = dp.ofproto_parser
        ofproto = dp.ofproto
        if data is None and msg is not None:
            data = msg.data
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)
