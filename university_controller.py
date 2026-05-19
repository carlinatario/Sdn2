#!/usr/bin/env python3
"""
University Campus SDN Controller — Ryu (OpenFlow 1.3)
=======================================================
Features:
  1. Topology Discovery   — LLDP auto-detects switches and links
  2. Dynamic Routing      — Dijkstra shortest-path, auto-reroutes on failure
  3. VLAN Segmentation    — 8 VLANs across two campuses
  4. Firewall / ACL       — inter-VLAN policy + blocked TCP/UDP ports
  5. QoS                  — flow priority per VLAN
  6. Admin Web UI         — live dashboard at http://127.0.0.1:8080
                            Manage firewall rules, ACL policy, QoS, view logs

Run:
  ryu-manager --observe-links university_controller.py
Then open: http://127.0.0.1:8080
"""

import json
import threading
import datetime
from collections import deque
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (MAIN_DISPATCHER, CONFIG_DISPATCHER,
                                     set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import (packet, ethernet, ipv4, tcp, udp, ether_types)
from ryu.topology import event as topo_event


# ═══════════════════════════════════════════════════════════════════════════════
#  LIVE POLICY STATE  (these are mutated at runtime by the Admin UI)
#  All access is protected by _policy_lock to allow safe concurrent updates.
# ═══════════════════════════════════════════════════════════════════════════════

_policy_lock = threading.Lock()

# VLAN name labels (display only)
VLAN_NAMES = {
    10: "Admin Office A",
    20: "HOD & Staff",
    30: "Computer Lab A",
    40: "Student WiFi A",
    50: "Library",
    60: "Admin Office B",
    70: "Computer Lab B",
    80: "Student WiFi B",
}

# VLAN → IP subnet prefix
VLAN_PREFIX = {
    10: "10.0.10.",
    20: "10.0.20.",
    30: "10.0.30.",
    40: "10.0.40.",
    50: "10.0.50.",
    60: "10.0.60.",
    70: "10.0.70.",
    80: "10.0.80.",
}

TRUNK = 0

PORT_VLAN = {
    1:  {1:TRUNK,2:TRUNK,3:TRUNK,4:TRUNK,8:TRUNK,9:TRUNK},
    2:  {1:TRUNK,2:TRUNK,3:TRUNK,4:TRUNK,8:TRUNK,9:TRUNK},
    3:  {1:TRUNK,2:TRUNK,3:TRUNK},
    4:  {1:TRUNK,2:TRUNK,3:TRUNK,4:TRUNK},
    5:  {1:TRUNK,2:TRUNK,3:TRUNK},
    6:  {1:TRUNK,2:TRUNK,3:TRUNK},
    7:  {1:TRUNK,2:10,3:10},
    8:  {1:TRUNK,2:20,3:20},
    9:  {1:TRUNK,2:30,3:30,4:30,5:30},
    10: {1:TRUNK,2:40,3:40},
    11: {1:TRUNK,2:50,3:50},
    12: {1:TRUNK,2:TRUNK,8:TRUNK,9:TRUNK},
    13: {1:TRUNK,2:TRUNK,8:TRUNK,9:TRUNK},
    14: {1:TRUNK,2:60},
    15: {1:TRUNK,2:TRUNK,3:70,4:70},
    16: {1:TRUNK,2:80},
}

# QoS — mutable at runtime
VLAN_PRIORITY = {
    10: 400,
    60: 380,
    20: 300,
    50: 200,
    30: 150,
    70: 130,
    40: 80,
    80: 60,
}

# Firewall port block lists — mutable sets
BLOCKED_TCP_PORTS = {23, 135, 139, 445}
BLOCKED_UDP_PORTS = {161, 162}

# Inter-VLAN ACL — mutable dict: (src, dst) → True=allow
INTER_VLAN_POLICY = {
    (10, 20): True,
    (10, 30): True,
    (10, 40): True,
    (10, 50): True,
    (10, 60): True,
    (10, 70): True,
    (10, 80): True,
    (20, 30): True,
    (20, 50): True,
    (50, 20): True,
    (60, 10): True,
    (60, 70): True,
    (60, 80): True,
    (20, 70): True,
}

# Firewall log — ring buffer, last 200 events
FW_LOG = deque(maxlen=200)
_log_lock = threading.Lock()

# Network stats counters
STATS = {
    "packets_in":    0,
    "packets_drop":  0,
    "packets_fwd":   0,
    "flows_installed": 0,
}
_stats_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _log(action, src_ip, dst_ip, reason, vlan=None):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    entry = {"time": ts, "action": action, "src": src_ip,
             "dst": dst_ip, "reason": reason, "vlan": vlan}
    with _log_lock:
        FW_LOG.appendleft(entry)


def ip_to_vlan(ip_addr):
    if not ip_addr:
        return None
    for vlan_id, prefix in VLAN_PREFIX.items():
        if ip_addr.startswith(prefix):
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
        b_tcp = set(BLOCKED_TCP_PORTS)
        b_udp = set(BLOCKED_UDP_PORTS)
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
        return True, "ACL allow %d→%d" % (src_vlan, dst_vlan)

    return False, "ACL block %d→%d" % (src_vlan, dst_vlan)


# ═══════════════════════════════════════════════════════════════════════════════
#  ADMIN WEB UI  (runs on port 8080 in a background thread)
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
.nav-icon{font-size:15px;width:18px;text-align:center;}
.nav-sep{height:1px;background:var(--border);margin:8px 4px;}

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
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;
           padding:16px 20px;}
.stat-num{font-family:var(--mono);font-size:1.8rem;font-weight:600;line-height:1;}
.stat-lbl{font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-top:4px;}
.s-blue{color:var(--accent);}
.s-green{color:var(--green);}
.s-red{color:var(--red);}
.s-amber{color:var(--amber);}

/* ── Tables ── */
table{width:100%;border-collapse:collapse;font-size:.82rem;}
th{text-align:left;font-size:.65rem;font-weight:700;letter-spacing:.12em;
   text-transform:uppercase;color:var(--muted);padding:8px 12px;
   border-bottom:1px solid var(--border);}
td{padding:9px 12px;border-bottom:1px solid rgba(37,44,66,.6);}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(255,255,255,.02);}

/* ── Badges ── */
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;
       border-radius:20px;font-size:.72rem;font-weight:600;font-family:var(--mono);}
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
  color:var(--text);padding:7px 11px;font-size:.82rem;font-family:inherit;outline:none;
  transition:border .15s;}
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
.matrix th,.matrix td{padding:5px 8px;text-align:center;border:1px solid var(--border);
                       min-width:52px;}
.matrix th{background:var(--panel2);font-size:.62rem;color:var(--muted);}
.matrix .row-hdr{background:var(--panel2);font-weight:600;color:var(--muted);text-align:left;
                  padding-left:10px;white-space:nowrap;}
.cell-allow{background:rgba(34,197,94,.15);color:var(--green);cursor:pointer;font-weight:700;}
.cell-block{background:rgba(239,68,68,.1);color:rgba(239,68,68,.5);cursor:pointer;}
.cell-self{background:var(--panel2);color:var(--muted);cursor:default;}
.cell-allow:hover{background:rgba(239,68,68,.2);}
.cell-block:hover{background:rgba(34,197,94,.2);}

/* ── QoS sliders ── */
.qos-row{display:flex;align-items:center;gap:14px;margin-bottom:14px;}
.qos-label{width:140px;font-size:.8rem;flex-shrink:0;}
.qos-vlan{font-family:var(--mono);font-size:.7rem;color:var(--muted);width:55px;}
input[type=range]{flex:1;accent-color:var(--accent);cursor:pointer;}
.qos-val{font-family:var(--mono);font-size:.85rem;font-weight:600;color:var(--accent);
         width:38px;text-align:right;}

/* ── Log table ── */
.log-action-allow{color:var(--green);}
.log-action-drop {color:var(--red);}
.log-action-fwd  {color:var(--accent);}
.mono{font-family:var(--mono);font-size:.78rem;}

/* ── Toast ── */
#toast{position:fixed;bottom:24px;right:24px;background:var(--panel);
       border:1px solid var(--green);border-radius:8px;padding:12px 18px;
       font-size:.82rem;color:var(--green);opacity:0;transition:opacity .3s;
       z-index:999;pointer-events:none;}
#toast.show{opacity:1;}

/* ── Responsive ── */
@media(max-width:900px){
  .stat-row{grid-template-columns:1fr 1fr;}
  nav{width:160px;}
}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">⬡</div>
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
  </div>
</header>

<div class="layout">
  <nav>
    <button class="nav-btn active" onclick="showPage('dashboard')" id="nb-dashboard">
      <span class="nav-icon">◈</span> Dashboard
    </button>
    <button class="nav-btn" onclick="showPage('firewall')" id="nb-firewall">
      <span class="nav-icon">⊕</span> Firewall
    </button>
    <button class="nav-btn" onclick="showPage('acl')" id="nb-acl">
      <span class="nav-icon">⊞</span> ACL Policy
    </button>
    <button class="nav-btn" onclick="showPage('qos')" id="nb-qos">
      <span class="nav-icon">≋</span> QoS
    </button>
    <div class="nav-sep"></div>
    <button class="nav-btn" onclick="showPage('log')" id="nb-log">
      <span class="nav-icon">≡</span> Event Log
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
          <thead><tr><th>VLAN</th><th>Name</th><th>Subnet</th><th>QoS Priority</th><th>Status</th></tr></thead>
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
      <p class="page-sub">Click any cell to toggle allow/block for that VLAN pair. Row = source, Column = destination.</p>

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
          <button class="btn btn-success" onclick="setAcl(true)">✔ Allow</button>
          <button class="btn btn-danger"  onclick="setAcl(false)">✖ Block</button>
        </div>
      </div>
    </div>

    <!-- ══ QOS ════════════════════════════════════════════════════════ -->
    <div class="page" id="page-qos">
      <h2>QoS — Flow Priorities</h2>
      <p class="page-sub">Higher priority = packets served first by switches. Range 1–500. Changes apply to new flows immediately.</p>

      <div class="card">
        <div class="card-title">VLAN Priority Settings</div>
        <div id="qos-sliders"></div>
        <button class="btn btn-primary" style="margin-top:6px" onclick="saveQos()">Save Priorities</button>
      </div>

      <div class="card">
        <div class="card-title">Priority Reference</div>
        <table>
          <thead><tr><th>Priority Range</th><th>Meaning</th></tr></thead>
          <tbody>
            <tr><td class="mono">400 – 500</td><td>Critical — management, admin</td></tr>
            <tr><td class="mono">200 – 399</td><td>High — staff, faculty</td></tr>
            <tr><td class="mono">100 – 199</td><td>Normal — labs, library</td></tr>
            <tr><td class="mono">1 – 99</td><td>Low — student WiFi, guests</td></tr>
          </tbody>
        </table>
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
              No events yet — network activity will appear here</td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </main>
</div>

<div id="toast"></div>

<script>
// ── VLAN metadata (mirrors Python VLAN_NAMES + VLAN_PREFIX) ──────────────────
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
  23:  {proto:"tcp",desc:"Telnet"},
  135: {proto:"tcp",desc:"NetBIOS"},
  139: {proto:"tcp",desc:"NetBIOS"},
  445: {proto:"tcp",desc:"SMB"},
  161: {proto:"udp",desc:"SNMP"},
  162: {proto:"udp",desc:"SNMP trap"},
};

// Local state (mirrors server, optimistic UI)
let state = {
  stats: {packets_in:0, packets_drop:0, packets_fwd:0, flows_installed:0},
  switches: [],
  blocked_tcp: new Set(),
  blocked_udp: new Set(),
  acl: {},
  qos: {},
  log: [],
};

// ── Page navigation ───────────────────────────────────────────────────────────
function showPage(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  document.getElementById('nb-'+name).classList.add('active');
  if(name==='acl') renderAclMatrix();
  if(name==='qos') renderQosSliders();
  if(name==='firewall') renderFwTable();
  if(name==='log') renderLog();
}

// ── Toast notification ────────────────────────────────────────────────────────
function toast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2200);
}

// ── API calls ─────────────────────────────────────────────────────────────────
async function api(path, body=null){
  const opts = body ? {method:'POST',headers:{'Content-Type':'application/json'},
                       body:JSON.stringify(body)} : {};
  const r = await fetch(path, opts);
  return r.json();
}

// ── Firewall ──────────────────────────────────────────────────────────────────
function renderFwTable(){
  const tb = document.getElementById('fw-rules-table');
  const rows = [];

  state.blocked_tcp.forEach(port=>{
    const desc = FW_DEFAULTS[port]?.desc || '';
    rows.push(`<tr>
      <td><span class="badge badge-blue">TCP</span></td>
      <td class="mono">${port}</td>
      <td style="color:var(--muted)">${desc}</td>
      <td><button class="btn btn-success btn-sm" onclick="removeFwRule('tcp',${port})">Unblock</button></td>
    </tr>`);
  });
  state.blocked_udp.forEach(port=>{
    const desc = FW_DEFAULTS[port]?.desc || '';
    rows.push(`<tr>
      <td><span class="badge badge-amber">UDP</span></td>
      <td class="mono">${port}</td>
      <td style="color:var(--muted)">${desc}</td>
      <td><button class="btn btn-success btn-sm" onclick="removeFwRule('udp',${port})">Unblock</button></td>
    </tr>`);
  });

  tb.innerHTML = rows.length ? rows.join('') :
    `<tr><td colspan="4" style="color:var(--muted);text-align:center">No blocked ports</td></tr>`;
}

async function addFwRule(){
  const proto = document.getElementById('fw-proto').value;
  const port  = parseInt(document.getElementById('fw-port').value);
  if(!port || port<1 || port>65535){ toast('Enter a valid port (1–65535)'); return; }

  const r = await api('/api/firewall/add', {proto, port});
  if(r.ok){
    if(proto==='tcp') state.blocked_tcp.add(port);
    else              state.blocked_udp.add(port);
    renderFwTable();
    toast('Port ' + port + ' (' + proto.toUpperCase() + ') blocked');
    document.getElementById('fw-port').value='';
    document.getElementById('fw-desc').value='';
  }
}

async function removeFwRule(proto, port){
  const r = await api('/api/firewall/remove', {proto, port});
  if(r.ok){
    if(proto==='tcp') state.blocked_tcp.delete(port);
    else              state.blocked_udp.delete(port);
    renderFwTable();
    toast('Port ' + port + ' (' + proto.toUpperCase() + ') unblocked');
  }
}

// ── ACL Matrix ────────────────────────────────────────────────────────────────
function renderAclMatrix(){
  const tbl = document.getElementById('acl-matrix');
  const ids = VLANS.map(v=>v.id);

  let html = '<thead><tr><th>SRC \\ DST</th>';
  VLANS.forEach(v=>{ html+=`<th>V${v.id}</th>`; });
  html += '</tr></thead><tbody>';

  VLANS.forEach(sv=>{
    html += `<tr><td class="row-hdr">VLAN ${sv.id}<br><span style="font-size:.6rem;font-weight:400">${sv.name}</span></td>`;
    VLANS.forEach(dv=>{
      if(sv.id===dv.id){
        html += `<td class="cell-self" title="Same VLAN">—</td>`;
      } else {
        const key = sv.id+','+dv.id;
        const allowed = !!state.acl[key];
        const cls = allowed ? 'cell-allow' : 'cell-block';
        const lbl = allowed ? '✔' : '✖';
        html += `<td class="${cls}" onclick="toggleAcl(${sv.id},${dv.id})" title="VLAN ${sv.id} → VLAN ${dv.id}: ${allowed?'ALLOW':'BLOCK'}">${lbl}</td>`;
      }
    });
    html += '</tr>';
  });
  html += '</tbody>';
  tbl.innerHTML = html;

  // Populate quick-action selects
  ['acl-src','acl-dst'].forEach(id=>{
    const sel = document.getElementById(id);
    if(sel.options.length===0){
      VLANS.forEach(v=>{
        const o=document.createElement('option');
        o.value=v.id; o.textContent='VLAN '+v.id+' — '+v.name;
        sel.appendChild(o);
      });
    }
  });
}

async function toggleAcl(src, dst){
  const key = src+','+dst;
  const current = !!state.acl[key];
  const allow = !current;
  const r = await api('/api/acl/set', {src_vlan:src, dst_vlan:dst, allow});
  if(r.ok){
    if(allow) state.acl[key]=true;
    else      delete state.acl[key];
    renderAclMatrix();
    toast('VLAN '+src+' → VLAN '+dst+': '+(allow?'ALLOWED':'BLOCKED'));
  }
}

async function setAcl(allow){
  const src = parseInt(document.getElementById('acl-src').value);
  const dst = parseInt(document.getElementById('acl-dst').value);
  if(src===dst){ toast('Source and destination must differ'); return; }
  const r = await api('/api/acl/set', {src_vlan:src, dst_vlan:dst, allow});
  if(r.ok){
    const key = src+','+dst;
    if(allow) state.acl[key]=true;
    else      delete state.acl[key];
    renderAclMatrix();
    toast('VLAN '+src+' → VLAN '+dst+': '+(allow?'ALLOWED':'BLOCKED'));
  }
}

// ── QoS ───────────────────────────────────────────────────────────────────────
function renderQosSliders(){
  const wrap = document.getElementById('qos-sliders');
  wrap.innerHTML = VLANS.map(v=>{
    const prio = state.qos[v.id] || 100;
    return `<div class="qos-row">
      <span class="qos-label">${v.name}</span>
      <span class="qos-vlan">VLAN ${v.id}</span>
      <input type="range" min="1" max="500" value="${prio}"
             oninput="document.getElementById('qv-${v.id}').textContent=this.value;state.qos[${v.id}]=+this.value">
      <span class="qos-val" id="qv-${v.id}">${prio}</span>
    </div>`;
  }).join('');
}

async function saveQos(){
  const r = await api('/api/qos/set', {priorities: state.qos});
  if(r.ok) toast('QoS priorities saved');
}

// ── Event log ─────────────────────────────────────────────────────────────────
function renderLog(){
  const tb = document.getElementById('log-table');
  if(!state.log.length){
    tb.innerHTML='<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:20px">No events yet</td></tr>';
    return;
  }
  tb.innerHTML = state.log.map(e=>{
    const cls = e.action==='DROP'?'log-action-drop':e.action==='FWD'?'log-action-fwd':'log-action-allow';
    return `<tr>
      <td class="mono" style="color:var(--muted)">${e.time}</td>
      <td class="mono ${cls}" style="font-weight:700">${e.action}</td>
      <td class="mono">${e.src||'—'}</td>
      <td class="mono">${e.dst||'—'}</td>
      <td style="font-size:.76rem;color:var(--muted)">${e.reason}</td>
      <td class="mono">${e.vlan!=null?'V'+e.vlan:'—'}</td>
    </tr>`;
  }).join('');
}

// ── Dashboard tables ──────────────────────────────────────────────────────────
function renderDashboard(){
  // Stats
  const s = state.stats;
  ['pktin','pkfwd','pkdrop','flows'].forEach(k=>{
    const map={pktin:'packets_in',pkfwd:'packets_fwd',pkdrop:'packets_drop',flows:'flows_installed'};
    const el1=document.getElementById('s-'+k);
    const el2=document.getElementById('h-'+k.replace('pk','pk').replace('flows','flows'));
    const val=s[map[k]]||0;
    if(el1)el1.textContent=val.toLocaleString();
  });
  document.getElementById('h-pktin').textContent=(s.packets_in||0).toLocaleString();
  document.getElementById('h-pkdrop').textContent=(s.packets_drop||0).toLocaleString();
  document.getElementById('h-flows').textContent=(s.flows_installed||0).toLocaleString();

  // Switches
  const st = document.getElementById('switch-table');
  if(state.switches.length){
    st.innerHTML = state.switches.map(sw=>`<tr>
      <td class="mono">s${sw.num||'?'}</td>
      <td class="mono" style="color:var(--muted)">${sw.dpid}</td>
      <td><span class="badge badge-green"><span class="dot" style="background:var(--green)"></span>Connected</span></td>
      <td style="color:var(--muted);font-size:.78rem">${sw.role||'Switch'}</td>
    </tr>`).join('');
  }

  // VLAN table
  const vt = document.getElementById('vlan-table');
  vt.innerHTML = VLANS.map(v=>{
    const prio = state.qos[v.id]||VLAN_PRIORITY_DEFAULT[v.id]||100;
    const bar = Math.round(prio/5);
    return `<tr>
      <td class="mono">VLAN ${v.id}</td>
      <td>${v.name}</td>
      <td class="mono" style="color:var(--muted)">${v.subnet}</td>
      <td><span class="mono" style="color:var(--amber)">${prio}</span>
          <span style="display:inline-block;width:${bar}px;height:4px;background:var(--accent);
          border-radius:2px;margin-left:8px;vertical-align:middle;opacity:.7"></span></td>
      <td><span class="badge badge-green">Active</span></td>
    </tr>`;
  }).join('');
}

const VLAN_PRIORITY_DEFAULT = {10:400,60:380,20:300,50:200,30:150,70:130,40:80,80:60};

// ── Polling ───────────────────────────────────────────────────────────────────
async function poll(){
  try{
    const data = await fetch('/api/state').then(r=>r.json());
    // Merge server state
    state.stats    = data.stats || state.stats;
    state.switches = data.switches || state.switches;
    state.blocked_tcp = new Set(data.blocked_tcp || []);
    state.blocked_udp = new Set(data.blocked_udp || []);
    state.acl      = {};
    (data.acl||[]).forEach(([s,d])=>{ state.acl[s+','+d]=true; });
    state.qos      = data.qos || state.qos;
    state.log      = data.log || state.log;

    renderDashboard();
    // Refresh current page's dynamic content
    const activePage = document.querySelector('.page.active')?.id?.replace('page-','');
    if(activePage==='firewall') renderFwTable();
    if(activePage==='acl')      renderAclMatrix();
    if(activePage==='qos')      renderQosSliders();
    if(activePage==='log')      renderLog();
  }catch(e){}
}

// Boot
poll();
setInterval(poll, 3000);
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP API HANDLER
# ═══════════════════════════════════════════════════════════════════════════════

# Reference to the running controller (set after init)
_controller_ref = None

SWITCH_ROLE = {
    1:"Core-A1", 2:"Core-A2", 3:"Admin-Dist", 4:"Acad-Dist",
    5:"Lab-Dist", 6:"Lib-Dist", 7:"Admin-Access", 8:"HOD-Access",
    9:"Lab-Access", 10:"Student-AP", 11:"Library-Access",
    12:"Core-B1", 13:"Core-B2", 14:"B-Admin", 15:"B-Lab", 16:"B-Student-AP",
}


class AdminHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass   # silence HTTP access logs

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ('/', '/index.html'):
            self._send(200, 'text/html', ADMIN_HTML.encode())
        elif path == '/api/state':
            self._send(200, 'application/json', json.dumps(self._build_state()).encode())
        else:
            self._send(404, 'text/plain', b'Not found')

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length)) if length else {}

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
            self._send(200, 'application/json', b'{"ok":true}')

        elif path == '/api/qos/set':
            priorities = body.get('priorities', {})
            with _policy_lock:
                for vlan_id, prio in priorities.items():
                    vid = int(vlan_id)
                    p   = max(1, min(500, int(prio)))
                    VLAN_PRIORITY[vid] = p
            self._send(200, 'application/json', b'{"ok":true}')

        else:
            self._send(404, 'application/json', b'{"ok":false}')

    def _build_state(self):
        """Collect live state from global policy tables and controller."""
        ctrl = _controller_ref

        with _policy_lock:
            b_tcp   = sorted(BLOCKED_TCP_PORTS)
            b_udp   = sorted(BLOCKED_UDP_PORTS)
            acl     = [[s, d] for (s, d) in INTER_VLAN_POLICY.keys()]
            qos     = dict(VLAN_PRIORITY)

        with _stats_lock:
            stats = dict(STATS)

        with _log_lock:
            log = list(FW_LOG)[:60]

        switches = []
        if ctrl:
            for dpid in sorted(ctrl.datapaths.keys()):
                num = dpid & 0xFF
                switches.append({
                    "dpid": "%016x" % dpid,
                    "num": num,
                    "role": SWITCH_ROLE.get(num, "Switch"),
                })

        return {
            "stats": stats,
            "switches": switches,
            "blocked_tcp": b_tcp,
            "blocked_udp": b_udp,
            "acl": acl,
            "qos": qos,
            "log": log,
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
        self.mac_table = {}     # dpid → vlan_id → mac → port
        self.datapaths = {}     # dpid → datapath

        # Start admin web UI
        start_admin_server(self, port=8080)
        self.logger.info("[INIT] University SDN Controller started.")
        self.logger.info("[INIT] Admin UI: http://127.0.0.1:8080")

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
        self.logger.info("[TOPO] Link removed: %016x <-> %016x — rerouting",
                         src.dpid, dst.dpid)

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

        self.logger.info("[ROUTE] Path: %s | %s→%s VLAN%d",
                         "→".join("%x" % d for d in path),
                         src_mac, dst_mac, vlan_id)

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

        # Determine VLAN
        vlan_id = port_vlan(dpid, in_port)
        if vlan_id == TRUNK or vlan_id is None:
            ip_tmp = pkt.get_protocol(ipv4.ipv4)
            vlan_id = ip_to_vlan(ip_tmp.src) if ip_tmp else None
            if vlan_id is None or vlan_id == TRUNK:
                return

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # MAC learning
        (self.mac_table
             .setdefault(dpid, {})
             .setdefault(vlan_id, {})
             [src_mac]) = in_port

        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Firewall / ACL check
        if ip_pkt:
            src_vlan = ip_to_vlan(ip_pkt.src)
            dst_vlan = ip_to_vlan(ip_pkt.dst)

            # Anti-spoofing
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
                self.logger.warning("[FW DROP] %s→%s %s dpid=%016x",
                                    ip_pkt.src, ip_pkt.dst, reason, dpid)
                return

        # Read QoS priority safely
        with _policy_lock:
            flow_priority = VLAN_PRIORITY.get(vlan_id, 50)

        with _stats_lock:
            STATS['packets_fwd'] += 1

        # Log forwarded IP packets
        if ip_pkt:
            _log('FWD', ip_pkt.src, ip_pkt.dst, 'Forwarded', vlan=vlan_id)

        # Forwarding
        known_port = (self.mac_table.get(dpid, {})
                      .get(vlan_id, {}).get(dst_mac))

        if known_port is not None:
            # Try to install full multi-switch path
            dst_dpid = self._find_switch_for_mac(vlan_id, dst_mac)
            if dst_dpid is not None and dst_dpid != dpid:
                path = self._shortest_path(dpid, dst_dpid)
                if path and len(path) > 1:
                    self._install_path_flows(
                        path, src_mac, dst_mac, vlan_id,
                        ip_src=ip_pkt.src if ip_pkt else None,
                        ip_dst=ip_pkt.dst if ip_pkt else None,
                        priority=flow_priority)
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
                        ip_dst=ip_pkt.dst if ip_pkt else None,
                        priority=flow_priority)
                    out_port = self._out_port_toward(dpid, path[1])
                    if out_port:
                        actions = [parser.OFPActionOutput(out_port)]
                        self._packet_out(dp, msg, in_port, actions)
                    return
            # Flood within VLAN
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

    def _packet_out(self, dp, msg, in_port, actions):
        parser  = dp.ofproto_parser
        ofproto = dp.ofproto
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)
