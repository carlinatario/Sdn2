#!/usr/bin/env python3
"""
University Campus SDN Topology — Mininet
Includes a built-in web topology viewer at http://127.0.0.1:9000
Open that URL in your browser after running this file.

Run:
  sudo python3 university_topology.py
  (Ryu must be running: ryu-manager --observe-links university_controller.py)
"""

import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# ── Link presets ───────────────────────────────────────────────────────────────
LAN_BW    = 100
WAN_BW    = 10
WAN_DELAY = "10ms"

# ── Static topology data served to the browser ────────────────────────────────
TOPOLOGY_DATA = {
    "nodes": [
        # Campus A Core
        {"id": "s1",  "label": "Core-A1",        "type": "core",   "campus": "A", "x": 30, "y": 22},
        {"id": "s2",  "label": "Core-A2",        "type": "core",   "campus": "A", "x": 45, "y": 22},
        # Campus A Distribution
        {"id": "s3",  "label": "Admin-Dist",     "type": "dist",   "campus": "A", "x": 10, "y": 40},
        {"id": "s4",  "label": "Acad-Dist",      "type": "dist",   "campus": "A", "x": 25, "y": 40},
        {"id": "s5",  "label": "Lab-Dist",       "type": "dist",   "campus": "A", "x": 40, "y": 40},
        {"id": "s6",  "label": "Lib-Dist",       "type": "dist",   "campus": "A", "x": 55, "y": 40},
        # Campus A Access
        {"id": "s7",  "label": "Admin\nVLAN10",  "type": "access", "campus": "A", "vlan": 10, "x": 10, "y": 57},
        {"id": "s8",  "label": "HOD\nVLAN20",    "type": "access", "campus": "A", "vlan": 20, "x": 22, "y": 57},
        {"id": "s9",  "label": "Lab\nVLAN30",    "type": "access", "campus": "A", "vlan": 30, "x": 40, "y": 57},
        {"id": "s10", "label": "Stu-AP\nVLAN40", "type": "access", "campus": "A", "vlan": 40, "x": 30, "y": 57},
        {"id": "s11", "label": "Lib\nVLAN50",    "type": "access", "campus": "A", "vlan": 50, "x": 55, "y": 57},
        # Campus A Hosts
        {"id": "admin_svr", "label": "Admin\nServer", "type": "server", "campus": "A", "ip": "10.0.10.10", "x": 5,  "y": 74},
        {"id": "admin_pc",  "label": "Admin\nPC",     "type": "host",   "campus": "A", "ip": "10.0.10.11", "x": 13, "y": 74},
        {"id": "hod1",      "label": "HOD1",          "type": "host",   "campus": "A", "ip": "10.0.20.11", "x": 19, "y": 74},
        {"id": "staff1",    "label": "Staff1",        "type": "host",   "campus": "A", "ip": "10.0.20.12", "x": 25, "y": 74},
        {"id": "lab1",      "label": "Lab1",          "type": "host",   "campus": "A", "ip": "10.0.30.11", "x": 35, "y": 74},
        {"id": "lab2",      "label": "Lab2",          "type": "host",   "campus": "A", "ip": "10.0.30.12", "x": 40, "y": 74},
        {"id": "lab3",      "label": "Lab3",          "type": "host",   "campus": "A", "ip": "10.0.30.13", "x": 45, "y": 74},
        {"id": "lab4",      "label": "Lab4",          "type": "host",   "campus": "A", "ip": "10.0.30.14", "x": 50, "y": 74},
        {"id": "student1",  "label": "Stu1",          "type": "host",   "campus": "A", "ip": "10.0.40.11", "x": 28, "y": 74},
        {"id": "student2",  "label": "Stu2",          "type": "host",   "campus": "A", "ip": "10.0.40.12", "x": 33, "y": 74},
        {"id": "lib1",      "label": "Lib1",          "type": "host",   "campus": "A", "ip": "10.0.50.11", "x": 53, "y": 74},
        {"id": "lib2",      "label": "Lib2",          "type": "host",   "campus": "A", "ip": "10.0.50.12", "x": 58, "y": 74},
        # Campus B Core
        {"id": "s12", "label": "Core-B1",        "type": "core",   "campus": "B", "x": 72, "y": 22},
        {"id": "s13", "label": "Core-B2",        "type": "core",   "campus": "B", "x": 85, "y": 22},
        # Campus B Access
        {"id": "s14", "label": "B-Admin\nVLAN60","type": "access", "campus": "B", "vlan": 60, "x": 68, "y": 45},
        {"id": "s15", "label": "B-Lab\nVLAN70",  "type": "access", "campus": "B", "vlan": 70, "x": 80, "y": 45},
        {"id": "s16", "label": "B-Stu\nVLAN80",  "type": "access", "campus": "B", "vlan": 80, "x": 90, "y": 45},
        # Campus B Hosts
        {"id": "b_admin", "label": "B-Admin", "type": "host",   "campus": "B", "ip": "10.0.60.11", "x": 68, "y": 62},
        {"id": "b_lab1",  "label": "B-Lab1",  "type": "host",   "campus": "B", "ip": "10.0.70.11", "x": 77, "y": 62},
        {"id": "b_lab2",  "label": "B-Lab2",  "type": "host",   "campus": "B", "ip": "10.0.70.12", "x": 84, "y": 62},
        {"id": "b_stu1",  "label": "B-Stu1",  "type": "host",   "campus": "B", "ip": "10.0.80.11", "x": 91, "y": 62},
    ],
    "links": [
        {"src": "s1",  "dst": "s2",        "type": "core"},
        {"src": "s12", "dst": "s13",       "type": "core"},
        {"src": "s1",  "dst": "s12",       "type": "wan",    "label": "Primary WAN"},
        {"src": "s2",  "dst": "s13",       "type": "wan",    "label": "Backup WAN"},
        {"src": "s1",  "dst": "s3",        "type": "dist"},
        {"src": "s1",  "dst": "s4",        "type": "dist"},
        {"src": "s1",  "dst": "s5",        "type": "dist"},
        {"src": "s1",  "dst": "s6",        "type": "dist"},
        {"src": "s2",  "dst": "s3",        "type": "dist"},
        {"src": "s2",  "dst": "s4",        "type": "dist"},
        {"src": "s2",  "dst": "s5",        "type": "dist"},
        {"src": "s2",  "dst": "s6",        "type": "dist"},
        {"src": "s3",  "dst": "s7",        "type": "access"},
        {"src": "s4",  "dst": "s8",        "type": "access"},
        {"src": "s4",  "dst": "s10",       "type": "access"},
        {"src": "s5",  "dst": "s9",        "type": "access"},
        {"src": "s6",  "dst": "s11",       "type": "access"},
        {"src": "s12", "dst": "s14",       "type": "access"},
        {"src": "s12", "dst": "s15",       "type": "access"},
        {"src": "s13", "dst": "s15",       "type": "access"},
        {"src": "s13", "dst": "s16",       "type": "access"},
        {"src": "s7",  "dst": "admin_svr", "type": "host"},
        {"src": "s7",  "dst": "admin_pc",  "type": "host"},
        {"src": "s8",  "dst": "hod1",      "type": "host"},
        {"src": "s8",  "dst": "staff1",    "type": "host"},
        {"src": "s9",  "dst": "lab1",      "type": "host"},
        {"src": "s9",  "dst": "lab2",      "type": "host"},
        {"src": "s9",  "dst": "lab3",      "type": "host"},
        {"src": "s9",  "dst": "lab4",      "type": "host"},
        {"src": "s10", "dst": "student1",  "type": "host"},
        {"src": "s10", "dst": "student2",  "type": "host"},
        {"src": "s11", "dst": "lib1",      "type": "host"},
        {"src": "s11", "dst": "lib2",      "type": "host"},
        {"src": "s14", "dst": "b_admin",   "type": "host"},
        {"src": "s15", "dst": "b_lab1",    "type": "host"},
        {"src": "s15", "dst": "b_lab2",    "type": "host"},
        {"src": "s16", "dst": "b_stu1",    "type": "host"},
    ],
    "vlans": [
        {"id": 10, "name": "Admin Office A",  "subnet": "10.0.10.0/24", "color": "#e74c3c"},
        {"id": 20, "name": "HOD & Staff",     "subnet": "10.0.20.0/24", "color": "#e67e22"},
        {"id": 30, "name": "Computer Lab A",  "subnet": "10.0.30.0/24", "color": "#2ecc71"},
        {"id": 40, "name": "Student WiFi A",  "subnet": "10.0.40.0/24", "color": "#3498db"},
        {"id": 50, "name": "Library",         "subnet": "10.0.50.0/24", "color": "#9b59b6"},
        {"id": 60, "name": "Admin Office B",  "subnet": "10.0.60.0/24", "color": "#c0392b"},
        {"id": 70, "name": "Computer Lab B",  "subnet": "10.0.70.0/24", "color": "#27ae60"},
        {"id": 80, "name": "Student WiFi B",  "subnet": "10.0.80.0/24", "color": "#2980b9"},
    ]
}

# ── Embedded HTML dashboard ────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>University Campus SDN</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#050d1a; --panel:#0a1628; --border:#0d3060;
    --accent:#00d4ff; --text:#c8e6f7; --muted:#4a7090;
    --core:#00d4ff; --dist:#00aaff; --access:#7b61ff;
    --host:#38e8b0; --server:#ffcc00; --wan:#ff6b35;
  }
  *{margin:0;padding:0;box-sizing:border-box;}
  body{background:var(--bg);color:var(--text);font-family:'Exo 2',sans-serif;
       height:100vh;display:flex;flex-direction:column;overflow:hidden;}

  header{display:flex;align-items:center;justify-content:space-between;
         padding:10px 24px;border-bottom:1px solid var(--border);
         background:var(--panel);flex-shrink:0;}
  .hlogo{width:34px;height:34px;border:2px solid var(--accent);border-radius:50%;
         display:flex;align-items:center;justify-content:center;
         box-shadow:0 0 14px var(--accent);
         animation:pulse 2.5s ease-in-out infinite;}
  .hlogo svg{width:16px;height:16px;fill:var(--accent);}
  @keyframes pulse{0%,100%{box-shadow:0 0 8px var(--accent);}
                   50%{box-shadow:0 0 24px var(--accent),0 0 40px rgba(0,212,255,.3);}}
  h1{font-size:.95rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
     color:var(--accent);margin-left:12px;}
  h1 span{color:var(--text);font-weight:300;}
  .pill{display:flex;align-items:center;gap:6px;font-family:'Share Tech Mono',monospace;
        font-size:.7rem;color:var(--accent);background:rgba(0,212,255,.07);
        border:1px solid rgba(0,212,255,.22);border-radius:20px;padding:4px 12px;}
  .dot{width:7px;height:7px;border-radius:50%;background:#2ecc71;
       box-shadow:0 0 6px #2ecc71;animation:blink 1.4s ease-in-out infinite;}
  @keyframes blink{0%,100%{opacity:1;}50%{opacity:.3;}}

  .main{display:flex;flex:1;overflow:hidden;}

  /* Canvas */
  .cv{flex:1;position:relative;overflow:hidden;}
  #svg{width:100%;height:100%;display:block;}
  .cv::after{content:'';position:absolute;inset:0;pointer-events:none;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,
    rgba(0,0,0,.025) 2px,rgba(0,0,0,.025) 4px);}

  /* SVG classes */
  .lcore  {stroke:var(--core);  stroke-width:2.4;opacity:.85;}
  .ldist  {stroke:var(--dist);  stroke-width:1.7;opacity:.6;}
  .laccess{stroke:var(--access);stroke-width:1.3;opacity:.5;}
  .lhost  {stroke:var(--host);  stroke-width:.9; opacity:.32;stroke-dasharray:3 3;}
  .lwan   {stroke:var(--wan);   stroke-width:2.2;opacity:.9;
           stroke-dasharray:9 4;animation:flow 1.8s linear infinite;}
  @keyframes flow{to{stroke-dashoffset:-26;}}

  .ncore  {fill:rgba(0,212,255,.13); stroke:var(--core);  stroke-width:2;}
  .ndist  {fill:rgba(0,170,255,.11); stroke:var(--dist);  stroke-width:1.5;}
  .naccess{fill:rgba(123,97,255,.14);stroke:var(--access);stroke-width:1.5;}
  .nhost  {fill:rgba(56,232,176,.11);stroke:var(--host);  stroke-width:1;}
  .nserver{fill:rgba(255,204,0,.13); stroke:var(--server);stroke-width:1.5;}

  .ng{cursor:pointer;}
  .ng:hover rect,.ng:hover circle{filter:brightness(1.5);}

  .nl{font-family:'Share Tech Mono',monospace;font-size:9px;fill:var(--text);
      text-anchor:middle;dominant-baseline:middle;pointer-events:none;}
  .nl2{font-size:7.5px;fill:var(--muted);}
  .clbl{font-family:'Exo 2',sans-serif;font-size:10px;font-weight:700;
        letter-spacing:.14em;text-transform:uppercase;fill:rgba(0,212,255,.32);}

  /* Tooltip */
  #tt{position:absolute;background:var(--panel);border:1px solid var(--accent);
      border-radius:6px;padding:8px 12px;font-family:'Share Tech Mono',monospace;
      font-size:.7rem;color:var(--text);pointer-events:none;opacity:0;
      transition:opacity .15s;z-index:100;max-width:190px;
      box-shadow:0 0 20px rgba(0,212,255,.18);}
  #tt.on{opacity:1;}
  .tt-h{color:var(--accent);font-size:.75rem;margin-bottom:4px;}
  .tt-r{display:flex;justify-content:space-between;gap:10px;}
  .tt-k{color:var(--muted);} .tt-v{color:var(--text);}

  /* Side panel */
  .side{width:222px;border-left:1px solid var(--border);background:var(--panel);
        display:flex;flex-direction:column;overflow-y:auto;flex-shrink:0;}
  .side::-webkit-scrollbar{width:4px;}
  .side::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}
  .sec{padding:13px 15px;border-bottom:1px solid var(--border);}
  .st{font-size:.62rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase;
      color:var(--muted);margin-bottom:9px;}

  .sg{display:grid;grid-template-columns:1fr 1fr;gap:7px;}
  .sb{background:rgba(0,212,255,.05);border:1px solid var(--border);
      border-radius:6px;padding:7px;text-align:center;}
  .sn{font-family:'Share Tech Mono',monospace;font-size:1.35rem;color:var(--accent);line-height:1;}
  .sl{font-size:.58rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-top:3px;}

  .li{display:flex;align-items:center;gap:8px;font-size:.73rem;margin-bottom:5px;}
  .ln{width:26px;height:3px;border-radius:2px;flex-shrink:0;}
  .lnd{width:13px;height:13px;border-radius:3px;border:1.5px solid;flex-shrink:0;}

  .vi{display:flex;align-items:center;gap:8px;margin-bottom:7px;font-size:.7rem;}
  .vd{width:9px;height:9px;border-radius:50%;flex-shrink:0;}
  .vn{color:var(--text);line-height:1.2;}
  .vs{color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:.62rem;}
</style>
</head>
<body>
<header>
  <div style="display:flex;align-items:center">
    <div class="hlogo">
      <svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20A10 10 0 0012 2zm0 3a7 7 0 110 14A7 7 0 0112 5zm0 3a4 4 0 100 8 4 4 0 000-8z"/></svg>
    </div>
    <h1 style="margin-left:12px">University Campus <span>SDN Topology</span></h1>
  </div>
  <div style="display:flex;gap:10px">
    <div class="pill"><div class="dot"></div>Network Active</div>
    <div class="pill" style="color:var(--wan);border-color:rgba(255,107,53,.28);background:rgba(255,107,53,.06)">⇄ Dual WAN</div>
  </div>
</header>

<div class="main">
  <div class="cv">
    <svg id="svg" viewBox="0 0 1000 610" preserveAspectRatio="xMidYMid meet"></svg>
    <div id="tt"></div>
  </div>
  <div class="side">
    <div class="sec">
      <div class="st">Network Stats</div>
      <div class="sg">
        <div class="sb"><div class="sn">2</div><div class="sl">Campuses</div></div>
        <div class="sb"><div class="sn">16</div><div class="sl">Switches</div></div>
        <div class="sb"><div class="sn">8</div><div class="sl">VLANs</div></div>
        <div class="sb"><div class="sn">19</div><div class="sl">Hosts</div></div>
      </div>
    </div>
    <div class="sec">
      <div class="st">Node Types</div>
      <div class="li"><div class="lnd" style="background:rgba(0,212,255,.13);border-color:#00d4ff"></div>Core Switch</div>
      <div class="li"><div class="lnd" style="background:rgba(0,170,255,.11);border-color:#00aaff"></div>Distribution SW</div>
      <div class="li"><div class="lnd" style="background:rgba(123,97,255,.14);border-color:#7b61ff"></div>Access SW / AP</div>
      <div class="li"><div class="lnd" style="background:rgba(56,232,176,.11);border-color:#38e8b0;border-radius:50%"></div>Host / PC</div>
      <div class="li"><div class="lnd" style="background:rgba(255,204,0,.13);border-color:#ffcc00;border-radius:50%"></div>Server</div>
    </div>
    <div class="sec">
      <div class="st">Link Types</div>
      <div class="li"><div class="ln" style="background:#00d4ff"></div>Core / Redundant</div>
      <div class="li"><div class="ln" style="background:#00aaff;opacity:.7"></div>Distribution</div>
      <div class="li"><div class="ln" style="background:#7b61ff;opacity:.6"></div>Access</div>
      <div class="li"><div class="ln" style="background:repeating-linear-gradient(90deg,#ff6b35 0,#ff6b35 9px,transparent 9px,transparent 13px)"></div>WAN Inter-Campus</div>
      <div class="li"><div class="ln" style="background:repeating-linear-gradient(90deg,#38e8b0 0,#38e8b0 3px,transparent 3px,transparent 6px)"></div>Host Link</div>
    </div>
    <div class="sec">
      <div class="st">VLANs</div>
      <div id="vl"></div>
    </div>
  </div>
</div>

<script>
const W=1000,H=610;
const svg=document.getElementById('svg');
const tt=document.getElementById('tt');

fetch('/topology').then(r=>r.json()).then(draw);

function px(v,max){return v/100*max;}

function draw(d){
  // Campus zones
  [{x:1,y:1,w:63,h:96,c:'rgba(0,100,200,.04)',lbl:'CAMPUS A — Main Campus'},
   {x:64,y:1,w:35,h:96,c:'rgba(0,60,120,.06)',lbl:'CAMPUS B — City Campus'}
  ].forEach(z=>{
    el('rect',{x:px(z.x,W),y:px(z.y,H),width:px(z.w,W),height:px(z.h,H),
      rx:8,fill:z.c,stroke:'rgba(0,150,255,.11)','stroke-width':1});
    const t=el('text',{x:px(z.x+1.5,W),y:px(z.y+4,H),class:'clbl'});
    t.textContent=z.lbl; svg.appendChild(t);
  });

  // Build position map
  const pos={};
  d.nodes.forEach(n=>{pos[n.id]={x:px(n.x,W),y:px(n.y,H)};});

  // Links
  const lg=el('g',{}); svg.appendChild(lg);
  d.links.forEach(lk=>{
    const p1=pos[lk.src],p2=pos[lk.dst];
    if(!p1||!p2)return;
    const ln=el('line',{x1:p1.x,y1:p1.y,x2:p2.x,y2:p2.y,class:'l'+lk.type});
    lg.appendChild(ln);
    if(lk.label){
      const mx=(p1.x+p2.x)/2,my=(p1.y+p2.y)/2;
      const lt=el('text',{x:mx,y:my-7,'text-anchor':'middle',
        style:'font-family:Share Tech Mono,monospace;font-size:7.5px;fill:#ff6b35;opacity:.85'});
      lt.textContent=lk.label; svg.appendChild(lt);
    }
  });

  // Nodes
  const ng=el('g',{}); svg.appendChild(ng);
  d.nodes.forEach(n=>{
    const {x,y}=pos[n.id];
    const g=el('g',{class:'ng','data-id':n.id});
    const isH=n.type==='host'||n.type==='server';
    const sz=isH?13:(n.type==='core'?25:(n.type==='dist'?21:19));

    if(isH){
      g.appendChild(el('circle',{cx:x,cy:y,r:sz/2,
        class:n.type==='server'?'nserver':'nhost'}));
    } else {
      g.appendChild(el('rect',{x:x-sz/2,y:y-sz/2,width:sz,height:sz,rx:4,
        class:'n'+n.type}));
    }

    const lines=n.label.split('\n');
    lines.forEach((line,i)=>{
      const off=(i-(lines.length-1)/2)*9+(isH?sz/2+8:0);
      const t=el('text',{x,y:y+off,class:i===0?'nl':'nl nl2'});
      t.textContent=line; g.appendChild(t);
    });

    g.addEventListener('mouseenter',e=>showTT(e,n));
    g.addEventListener('mousemove', e=>moveTT(e));
    g.addEventListener('mouseleave',hideTT);
    ng.appendChild(g);
  });

  // VLAN list
  const vl=document.getElementById('vl');
  d.vlans.forEach(v=>{
    const div=document.createElement('div');
    div.className='vi';
    div.innerHTML=`<div class="vd" style="background:${v.color}"></div>
      <div><div class="vn">VLAN ${v.id} — ${v.name}</div>
           <div class="vs">${v.subnet}</div></div>`;
    vl.appendChild(div);
  });
}

function el(tag,attrs){
  const e=document.createElementNS('http://www.w3.org/2000/svg',tag);
  Object.entries(attrs).forEach(([k,v])=>e.setAttribute(k,v));
  svg.appendChild(e);
  return e;
}

function showTT(e,n){
  let h=`<div class="tt-h">${n.label.replace('\n',' ')}</div>`;
  if(n.type)  h+=row('Type',n.type);
  if(n.campus)h+=row('Campus',n.campus==='A'?'Main Campus':'City Campus');
  if(n.vlan)  h+=row('VLAN',n.vlan);
  if(n.ip)    h+=row('IP',n.ip);
  tt.innerHTML=h; tt.classList.add('on'); moveTT(e);
}
function moveTT(e){
  const b=document.querySelector('.cv').getBoundingClientRect();
  let tx=e.clientX-b.left+14, ty=e.clientY-b.top+14;
  if(tx+200>b.width) tx-=220;
  if(ty+110>b.height)ty-=100;
  tt.style.left=tx+'px'; tt.style.top=ty+'px';
}
function hideTT(){tt.classList.remove('on');}
function row(k,v){return`<div class="tt-r"><span class="tt-k">${k}</span><span class="tt-v">${v}</span></div>`;}
</script>
</body>
</html>"""


# ── HTTP server ────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence HTTP logs in terminal
    def do_GET(self):
        if self.path in ('/', '/index.html'):
            self._send(200, 'text/html', DASHBOARD_HTML.encode())
        elif self.path == '/topology':
            self._send(200, 'application/json', json.dumps(TOPOLOGY_DATA).encode())
        else:
            self._send(404, 'text/plain', b'Not found')
    def _send(self, code, ct, body):
        self.send_response(code)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)


def start_web_server(port=9000):
    srv = HTTPServer(('0.0.0.0', port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════════
#  MININET TOPOLOGY
# ═══════════════════════════════════════════════════════════════════════════════

def gateway_for(ip):
    host_ip = ip.split("/", 1)[0]
    parts = host_ip.split(".")
    return ".".join(parts[:3] + ["1"])


def add_host(net, name, ip):
    return net.addHost(name, ip=ip, defaultRoute="via %s" % gateway_for(ip))


def build():
    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False
    )

    net.addController("c0", ip="127.0.0.1", port=6653)

    # Switches
    s1  = net.addSwitch("s1",  dpid="0000000000000001")
    s2  = net.addSwitch("s2",  dpid="0000000000000002")
    s3  = net.addSwitch("s3",  dpid="0000000000000003")
    s4  = net.addSwitch("s4",  dpid="0000000000000004")
    s5  = net.addSwitch("s5",  dpid="0000000000000005")
    s6  = net.addSwitch("s6",  dpid="0000000000000006")
    s7  = net.addSwitch("s7",  dpid="0000000000000007")
    s8  = net.addSwitch("s8",  dpid="0000000000000008")
    s9  = net.addSwitch("s9",  dpid="0000000000000009")
    s10 = net.addSwitch("s10", dpid="000000000000000a")
    s11 = net.addSwitch("s11", dpid="000000000000000b")
    s12 = net.addSwitch("s12", dpid="000000000000000c")
    s13 = net.addSwitch("s13", dpid="000000000000000d")
    s14 = net.addSwitch("s14", dpid="000000000000000e")
    s15 = net.addSwitch("s15", dpid="000000000000000f")
    s16 = net.addSwitch("s16", dpid="0000000000000010")

    # Campus A hosts
    admin_svr = add_host(net, "admin_svr", "10.0.10.10/24")
    admin_pc  = add_host(net, "admin_pc",  "10.0.10.11/24")
    hod1      = add_host(net, "hod1",      "10.0.20.11/24")
    staff1    = add_host(net, "staff1",    "10.0.20.12/24")
    lab1      = add_host(net, "lab1",      "10.0.30.11/24")
    lab2      = add_host(net, "lab2",      "10.0.30.12/24")
    lab3      = add_host(net, "lab3",      "10.0.30.13/24")
    lab4      = add_host(net, "lab4",      "10.0.30.14/24")
    student1  = add_host(net, "student1",  "10.0.40.11/24")
    student2  = add_host(net, "student2",  "10.0.40.12/24")
    lib1      = add_host(net, "lib1",      "10.0.50.11/24")
    lib2      = add_host(net, "lib2",      "10.0.50.12/24")

    # Campus B hosts
    b_admin = add_host(net, "b_admin", "10.0.60.11/24")
    b_lab1  = add_host(net, "b_lab1",  "10.0.70.11/24")
    b_lab2  = add_host(net, "b_lab2",  "10.0.70.12/24")
    b_stu1  = add_host(net, "b_stu1",  "10.0.80.11/24")

    # Campus A core links
    net.addLink(s1, s2,  port1=8, port2=8, bw=LAN_BW)
    net.addLink(s1, s3,  port1=1, port2=1, bw=LAN_BW)
    net.addLink(s1, s4,  port1=2, port2=1, bw=LAN_BW)
    net.addLink(s1, s5,  port1=3, port2=1, bw=LAN_BW)
    net.addLink(s1, s6,  port1=4, port2=1, bw=LAN_BW)
    net.addLink(s2, s3,  port1=1, port2=2, bw=LAN_BW)
    net.addLink(s2, s4,  port1=2, port2=2, bw=LAN_BW)
    net.addLink(s2, s5,  port1=3, port2=2, bw=LAN_BW)
    net.addLink(s2, s6,  port1=4, port2=2, bw=LAN_BW)

    # Distribution to access
    net.addLink(s3, s7,  port1=3, port2=1, bw=LAN_BW)
    net.addLink(s4, s8,  port1=3, port2=1, bw=LAN_BW)
    net.addLink(s4, s10, port1=4, port2=1, bw=LAN_BW)
    net.addLink(s5, s9,  port1=3, port2=1, bw=LAN_BW)
    net.addLink(s6, s11, port1=3, port2=1, bw=LAN_BW)

    # Access to hosts
    net.addLink(s7,  admin_svr, port1=2, port2=1, bw=LAN_BW)
    net.addLink(s7,  admin_pc,  port1=3, port2=1, bw=LAN_BW)
    net.addLink(s8,  hod1,      port1=2, port2=1, bw=LAN_BW)
    net.addLink(s8,  staff1,    port1=3, port2=1, bw=LAN_BW)
    net.addLink(s9,  lab1,      port1=2, port2=1, bw=LAN_BW)
    net.addLink(s9,  lab2,      port1=3, port2=1, bw=LAN_BW)
    net.addLink(s9,  lab3,      port1=4, port2=1, bw=LAN_BW)
    net.addLink(s9,  lab4,      port1=5, port2=1, bw=LAN_BW)
    net.addLink(s10, student1,  port1=2, port2=1, bw=LAN_BW)
    net.addLink(s10, student2,  port1=3, port2=1, bw=LAN_BW)
    net.addLink(s11, lib1,      port1=2, port2=1, bw=LAN_BW)
    net.addLink(s11, lib2,      port1=3, port2=1, bw=LAN_BW)

    # Campus B links
    net.addLink(s12, s13, port1=8, port2=8, bw=LAN_BW)
    net.addLink(s12, s14, port1=1, port2=1, bw=LAN_BW)
    net.addLink(s12, s15, port1=2, port2=1, bw=LAN_BW)
    net.addLink(s13, s15, port1=1, port2=2, bw=LAN_BW)
    net.addLink(s13, s16, port1=2, port2=1, bw=LAN_BW)
    net.addLink(s14, b_admin, port1=2, port2=1, bw=LAN_BW)
    net.addLink(s15, b_lab1,  port1=3, port2=1, bw=LAN_BW)
    net.addLink(s15, b_lab2,  port1=4, port2=1, bw=LAN_BW)
    net.addLink(s16, b_stu1,  port1=2, port2=1, bw=LAN_BW)

    # WAN links
    net.addLink(s1,  s12, port1=9, port2=9, bw=WAN_BW, delay=WAN_DELAY)
    net.addLink(s2,  s13, port1=9, port2=9, bw=WAN_BW, delay=WAN_DELAY)

    net.start()

    for sw in [s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16]:
        sw.cmd("ovs-vsctl set bridge %s protocols=OpenFlow13" % sw.name)

    # Start viewer
    start_web_server(port=9000)

    info("\n")
    info("=" * 60 + "\n")
    info("  UNIVERSITY CAMPUS SDN — NETWORK STARTED\n")
    info("=" * 60 + "\n")
    info("\n")
    info("  >>> OPEN IN BROWSER: http://127.0.0.1:9000 <<<\n")
    info("\n")
    info("  QUICK TESTS:\n")
    info("    lab1 ping -c3 lab2\n")
    info("    admin_pc ping -c3 lab1\n")
    info("    student1 ping -c3 admin_svr   (BLOCKED)\n")
    info("    admin_pc ping -c3 b_admin\n")
    info("    link s1 s12 down              (test failover)\n")
    info("=" * 60 + "\n\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build()
