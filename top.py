#!/usr/bin/env python3
"""
Realistic University Campus SDN Topology - Mininet
==================================================

This topology is intentionally smaller than the earlier 16-switch model.
It represents a more believable university lab network:

  - Main campus collapsed core
  - Building/access switches for admin, academics, labs, and library/DC
  - Small city campus core with admin/lab and student WiFi access switches
  - One WAN-style inter-campus link

Run:
  sudo python3 university_topology_realistic.py

Start the matching controller first:
  ryu-manager --observe-links university_controller_realistic.py

Viewer:
  http://127.0.0.1:9000
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from mininet.cli import CLI
from mininet.clean import cleanup
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController


LAN_BW = 100
WAN_BW = 20
WAN_DELAY = "8ms"


TOPOLOGY_DATA = {
    "nodes": [
        {"id": "s1", "label": "Main Campus Core", "type": "core", "campus": "Main", "x": 48, "y": 18},
        {"id": "s2", "label": "Admin Services", "type": "access", "campus": "Main", "x": 18, "y": 42},
        {"id": "s3", "label": "Academic Building", "type": "access", "campus": "Main", "x": 38, "y": 46},
        {"id": "s4", "label": "Lab Building", "type": "access", "campus": "Main", "x": 58, "y": 46},
        {"id": "s5", "label": "Library / DC", "type": "access", "campus": "Main", "x": 76, "y": 42},
        {"id": "s6", "label": "City Campus Core", "type": "core", "campus": "City", "x": 50, "y": 78},
        {"id": "s7", "label": "City Admin + Lab", "type": "access", "campus": "City", "x": 35, "y": 90},
        {"id": "s8", "label": "City Student WiFi", "type": "access", "campus": "City", "x": 65, "y": 90},

        {"id": "adminPc", "label": "Admin PC", "type": "host", "vlan": 10, "ip": "10.0.10.11", "x": 12, "y": 58},
        {"id": "registrar", "label": "Registrar", "type": "host", "vlan": 20, "ip": "10.0.20.10", "x": 22, "y": 62},
        {"id": "hod1", "label": "HOD", "type": "host", "vlan": 20, "ip": "10.0.20.11", "x": 32, "y": 62},
        {"id": "staff1", "label": "Staff", "type": "host", "vlan": 20, "ip": "10.0.20.12", "x": 39, "y": 66},
        {"id": "student1", "label": "Student 1", "type": "host", "vlan": 40, "ip": "10.0.40.11", "x": 45, "y": 62},
        {"id": "lab3", "label": "Lab 3", "type": "host", "vlan": 30, "ip": "10.0.30.13", "x": 50, "y": 66},
        {"id": "lab1", "label": "Lab 1", "type": "host", "vlan": 30, "ip": "10.0.30.11", "x": 56, "y": 62},
        {"id": "lab2", "label": "Lab 2", "type": "host", "vlan": 30, "ip": "10.0.30.12", "x": 62, "y": 66},
        {"id": "lab4", "label": "Lab 4", "type": "host", "vlan": 30, "ip": "10.0.30.14", "x": 68, "y": 62},
        {"id": "adminSvr", "label": "Admin Server", "type": "server", "vlan": 10, "ip": "10.0.10.10", "x": 74, "y": 56},
        {"id": "lib1", "label": "Library PC", "type": "host", "vlan": 50, "ip": "10.0.50.11", "x": 78, "y": 58},
        {"id": "lib2", "label": "Catalog PC", "type": "host", "vlan": 50, "ip": "10.0.50.12", "x": 43, "y": 70},
        {"id": "student2", "label": "Student 2", "type": "host", "vlan": 40, "ip": "10.0.40.12", "x": 88, "y": 66},
        {"id": "librarySvr", "label": "Library Server", "type": "server", "vlan": 50, "ip": "10.0.50.20", "x": 92, "y": 58},
        {"id": "b_admin", "label": "City Admin", "type": "host", "vlan": 60, "ip": "10.0.60.11", "x": 24, "y": 96},
        {"id": "b_lab1", "label": "City Lab 1", "type": "host", "vlan": 70, "ip": "10.0.70.11", "x": 34, "y": 98},
        {"id": "b_stu2", "label": "City Student 2", "type": "host", "vlan": 80, "ip": "10.0.80.12", "x": 43, "y": 96},
        {"id": "b_staff", "label": "City Staff", "type": "host", "vlan": 60, "ip": "10.0.60.12", "x": 56, "y": 96},
        {"id": "b_lab2", "label": "City Lab 2", "type": "host", "vlan": 70, "ip": "10.0.70.12", "x": 64, "y": 98},
        {"id": "b_stu1", "label": "City Student 1", "type": "host", "vlan": 80, "ip": "10.0.80.11", "x": 72, "y": 96},
    ],
    "links": [
        {"src": "s1", "dst": "s2", "type": "campus", "label": "Admin"},
        {"src": "s1", "dst": "s3", "type": "campus", "label": "Academic"},
        {"src": "s1", "dst": "s4", "type": "campus", "label": "Labs"},
        {"src": "s1", "dst": "s5", "type": "campus", "label": "Library/DC"},
        {"src": "s1", "dst": "s6", "type": "wan", "label": "Inter-campus WAN"},
        {"src": "s6", "dst": "s7", "type": "campus", "label": "City admin/lab"},
        {"src": "s6", "dst": "s8", "type": "campus", "label": "City WiFi"},
        {"src": "s2", "dst": "adminPc", "type": "host"},
        {"src": "s2", "dst": "registrar", "type": "host"},
        {"src": "s3", "dst": "hod1", "type": "host"},
        {"src": "s3", "dst": "staff1", "type": "host"},
        {"src": "s3", "dst": "student1", "type": "host"},
        {"src": "s3", "dst": "lab3", "type": "host"},
        {"src": "s3", "dst": "lib2", "type": "host"},
        {"src": "s4", "dst": "lab1", "type": "host"},
        {"src": "s4", "dst": "lab2", "type": "host"},
        {"src": "s4", "dst": "lab4", "type": "host"},
        {"src": "s5", "dst": "adminSvr", "type": "host"},
        {"src": "s5", "dst": "lib1", "type": "host"},
        {"src": "s5", "dst": "student2", "type": "host"},
        {"src": "s5", "dst": "librarySvr", "type": "host"},
        {"src": "s7", "dst": "b_admin", "type": "host"},
        {"src": "s7", "dst": "b_lab1", "type": "host"},
        {"src": "s7", "dst": "b_stu2", "type": "host"},
        {"src": "s8", "dst": "b_staff", "type": "host"},
        {"src": "s8", "dst": "b_lab2", "type": "host"},
        {"src": "s8", "dst": "b_stu1", "type": "host"},
    ],
    "vlans": [
        {"id": 10, "name": "Main Admin", "subnet": "10.0.10.0/24", "gateway": "10.0.10.1", "color": "#c0392b"},
        {"id": 20, "name": "Faculty & Staff", "subnet": "10.0.20.0/24", "gateway": "10.0.20.1", "color": "#d68910"},
        {"id": 30, "name": "Teaching Labs", "subnet": "10.0.30.0/24", "gateway": "10.0.30.1", "color": "#239b56"},
        {"id": 40, "name": "Student WiFi", "subnet": "10.0.40.0/24", "gateway": "10.0.40.1", "color": "#2874a6"},
        {"id": 50, "name": "Library & Servers", "subnet": "10.0.50.0/24", "gateway": "10.0.50.1", "color": "#7d3c98"},
        {"id": 60, "name": "City Admin", "subnet": "10.0.60.0/24", "gateway": "10.0.60.254", "color": "#922b21"},
        {"id": 70, "name": "City Labs", "subnet": "10.0.70.0/24", "gateway": "10.0.70.254", "color": "#1e8449"},
        {"id": 80, "name": "City Student WiFi", "subnet": "10.0.80.0/24", "gateway": "10.0.80.254", "color": "#21618c"},
    ],
}


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>University SDN Dashboard</title>

<style>

*{
margin:0;
padding:0;
box-sizing:border-box;
font-family:Arial,Helvetica,sans-serif;
}

:root{

--bg:#10151b;
--panel:#192129;
--panel2:#222d37;

--border:#31414f;

--text:#eef3f7;
--muted:#9fb0bc;

--core:#34b5ff;
--access:#61d36c;
--host:#d8e2ea;
--server:#ffcb59;

--wan:#ff7043;

}

body{

background:#10151b;

color:var(--text);

min-height:100vh;

display:flex;

flex-direction:column;

overflow:auto;

}

header{

height:60px;

background:var(--panel);

display:flex;

justify-content:space-between;

align-items:center;

padding:0 25px;

border-bottom:1px solid var(--border);

}

header h1{

font-size:21px;

}

header span{

font-size:14px;

color:var(--muted);

}

.status{

display:flex;

gap:12px;

}

.badge{

background:var(--panel2);

padding:7px 14px;

border-radius:20px;

border:1px solid var(--border);

font-size:13px;

}

.main{

flex:1;

display:flex;

overflow:auto;

}
.canvas{

flex:1;

position:relative;

background:#11181f;

overflow:auto;

}
.side{

width:290px;

background:var(--panel);

padding:18px;

overflow:auto;

border-left:1px solid var(--border);

}

.card{

background:var(--panel2);

border:1px solid var(--border);

border-radius:10px;

padding:15px;

margin-bottom:16px;

}

.card h3{

font-size:13px;

margin-bottom:12px;

text-transform:uppercase;

color:#b8c5cf;

}

.stats{

display:grid;

grid-template-columns:1fr 1fr;

gap:10px;

}

.stat{

background:#172029;

padding:12px;

border-radius:8px;

text-align:center;

}

.stat .num{

font-size:24px;

font-weight:bold;

}

.stat .txt{

font-size:11px;

color:var(--muted);

margin-top:4px;

}

.legend{

display:flex;

align-items:center;

gap:10px;

margin:10px 0;

font-size:14px;

}

.swatch{

width:15px;

height:15px;

border:2px solid;

border-radius:4px;

}

.vlan{

display:flex;

gap:10px;

padding:10px;

background:#172029;

border-radius:8px;

margin-bottom:10px;

}

.dot{

width:12px;

height:12px;

border-radius:50%;

margin-top:4px;

}

.small{

font-size:11px;

color:var(--muted);

}

svg{

width:1400px;

height:950px;

display:block;

}

.zone{

fill:#141d26;

stroke:#31414f;

stroke-width:2;

}

.zone-title{

fill:#93a8b7;

font-size:14px;

font-weight:bold;

letter-spacing:2px;

}

.link-campus{

stroke:#708491;

stroke-width:3;

}

.link-host{

stroke:#5f6f79;

stroke-width:1.5;

stroke-dasharray:4 4;

}

.link-wan{

stroke:var(--wan);

stroke-width:4;

stroke-dasharray:10 6;

}

.core{

fill:#17384f;

stroke:var(--core);

stroke-width:2.5;

}

.access{

fill:#234028;

stroke:var(--access);

stroke-width:2;

}

.host{

fill:#273038;

stroke:var(--host);

stroke-width:2;

}

.server{

fill:#47381f;

stroke:var(--server);

stroke-width:2;

}

.node text{

fill:white;

font-size:12px;

font-weight:bold;

text-anchor:middle;

dominant-baseline:middle;

pointer-events:none;

}

.label{

fill:#9db1be;

font-size:11px;

text-anchor:middle;

}

.node:hover{

filter:drop-shadow(0 0 6px rgba(255,255,255,.35));

cursor:pointer;

}

#tip{

position:absolute;

background:#18212a;

border:1px solid #41596a;

padding:10px;

border-radius:6px;

font-size:12px;

pointer-events:none;

opacity:0;

transition:.2s;

}

#tip.on{

opacity:1;

}

</style>

</head>

<body>

<header>

<h1>

University SDN

<span>Topology Dashboard</span>

</h1>

<div class="status">

<div class="badge">2 Campuses</div>

<div class="badge">8 Switches</div>

<div class="badge">20 Hosts</div>

<div class="badge">8 VLANs</div>

</div>

</header>

<div class="main">

<div class="canvas">

<svg
id="svg"
viewBox="0 0 1000 900"
width="100%"
height="900">
</svg>

<div id="tip"></div>

</div>

<aside class="side">

<div class="card">

<h3>Network Summary</h3>

<div class="stats">

<div class="stat">

<div class="num">2</div>

<div class="txt">Campuses</div>

</div>

<div class="stat">

<div class="num">8</div>

<div class="txt">Switches</div>

</div>

<div class="stat">

<div class="num">20</div>

<div class="txt">Hosts</div>

</div>

<div class="stat">

<div class="num">8</div>

<div class="txt">VLANs</div>

</div>

</div>

</div>

<div class="card">

<h3>Node Types</h3>

<div class="legend">
<div class="swatch" style="background:#17384f;border-color:#34b5ff"></div>
Core Switch
</div>

<div class="legend">
<div class="swatch" style="background:#234028;border-color:#61d36c"></div>
Access Switch
</div>

<div class="legend">
<div class="swatch" style="background:#273038;border-color:#d8e2ea;border-radius:50%"></div>
Host
</div>

<div class="legend">
<div class="swatch" style="background:#47381f;border-color:#ffcb59;border-radius:50%"></div>
Server
</div>

</div>

<div class="card">

<h3>VLANs</h3>

<div id="vlans"></div>

</div>

</aside>

</div>

<script>

const svg=document.getElementById("svg");
const tip=document.getElementById("tip");

const W=1000;
const H=650;

fetch("/topology")
.then(r=>r.json())
.then(draw);

function p(v,max){
return v/100*max;
}

function el(tag,attrs,parent=svg){

const e=document.createElementNS(
"http://www.w3.org/2000/svg",
tag);

Object.entries(attrs).forEach(([k,v])=>e.setAttribute(k,v));

parent.appendChild(e);

return e;

}

function text(x,y,s,c,parent=svg){

const t=el("text",{x,y,class:c},parent);

t.textContent=s;

return t;

}function draw(data){

    // Campus Areas
    el("rect",{
        x:30,
        y:30,
        width:940,
        height:360,
        rx:12,
        class:"zone"
    });

   el("rect",{
    x:230,
    y:490,      // was 430
    width:540,
    height:180,
    rx:12,
    class:"zone"
});

text(250,515,"CITY CAMPUS","zone-title"); // was 455
    text(55,55,"MAIN CAMPUS","zone-title");
    

    // Original switch positions
    const pos={};

    data.nodes.forEach(n=>{

        pos[n.id]={
            x:p(n.x,W),
            y:p(n.y,H)
        };

    });

    // Arrange hosts automatically
    const groups={};

    data.links.forEach(l=>{

        if(l.type==="host"){

            if(!groups[l.src])
                groups[l.src]=[];

            groups[l.src].push(l.dst);

        }

    });

    Object.keys(groups).forEach(sw => {

    const s = pos[sw];
    const hosts = groups[sw];

    const perRow = 3;
    const spacingX = 70;
    const spacingY = 45;

    hosts.forEach((id, i) => {

        const row = Math.floor(i / perRow);
        const col = i % perRow;

        const colsInRow = Math.min(perRow, hosts.length - row * perRow);
        const offset = (colsInRow - 1) / 2;

        pos[id] = {
            x: s.x + (col - offset) * spacingX,
            y: s.y + 90 + row * spacingY
        };

    });

});

    // Draw links
    data.links.forEach(l=>{

        const a=pos[l.src];
        const b=pos[l.dst];

        if(!a||!b) return;

        el("line",{

            x1:a.x,
            y1:a.y,

            x2:b.x,
            y2:b.y,

            class:"link-"+l.type

        });

        if(l.label && l.type!="host"){

            text(

                (a.x+b.x)/2,
                (a.y+b.y)/2-8,

                l.label,

                "label"

            );

        }

    });

    // Draw nodes
    data.nodes.forEach(n=>drawNode(n,pos[n.id]));

    // VLAN List
    const box=document.getElementById("vlans");

    data.vlans.forEach(v=>{

        const div=document.createElement("div");

        div.className="vlan";

        div.innerHTML=`
        <span class="dot"
        style="background:${v.color}">
        </span>

        <div>

        <div>

        <b>VLAN ${v.id}</b>

        ${v.name}

        </div>

        <div class="small">

        ${v.subnet} | GW ${v.gateway}

        </div>

        </div>
        `;

        box.appendChild(div);

    });

}

function drawNode(n,pt){

    const g=el("g",{class:"node"});

    if(n.type=="core"){

        el("rect",{

            x:pt.x-65,

            y:pt.y-18,

            width:130,

            height:36,

            rx:6,

            class:"core"

        },g);

    }

    else if(n.type=="access"){

        el("rect",{

            x:pt.x-58,

            y:pt.y-18,

            width:116,

            height:36,

            rx:6,

            class:"access"

        },g);

    }

    else if(n.type=="server"){

        el("circle",{

            cx:pt.x,

            cy:pt.y,

            r:14,

            class:"server"

        },g);

    }

    else{

        el("circle",{

            cx:pt.x,

            cy:pt.y,

            r:10,

            class:"host"

        },g);

    }

    if(n.type=="host" || n.type=="server"){

        text(

            pt.x,

            pt.y+24,

            n.label,

            "",

            g

        );

    }

    else{

        text(

            pt.x,

            pt.y,

            n.label,

            "",

            g

        );

    }

    g.addEventListener("mouseenter",e=>showTip(e,n));
    g.addEventListener("mousemove",moveTip);
    g.addEventListener("mouseleave",()=>tip.classList.remove("on"));

}

function showTip(e,n){

tip.innerHTML=`
<b>${n.label}</b><br>

Type: ${n.type}

${n.campus?`<br>Campus: ${n.campus}`:""}

${n.vlan?`<br>VLAN: ${n.vlan}`:""}

${n.ip?`<br>IP: ${n.ip}`:""}
`;

tip.classList.add("on");

moveTip(e);

}

function moveTip(e){

const r=document.querySelector(".canvas").getBoundingClientRect();

tip.style.left=(e.clientX-r.left+15)+"px";

tip.style.top=(e.clientY-r.top+15)+"px";

}

</script>

</body>

</html>
"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", DASHBOARD_HTML.encode())
        elif self.path == "/topology":
            self._send(200, "application/json", json.dumps(TOPOLOGY_DATA).encode())
        else:
            self._send(404, "text/plain", b"Not found")

    def _send(self, code, content_type, body):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def start_web_server(port=9000):
    server = HTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def gateway_for(ip):
    host_ip = ip.split("/", 1)[0]
    parts = host_ip.split(".")
    vlan_id = int(parts[2])
    gateway_host = "254" if vlan_id in {60, 70, 80} else "1"
    return ".".join(parts[:3] + [gateway_host])


def add_host(net, name, ip):
    return net.addHost(name, ip=ip, defaultRoute="via %s" % gateway_for(ip))


def build():
    cleanup()

    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False,
    )

    net.addController("c0", ip="127.0.0.1", port=6653)

    switch_opts = {"protocols": "OpenFlow13", "failMode": "secure"}
    switches = {}
    for num in range(1, 9):
        name = "s%d" % num
        switches[name] = net.addSwitch(
            name,
            dpid="%016x" % num,
            **switch_opts
        )

    hosts = {
        "adminSvr": add_host(net, "adminSvr", "10.0.10.10/24"),
        "adminPc": add_host(net, "adminPc", "10.0.10.11/24"),
        "registrar": add_host(net, "registrar", "10.0.20.10/24"),
        "hod1": add_host(net, "hod1", "10.0.20.11/24"),
        "staff1": add_host(net, "staff1", "10.0.20.12/24"),
        "student1": add_host(net, "student1", "10.0.40.11/24"),
        "student2": add_host(net, "student2", "10.0.40.12/24"),
        "lab1": add_host(net, "lab1", "10.0.30.11/24"),
        "lab2": add_host(net, "lab2", "10.0.30.12/24"),
        "lab3": add_host(net, "lab3", "10.0.30.13/24"),
        "lab4": add_host(net, "lab4", "10.0.30.14/24"),
        "lib1": add_host(net, "lib1", "10.0.50.11/24"),
        "lib2": add_host(net, "lib2", "10.0.50.12/24"),
        "librarySvr": add_host(net, "librarySvr", "10.0.50.20/24"),
        "b_admin": add_host(net, "b_admin", "10.0.60.11/24"),
        "b_staff": add_host(net, "b_staff", "10.0.60.12/24"),
        "b_lab1": add_host(net, "b_lab1", "10.0.70.11/24"),
        "b_lab2": add_host(net, "b_lab2", "10.0.70.12/24"),
        "b_stu1": add_host(net, "b_stu1", "10.0.80.11/24"),
        "b_stu2": add_host(net, "b_stu2", "10.0.80.12/24"),
    }

    s1, s2, s3, s4 = switches["s1"], switches["s2"], switches["s3"], switches["s4"]
    s5, s6, s7, s8 = switches["s5"], switches["s6"], switches["s7"], switches["s8"]

    net.addLink(s1, s2, port1=1, port2=1, bw=LAN_BW)
    net.addLink(s1, s3, port1=2, port2=1, bw=LAN_BW)
    net.addLink(s1, s4, port1=3, port2=1, bw=LAN_BW)
    net.addLink(s1, s5, port1=4, port2=1, bw=LAN_BW)
    net.addLink(s1, s6, port1=5, port2=1, bw=WAN_BW, delay=WAN_DELAY)
    net.addLink(s6, s7, port1=2, port2=1, bw=LAN_BW)
    net.addLink(s6, s8, port1=3, port2=1, bw=LAN_BW)

    net.addLink(s2, hosts["adminPc"], port1=2, port2=1, bw=LAN_BW)
    net.addLink(s2, hosts["registrar"], port1=3, port2=1, bw=LAN_BW)
    net.addLink(s3, hosts["hod1"], port1=2, port2=1, bw=LAN_BW)
    net.addLink(s3, hosts["staff1"], port1=3, port2=1, bw=LAN_BW)
    net.addLink(s3, hosts["student1"], port1=4, port2=1, bw=LAN_BW)
    net.addLink(s3, hosts["lab3"], port1=5, port2=1, bw=LAN_BW)
    net.addLink(s3, hosts["lib2"], port1=6, port2=1, bw=LAN_BW)
    net.addLink(s4, hosts["lab1"], port1=2, port2=1, bw=LAN_BW)
    net.addLink(s4, hosts["lab2"], port1=3, port2=1, bw=LAN_BW)
    net.addLink(s4, hosts["lab4"], port1=4, port2=1, bw=LAN_BW)
    net.addLink(s5, hosts["adminSvr"], port1=2, port2=1, bw=LAN_BW)
    net.addLink(s5, hosts["lib1"], port1=3, port2=1, bw=LAN_BW)
    net.addLink(s5, hosts["student2"], port1=4, port2=1, bw=LAN_BW)
    net.addLink(s5, hosts["librarySvr"], port1=5, port2=1, bw=LAN_BW)
    net.addLink(s7, hosts["b_admin"], port1=2, port2=1, bw=LAN_BW)
    net.addLink(s7, hosts["b_lab1"], port1=3, port2=1, bw=LAN_BW)
    net.addLink(s7, hosts["b_stu2"], port1=4, port2=1, bw=LAN_BW)
    net.addLink(s8, hosts["b_staff"], port1=2, port2=1, bw=LAN_BW)
    net.addLink(s8, hosts["b_lab2"], port1=3, port2=1, bw=LAN_BW)
    net.addLink(s8, hosts["b_stu1"], port1=4, port2=1, bw=LAN_BW)

    net.start()

    # Note: OpenFlow13 already set via switch_opts in addSwitch() above

    start_web_server(port=9000)

    info("\n")
    info("=" * 66 + "\n")
    info("  REALISTIC UNIVERSITY SDN TOPOLOGY STARTED\n")
    info("=" * 66 + "\n")
    info("  Browser topology: http://127.0.0.1:9000\n\n")
    info("  Useful tests:\n")
    info("    lab1 ping -c3 lab2\n")
    info("    adminPc ping -c3 librarySvr\n")
    info("    adminPc ping -c3 b_admin\n")
    info("    student1 ping -c3 adminSvr    (expected blocked by ACL)\n")
    info("    link s1 s6 down                (tests city campus isolation)\n")
    info("=" * 66 + "\n\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build()
