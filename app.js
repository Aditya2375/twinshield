(() => {
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
let mode = "live", demo = null, frame = 0, playing = true, timer = null, st = null, flagged = new Set();

const HEAD = {
  clear: ["Nothing suspicious", "Every radio using an approved name is one you approved."],
  review: ["Worth a look", "Something changed that may be normal. Check the evidence below."],
  alert: ["Suspicious evidence found", "A radio is using an approved name and the evidence does not fit your baseline. Verify before connecting."],
  unavailable: ["Scanner unavailable", "No fresh scan. This is not a safe signal. Check the scanner."],
  no_baseline: ["No baseline yet", "Approve the networks you trust so there is something to compare against."],
};

function ago(t) { if (!t) return "never"; const s = Math.max(0, Math.round(Date.now() / 1000 - t)); return s < 60 ? s + "s ago" : Math.round(s / 60) + "m ago"; }

function statusOf(s) {
  if (s.status) return s.status;
  const inc = s.incidents || [];
  if (inc.some((i) => i.active && i.level === "high")) return "alert";
  if (inc.some((i) => i.active && i.level === "review")) return "review";
  return "clear";
}

function render(s) {
  st = s; flagged = new Set((s.incidents || []).filter((i) => i.active && i.level !== "low").map((i) => i.bssid));
  const k = statusOf(s);
  $("#status").className = "status s-" + k;
  $("#headline").textContent = HEAD[k][0]; $("#sub").textContent = s.error ? s.error : HEAD[k][1];
  $("#meta1").textContent = mode === "demo" ? "scan cycle " + s.cycle : "scan " + s.cycle + " every " + s.interval + "s";
  $("#meta2").textContent = mode === "demo" ? "test fixture" : "last " + ago(s.last_scan_at);
  const inc = (s.incidents || []).filter((i) => !i.acked || i.level === "high");
  $("#alertCount").textContent = inc.filter((i) => i.active).length + " active";
  $("#alerts").innerHTML = inc.length ? inc.map(alertHtml).join("") : `<div class="empty">${s.baseline ? "No alerts. Radios sharing an approved name all match your baseline." : "Alerts appear once a baseline exists."}</div>`;
  document.querySelectorAll("[data-ack]").forEach((b) => b.onclick = () => ack(b.dataset.ack));
  document.querySelectorAll("canvas.spark").forEach((c) => spark(c, JSON.parse(c.dataset.h)));
  baselineHtml(s); scanHtml(s); drawRadar();
}
function alertHtml(i) {
  return `<article class="alert ${i.level} ${i.active ? "" : "gone"}">
  <div class="a-top"><div class="a-name">${esc(i.ssid || "(hidden name)")}<small>${esc(i.bssid)} &middot; ch ${i.channel} &middot; ${esc(i.band)} &middot; ${esc(i.security)}</small><span class="badge">${esc(i.label)}</span></div>
  <div class="score"><b>${i.score}</b><span>review score</span></div></div>
  <ul class="ev">${i.evidence.map((e) => `<li><span class="pts">+${e.points}</span><div><b>${esc(e.rule)}</b><span>${esc(e.detail)}</span></div></li>`).join("")}</ul>
  <div class="a-foot"><span>seen ${i.sightings}x</span><span>${i.active ? "present now" : "no longer visible"}</span><canvas class="spark" width="180" height="44" data-h='${JSON.stringify(i.signal_history || [])}'></canvas><span>signal ${i.signal_pct}%</span>
  ${mode === "live" ? `<button class="btn ghost" data-ack="${esc(i.key)}" type="button">Acknowledge</button>` : ""}</div></article>`;
}
function spark(c, h) {
  const g = c.getContext("2d"); g.clearRect(0, 0, c.width, c.height); if (h.length < 2) return;
  g.strokeStyle = "#8b98a5"; g.lineWidth = 2; g.beginPath();
  h.forEach((v, i) => { const x = (i / (h.length - 1)) * (c.width - 4) + 2, y = c.height - 3 - (v / 100) * (c.height - 6); i ? g.lineTo(x, y) : g.moveTo(x, y); }); g.stroke();
}
function baselineHtml(s) {
  const b = s.baseline;
  $("#blMeta").textContent = b ? "approved set" : "none";
  $("#baseline").innerHTML = b ? Object.entries(b.networks).map(([n, v]) => `<div class="bl-net"><b>${esc(n)}</b><span>${Object.keys(v.radios).length} approved radio(s) &middot; ${esc(v.security)}</span></div>`).join("") : `<div class="empty">No baseline yet.</div>`;
  const live = mode === "live";
  $("#approveBox").hidden = !live;
  if (live && !$("#ssidPick").dataset.set) {
    $("#ssidPick").innerHTML = (s.ssids || []).map((n) => `<label><input type="checkbox" value="${esc(n)}">${esc(n)}</label>`).join("") || `<span class="note">Waiting for networks.</span>`;
    if ((s.ssids || []).length) $("#ssidPick").dataset.set = "1";
  }
}
function scanHtml(s) {
  $("#scanMeta").textContent = (s.scan || []).length + " radios";
  $("#scanTbl tbody").innerHTML = (s.scan || []).slice().sort((a, b) => b.signal_pct - a.signal_pct).map((a) =>
    `<tr class="${flagged.has(a.bssid) ? "f" : ""}"><td>${esc(a.ssid || "(hidden)")}</td><td>${esc(a.bssid)}</td><td>${a.channel}</td><td>${a.signal_pct}%</td><td>${esc(a.security)}</td></tr>`).join("");
}

/* radar: radius from signal, angle from the radio address, so a radio keeps its place between scans */
function hue(b) { let h = 0; for (const c of b) h = (h * 31 + c.charCodeAt(0)) >>> 0; return (h % 3600) / 3600 * Math.PI * 2; }
let t0 = performance.now();
function drawRadar(now) {
  const c = $("#radar"), r = c.getBoundingClientRect(), dpr = Math.min(devicePixelRatio || 1, 2);
  if (c.width !== Math.round(r.width * dpr)) { c.width = Math.round(r.width * dpr); c.height = Math.round(r.height * dpr); }
  const g = c.getContext("2d"), W = c.width, cx = W / 2, R = W / 2 - 18 * dpr, t = ((now || t0) - t0) / 1000;
  g.clearRect(0, 0, W, W);
  g.strokeStyle = "#1a232c"; g.lineWidth = dpr;
  for (let i = 1; i <= 4; i++) { g.beginPath(); g.arc(cx, cx, (R * i) / 4, 0, 7); g.stroke(); }
  g.beginPath(); g.moveTo(cx - R, cx); g.lineTo(cx + R, cx); g.moveTo(cx, cx - R); g.lineTo(cx, cx + R); g.stroke();
  const a = t * 0.9, grad = g.createConicGradient ? g.createConicGradient(a, cx, cx) : null;
  if (grad) { grad.addColorStop(0, "rgba(95,208,160,.22)"); grad.addColorStop(0.12, "rgba(95,208,160,0)"); grad.addColorStop(1, "rgba(95,208,160,0)"); g.fillStyle = grad; g.beginPath(); g.arc(cx, cx, R, 0, 7); g.fill(); }
  g.fillStyle = "#e6edf3"; g.beginPath(); g.arc(cx, cx, 4 * dpr, 0, 7); g.fill();
  if (!st) return requestAnimationFrame(drawRadar);
  const approved = new Set(); Object.values((st.baseline && st.baseline.networks) || {}).forEach((n) => Object.keys(n.radios).forEach((b) => approved.add(b)));
  (st.scan || []).forEach((ap) => {
    const rad = R * (1 - Math.min(ap.signal_pct, 99) / 100) * 0.92 + R * 0.06, th = hue(ap.bssid), x = cx + Math.cos(th) * rad, y = cx + Math.sin(th) * rad;
    const bad = flagged.has(ap.bssid), ok = approved.has(ap.bssid), col = bad ? "#ff6b4a" : ok ? "#5fd0a0" : "#6e7c8a";
    if (bad) { g.strokeStyle = "rgba(255,107,74,.5)"; g.lineWidth = dpr * 1.5; g.beginPath(); g.arc(x, y, (9 + 5 * ((t * 1.4) % 1)) * dpr, 0, 7); g.stroke(); }
    g.fillStyle = col; g.beginPath(); g.arc(x, y, (bad ? 6 : 4.5) * dpr, 0, 7); g.fill();
    if (bad || ok && ap.ssid) { g.fillStyle = "#b8c4d0"; g.font = `${11 * dpr}px JetBrains Mono, monospace`; g.fillText((ap.ssid || "").slice(0, 14), x + 9 * dpr, y + 4 * dpr); }
  });
  requestAnimationFrame(drawRadar);
}

async function ack(key) { await fetch("/api/ack", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key }) }); poll(); }
$("#approve").onclick = async () => {
  const ssids = [...document.querySelectorAll("#ssidPick input:checked")].map((i) => i.value);
  if (!ssids.length) { $("#approveMsg").textContent = "Pick at least one network."; return; }
  const r = await fetch("/api/baseline/approve", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ssids }) });
  const j = await r.json(); $("#approveMsg").textContent = j.ok ? "Baseline saved from the last few scans." : j.message; poll();
};

function showFrame(i) {
  frame = i; const f = demo.frames[i];
  render({ cycle: f.cycle, interval: demo.interval, scan: f.scan, incidents: f.incidents, baseline: demo.baseline });
  $("#cyc").textContent = f.cycle; $("#range").value = f.cycle;
}
function tick() { if (!playing) return; showFrame((frame + 1) % demo.frames.length); }

async function poll() {
  try { const r = await fetch("/api/state", { cache: "no-store" }); if (!r.ok) throw 0; render(await r.json()); } catch (e) { $("#sub").textContent = "Lost contact with the local scanner."; }
}
async function start() {
  try {
    const r = await fetch("/api/state", { cache: "no-store" }); if (!r.ok) throw 0;
    const s = await r.json(); mode = s.mode;
    $("#mode").textContent = mode === "replay" ? "replay (test fixture)" : "live scan";
    if (mode === "replay") { $("#banner").hidden = false; $("#banner").textContent = "Replaying a labelled test fixture, not a real scan."; }
    render(s); setInterval(poll, 3000); return;
  } catch (e) {}
  mode = "demo";
  demo = await (await fetch("demo.json")).json();
  $("#mode").textContent = "demo (test fixture)";
  $("#banner").hidden = false;
  $("#banner").innerHTML = "This is a public demo that replays a scripted test scenario. It is not a scan of your network. To scan for real, download the tool and run <code>sh run.sh</code> on a laptop; nothing leaves your machine.";
  $("#replayCard").hidden = false; $("#cycN").textContent = demo.frames.length; $("#range").max = demo.frames.length;
  $("#range").oninput = (e) => { playing = false; $("#play").textContent = "Play"; showFrame(+e.target.value - 1); };
  $("#play").onclick = () => { playing = !playing; $("#play").textContent = playing ? "Pause" : "Play"; };
  frame = demo.frames.length - 1; showFrame(0); timer = setInterval(tick, 1100);
}
start();
})();
