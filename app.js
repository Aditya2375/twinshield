/* TwinShield review desk. No scanning takes place on public hosting. */
(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const esc = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  const own = (o, k) =>
    o && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined;
  const number = (v, fallback = 0) => (Number.isFinite(v) ? v : fallback);
  const strength = (v) => Math.max(0, Math.min(100, number(v)));
  const name = (a) => a.ssid || "(hidden name)";
  const band = (a) =>
    a.freq
      ? a.freq >= 5925
        ? "6 GHz"
        : a.freq >= 4900
          ? "5 GHz"
          : "2.4 GHz"
      : a.channel > 14
        ? "5 GHz"
        : "2.4 GHz";
  let state = null,
    mode = "loading",
    fixture = null,
    frame = 9,
    playing = false,
    timer = null,
    polling = false,
    pollTimer = null;
  let selected = "",
    filter = "active",
    disposed = false;
  const pendingAcks = new Set(),
    requests = new Set();
  const HEAD = {
    clear: [
      "No review-level findings",
      "No review-level mismatch in this observation. Metadata alone cannot establish that a network is safe.",
      "–",
    ],
    review: [
      "A difference worth reviewing",
      "The metadata differs from the baseline. Read the evidence before you connect.",
      "!",
    ],
    alert: [
      "Strong evidence to review",
      "Repeated high-priority differences in this observation. Verify the radio with its owner before connecting.",
      "!",
    ],
    no_baseline: [
      "Start with a baseline",
      "Choose the networks you own or are authorised to manage. Until then, there is no reference for comparison.",
      "⊞",
    ],
    unavailable: [
      "Scanner unavailable",
      "No fresh observation. Previous data may be stale. This is not a safe signal.",
      "!",
    ],
  };
  class HttpError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }
  async function request(url, options = {}) {
    const controller = new AbortController();
    requests.add(controller);
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      const reader = response.body.getReader(),
        decoder = new TextDecoder();
      let size = 0,
        text = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 2000000) {
          await reader.cancel();
          throw Error("Response exceeds the review limit.");
        }
        text += decoder.decode(value, { stream: true });
      }
      text += decoder.decode();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new HttpError(
          response.status,
          "The data source returned an unreadable response.",
        );
      }
      if (!response.ok)
        throw new HttpError(
          response.status,
          typeof data.message === "string"
            ? data.message.slice(0, 500)
            : "Request failed (" + response.status + ").",
        );
      return data;
    } finally {
      clearTimeout(timeout);
      requests.delete(controller);
    }
  }
  function validState(s) {
    if (
      !s ||
      typeof s !== "object" ||
      !Array.isArray(s.scan) ||
      s.scan.length > 2000 ||
      !Array.isArray(s.incidents) ||
      s.incidents.length > 1000
    )
      throw Error("Invalid observation data.");
    if (
      s.baseline &&
      (!s.baseline.networks ||
        typeof s.baseline.networks !== "object" ||
        Array.isArray(s.baseline.networks))
    )
      throw Error("Invalid baseline data.");
    if (
      s.baseline &&
      Object.values(s.baseline.networks).some(
        (v) =>
          !v ||
          typeof v !== "object" ||
          !v.radios ||
          typeof v.radios !== "object" ||
          Array.isArray(v.radios),
      )
    )
      throw Error("Invalid baseline radios.");
    if (
      s.scan.some(
        (a) =>
          !a ||
          typeof a.ssid !== "string" ||
          typeof a.bssid !== "string" ||
          !Number.isFinite(a.signal_pct) ||
          !Number.isFinite(a.channel) ||
          typeof a.security !== "string" ||
          a.signal_pct < 0 ||
          a.signal_pct > 100 ||
          a.channel < 0 ||
          a.channel > 233 ||
          (a.freq !== undefined && !Number.isFinite(a.freq)),
      )
    )
      throw Error("Invalid radio metadata.");
    if (
      s.incidents.some(
        (i) =>
          !i ||
          typeof i.key !== "string" ||
          typeof i.bssid !== "string" ||
          !Array.isArray(i.evidence) ||
          i.evidence.length > 100 ||
          !Number.isFinite(i.score) ||
          !Number.isFinite(i.sightings) ||
          !["high", "review", "low"].includes(i.level) ||
          i.evidence.some(
            (e) =>
              !e ||
              typeof e.rule !== "string" ||
              typeof e.detail !== "string" ||
              !Number.isFinite(e.points),
          ),
      )
    )
      throw Error("Invalid evidence data.");
    if (
      s.incidents.some(
        (i) =>
          typeof i.active !== "boolean" ||
          i.score < 0 ||
          i.score > 100 ||
          !Number.isInteger(i.sightings) ||
          i.sightings < 1 ||
          i.level !==
            (i.score >= 60 && i.sightings >= 2
              ? "high"
              : i.score >= 30
                ? "review"
                : "low"),
      )
    )
      throw Error("Inconsistent review priority.");
    if (
      s.ssids !== undefined &&
      (!Array.isArray(s.ssids) || s.ssids.some((n) => typeof n !== "string"))
    )
      throw Error("Invalid observed network list.");
    return s;
  }
  function networks() {
    return state?.baseline?.networks || {};
  }
  function reference(a) {
    return own(networks(), a.ssid);
  }
  function approved(a) {
    return !!own(reference(a)?.radios, a.bssid);
  }
  function flagged(a) {
    return (state?.incidents || []).some(
      (i) => i.active && i.bssid === a.bssid && i.level !== "low",
    );
  }
  function incidentsFor(a) {
    return (state?.incidents || []).filter((i) => i.bssid === a.bssid);
  }
  function statusOf(s) {
    if (s.status && HEAD[s.status]) return s.status;
    if (s.incidents.some((i) => i.active && i.level === "high")) return "alert";
    if (s.incidents.some((i) => i.active && i.level === "review"))
      return "review";
    return s.baseline ? "clear" : "no_baseline";
  }
  function ago(t) {
    if (!Number.isFinite(t)) return "no completed scan";
    const seconds = Math.max(0, Math.round(Date.now() / 1000 - t));
    return seconds < 60
      ? seconds + "s ago"
      : Math.floor(seconds / 60) + "m ago";
  }
  function preserveFocus(work) {
    const prior = document.activeElement,
      key = prior?.dataset?.focus || prior?.id;
    work();
    if (prior && !prior.isConnected && key) {
      const target =
        [...document.querySelectorAll("[data-focus]")].find(
          (e) => e.dataset.focus === key,
        ) || document.getElementById(key);
      if (target) target.focus({ preventScroll: true });
      else $("#alertsTitle").focus({ preventScroll: true });
    }
  }
  function render(s) {
    validState(s);
    state = s;
    if (!s.scan.some((a) => a.bssid === selected))
      selected = (s.scan.find(flagged) || s.scan[0])?.bssid || "";
    const k = statusOf(s),
      head = HEAD[k];
    $("#status").className = "status-strip s-" + k;
    $("#headline").textContent = head[0];
    $("#statusMark").textContent = head[2];
    $("#sub").textContent =
      typeof s.error === "string" ? s.error.slice(0, 2000) : head[1];
    $("#retry").hidden = k !== "unavailable" || mode === "demo";
    const active = s.incidents.filter((i) => i.active).length;
    $("#radioCount").textContent = s.scan.length;
    $("#networkCount").textContent = Object.keys(networks()).length;
    $("#findingCount").textContent = active;
    $("#navCount").textContent = active;
    $("#meta1").textContent =
      mode === "demo"
        ? "Fixture cycle " + number(s.cycle) + " of " + fixture.frames.length
        : "Observation " + number(s.cycle);
    $("#meta2").textContent =
      mode === "demo"
        ? "Paused data source, not your Wi-Fi"
        : mode === "replay"
          ? "Local fixture · every " + number(s.interval) + "s"
          : "Last scan " + ago(s.last_scan_at);
    if (mode === "demo" && playing)
      $("#meta2").textContent = "Playing the labelled fixture";
    $("#scanMeta").textContent =
      (k === "unavailable" ? "Previous: " : "") + s.scan.length + " radios";
    preserveFocus(() => {
      drawPlot();
      renderSelection();
      renderAlerts();
      renderTable();
      renderBaseline();
    });
  }
  function renderSelection() {
    const a = state.scan.find((a) => a.bssid === selected),
      box = $("#selectedRadio");
    if (!a) {
      box.innerHTML =
        '<strong>No radio selected</strong><span class="selected-meta">Waiting for an observation.</span>';
      return;
    }
    const i = incidentsFor(a).find((i) => i.active);
    box.innerHTML =
      "<div><strong>" +
      esc(name(a)) +
      "</strong><br><code>" +
      esc(a.bssid) +
      "</code></div>" +
      (i
        ? '<span class="selected-score">' +
          number(i.score) +
          " review points</span>"
        : '<span class="panel-tag">' +
          (approved(a) ? "In baseline" : "Not in baseline") +
          "</span>") +
      '<div class="selected-meta"><span>' +
      esc(band(a)) +
      " · channel " +
      number(a.channel) +
      "</span><span>" +
      strength(a.signal_pct) +
      "% signal</span><span>" +
      esc(a.security) +
      "</span></div>";
  }
  function drawPlot() {
    const root = $("#spectrum"),
      groups = new Map();
    for (const a of state.scan) {
      const key = band(a);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(a);
    }
    if (!groups.size) {
      root.innerHTML = '<div class="empty">No observed radios to plot.</div>';
      return;
    }
    const width = root.clientWidth - 38,
      cols = width >= 456 ? 2 : 1,
      W = Math.max(170, Math.round((width - (cols - 1) * 16) / cols)),
      H = 193,
      L = 30,
      R = W - 10,
      T = 15,
      B = 156;
    root.innerHTML = [...groups]
      .sort((a, b) => parseFloat(a[0]) - parseFloat(b[0]))
      .map(([group, aps]) => {
        const bounds =
          group === "2.4 GHz"
            ? [1, 14]
            : group === "5 GHz"
              ? [32, 177]
              : [1, 233];
        const ticks =
          group === "2.4 GHz"
            ? [1, 6, 11, 14]
            : group === "5 GHz"
              ? [36, 100, 149, 177]
              : [1, 77, 149, 233];
        const x = (c) =>
            L + ((number(c) - bounds[0]) / (bounds[1] - bounds[0])) * (R - L),
          y = (v) => B - (strength(v) / 100) * (B - T);
        const grid = [0, 50, 100]
          .map(
            (v) =>
              '<line class="plot-grid" x1="' +
              L +
              '" x2="' +
              R +
              '" y1="' +
              y(v) +
              '" y2="' +
              y(v) +
              '"/><text class="plot-axis" x="' +
              (L - 7) +
              '" y="' +
              (y(v) + 3) +
              '" text-anchor="end">' +
              v +
              "</text>",
          )
          .join("");
        const axis = ticks
          .map(
            (c) =>
              '<line class="plot-grid" x1="' +
              x(c) +
              '" x2="' +
              x(c) +
              '" y1="' +
              T +
              '" y2="' +
              B +
              '"/><text class="plot-axis" x="' +
              x(c) +
              '" y="' +
              (B + 17) +
              '" text-anchor="middle">' +
              c +
              "</text>",
          )
          .join("");
        const dots = aps
          .filter((a) => a.channel >= bounds[0] && a.channel <= bounds[1])
          .map((a) => {
            const cls = flagged(a)
                ? "flagged"
                : approved(a)
                  ? "approved"
                  : "other",
              chosen = selected === a.bssid;
            return (
              '<line class="plot-stem ' +
              cls +
              '" x1="' +
              x(a.channel) +
              '" x2="' +
              x(a.channel) +
              '" y1="' +
              B +
              '" y2="' +
              y(a.signal_pct) +
              '"/>' +
              (chosen
                ? '<circle class="plot-halo" cx="' +
                  x(a.channel) +
                  '" cy="' +
                  y(a.signal_pct) +
                  '" r="10"/>'
                : "") +
              '<circle class="plot-point ' +
              cls +
              (chosen ? " selected" : "") +
              '" cx="' +
              x(a.channel) +
              '" cy="' +
              y(a.signal_pct) +
              '" r="' +
              (flagged(a) ? 5.5 : 4.5) +
              '" tabindex="0" role="button" aria-label="' +
              esc(
                name(a) +
                  ", " +
                  a.bssid +
                  ", channel " +
                  a.channel +
                  ", " +
                  strength(a.signal_pct) +
                  "% signal",
              ) +
              '" aria-pressed="' +
              chosen +
              '" data-radio="' +
              esc(a.bssid) +
              '" data-focus="plot-' +
              esc(a.bssid) +
              '"><title>' +
              esc(
                name(a) +
                  " · " +
                  a.bssid +
                  " · " +
                  strength(a.signal_pct) +
                  "%",
              ) +
              "</title></circle>"
            );
          })
          .join("");
        const omitted = aps.filter(
          (a) => a.channel < bounds[0] || a.channel > bounds[1],
        ).length;
        return (
          '<div class="band-block"><h3>' +
          esc(group) +
          "<span>" +
          aps.length +
          ' radios</span></h3><svg viewBox="0 0 ' +
          W +
          " " +
          H +
          '" role="group" aria-label="' +
          esc(group) +
          ' channel and signal plot">' +
          grid +
          axis +
          dots +
          '<text class="plot-axis" x="' +
          (L + R) / 2 +
          '" y="' +
          (H - 2) +
          '" text-anchor="middle">Channel</text><text class="plot-axis" x="' +
          L +
          '" y="8">Signal %</text></svg>' +
          (omitted
            ? '<p class="plot-note">' +
              omitted +
              " radio" +
              (omitted === 1 ? " has" : "s have") +
              " an unavailable or out-of-range channel. See the inventory.</p>"
            : "") +
          "</div>"
        );
      })
      .join("");
  }
  function renderAlerts() {
    const all = state.incidents,
      items = filter === "active" ? all.filter((i) => i.active) : all;
    $("#alertCount").textContent =
      items.length + (filter === "active" ? " present" : " recorded");
    const stale = statusOf(state) === "unavailable";
    $("#alerts").innerHTML =
      (stale
        ? '<p class="stale-label">Previous observations. Scanner contact is unavailable.</p>'
        : "") +
      (items.length
        ? items.map(alertHtml).join("")
        : '<div class="empty"><strong>' +
          (filter === "active"
            ? "Nothing in this queue."
            : "No recorded findings.") +
          "</strong>" +
          (state.baseline
            ? "No " +
              (filter === "active" ? "present " : "") +
              "rule findings in this observation. This is not proof of safe Wi-Fi."
            : "Approve a baseline before comparing observations.") +
          "</div>");
  }
  function alertHtml(i) {
    const base = own(networks(), i.ssid),
      observed = state.scan.find((a) => a.bssid === i.bssid),
      canAck = mode === "live" && statusOf(state) !== "unavailable";
    const comparison = base
      ? '<div class="comparison"><div><span>Approved security</span><b>' +
        esc(base.security) +
        '</b></div><i aria-hidden="true">→</i><div><span>Observed security</span><b>' +
        esc(i.security) +
        "</b></div></div>"
      : "";
    return (
      '<article class="alert ' +
      i.level +
      (i.active ? "" : " gone") +
      '" data-incident="' +
      esc(i.key) +
      '"><div class="a-top"><div class="a-name"><h3>' +
      esc(i.ssid || "(hidden name)") +
      "</h3><code>" +
      esc(i.bssid) +
      '</code><span class="badge">' +
      esc(i.label || i.level) +
      '</span></div><div class="score"><b>' +
      Math.max(0, Math.min(100, number(i.score))) +
      "</b><span>review score</span></div></div>" +
      comparison +
      '<ul class="ev">' +
      i.evidence
        .map(
          (e) =>
            '<li><span class="pts">+' +
            number(e.points) +
            "</span><div><b>" +
            esc(e.rule) +
            "</b><span>" +
            esc(e.detail) +
            "</span></div></li>",
        )
        .join("") +
      '</ul><div class="a-foot"><span>' +
      number(i.sightings) +
      " sighting" +
      (i.sightings === 1 ? "" : "s") +
      "</span><span>" +
      (i.active ? "Present in this observation" : "No longer observed") +
      "</span><span>Ch " +
      number(i.channel) +
      " · " +
      esc(i.band) +
      "</span>" +
      (observed
        ? '<button class="text-button" data-inspect="' +
          esc(i.bssid) +
          '" data-focus="inspect-' +
          esc(i.key) +
          '" type="button">Inspect radio ↗</button>'
        : "") +
      (i.acked
        ? '<span class="acknowledged">Acknowledged</span>'
        : canAck
          ? '<button class="ack" data-ack="' +
            esc(i.key) +
            '" data-focus="ack-' +
            esc(i.key) +
            '" type="button"' +
            (pendingAcks.has(i.key) ? " disabled" : "") +
            ">" +
            (pendingAcks.has(i.key) ? "Saving…" : "Acknowledge") +
            "</button>"
          : "") +
      "</div></article>"
    );
  }
  function renderTable() {
    const query = $("#radioSearch").value.toLocaleLowerCase(),
      rows = state.scan
        .slice()
        .sort((a, b) => b.signal_pct - a.signal_pct)
        .filter((a) =>
          (name(a) + " " + a.bssid).toLocaleLowerCase().includes(query),
        );
    $("#scanTbl tbody").innerHTML =
      rows
        .map((a) => {
          const known = approved(a),
            bad = flagged(a),
            mark = bad
              ? "Needs review"
              : known
                ? "In baseline"
                : "Not in baseline";
          return (
            '<tr class="' +
            (selected === a.bssid ? "selected " : "") +
            (bad ? "f" : "") +
            '"><th scope="row"><button type="button" class="radio-select" data-radio="' +
            esc(a.bssid) +
            '" data-focus="row-' +
            esc(a.bssid) +
            '" aria-pressed="' +
            (selected === a.bssid) +
            '"><b>' +
            esc(name(a)) +
            "</b><code>" +
            esc(a.bssid) +
            '</code></button></th><td><span class="row-mark ' +
            (bad ? "flag" : known ? "known" : "") +
            '">' +
            mark +
            "</span></td><td>" +
            number(a.channel) +
            ' <span class="sr-only">on ' +
            esc(band(a)) +
            '</span></td><td><span class="signal-value"><svg class="strength-meter" viewBox="0 0 50 5" aria-hidden="true"><rect width="50" height="5" rx="2.5"/><rect width="' +
            strength(a.signal_pct) / 2 +
            '" height="5" rx="2.5"/></svg>' +
            strength(a.signal_pct) +
            '%</span></td><td><span class="security-pill ' +
            (a.security === "OPEN" ? "open" : "") +
            '">' +
            esc(a.security) +
            "</span></td></tr>"
          );
        })
        .join("") ||
      '<tr><td colspan="5">' +
        (query
          ? "No matching radios. Try a different name or address."
          : "No radio metadata available.") +
        "</td></tr>";
    $("#searchResult").textContent = query
      ? rows.length + " of " + state.scan.length + " radios match."
      : "";
  }
  function renderBaseline() {
    const entries = Object.entries(networks());
    $("#blMeta").textContent = entries.length
      ? entries.length + " network" + (entries.length === 1 ? "" : "s")
      : "Not set";
    $("#baselineList").innerHTML =
      entries
        .map(
          ([ssid, v]) =>
            '<div class="baseline-item"><span class="baseline-icon" aria-hidden="true">⌁</span><div class="baseline-names"><b>' +
            esc(ssid) +
            "</b><p>" +
            Object.keys(v.radios || {}).length +
            " approved radio" +
            (Object.keys(v.radios || {}).length === 1 ? "" : "s") +
            "</p></div><span>" +
            esc(v.security) +
            "</span></div>",
        )
        .join("") ||
      '<p class="baseline-empty">No approved reference yet. Two completed scans are needed before a baseline can be saved.</p>';
    $("#approveBox").hidden = mode !== "live";
    if (mode !== "live") return;
    const available = [
        ...new Set((state.ssids || []).filter((n) => typeof n === "string")),
      ].sort(),
      signature = JSON.stringify(available);
    if ($("#ssidPick").dataset.names !== signature) {
      const chosen = new Set(
        [...document.querySelectorAll("#ssidPick input:checked")].map(
          (e) => e.value,
        ),
      );
      $("#ssidPick").innerHTML =
        available
          .map(
            (ssid, index) =>
              '<label><input type="checkbox" value="' +
              esc(ssid) +
              '" data-focus="ssid-' +
              index +
              '"' +
              (chosen.has(ssid) ? " checked" : "") +
              ">" +
              esc(ssid) +
              "</label>",
          )
          .join("") || "<p>No network names in the current observation.</p>";
      $("#ssidPick").dataset.names = signature;
      if ([...chosen].some((n) => !available.includes(n)))
        $("#approveMsg").textContent =
          "A selected network is no longer in the current list. Review your selection.";
    }
    const stale = statusOf(state) === "unavailable";
    $("#approve").disabled = stale || $("#approve").dataset.pending === "true";
    for (const input of document.querySelectorAll("#ssidPick input"))
      input.disabled = stale;
  }
  function selectRadio(address, announce = true) {
    if (!state?.scan.some((a) => a.bssid === address)) return;
    selected = address;
    preserveFocus(() => {
      drawPlot();
      renderSelection();
      renderTable();
    });
    if (announce) {
      const a = state.scan.find((a) => a.bssid === address);
      $("#actionStatus").textContent =
        "Selected " +
        name(a) +
        ", " +
        a.bssid +
        ", " +
        strength(a.signal_pct) +
        "% signal.";
    }
  }
  $("#spectrum").addEventListener("click", (e) => {
    const target = e.target.closest("[data-radio]");
    if (target) selectRadio(target.dataset.radio);
  });
  $("#spectrum").addEventListener("keydown", (e) => {
    if (
      (e.key === "Enter" || e.key === " ") &&
      e.target.matches("[data-radio]")
    ) {
      e.preventDefault();
      selectRadio(e.target.dataset.radio);
    }
  });
  $("#scanTbl").addEventListener("click", (e) => {
    const target = e.target.closest("[data-radio]");
    if (target) selectRadio(target.dataset.radio);
  });
  $("#radioSearch").addEventListener("input", () => {
    if (state) renderTable();
  });
  document.querySelectorAll("[data-filter]").forEach((button) =>
    button.addEventListener("click", () => {
      filter = button.dataset.filter;
      document
        .querySelectorAll("[data-filter]")
        .forEach((b) => b.setAttribute("aria-pressed", String(b === button)));
      if (state) renderAlerts();
    }),
  );
  $("#alerts").addEventListener("click", (e) => {
    const inspect = e.target.closest("[data-inspect]"),
      ack = e.target.closest("[data-ack]");
    if (inspect) {
      selectRadio(inspect.dataset.inspect);
      $("#selectedRadio").scrollIntoView({ block: "nearest" });
    }
    if (ack) void acknowledge(ack.dataset.ack);
  });
  async function acknowledge(key) {
    if (
      mode !== "live" ||
      pendingAcks.has(key) ||
      statusOf(state) === "unavailable"
    )
      return;
    pendingAcks.add(key);
    preserveFocus(renderAlerts);
    $("#actionStatus").textContent = "Saving acknowledgment…";
    try {
      const result = await request("/api/ack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key }),
      });
      if (result.ok !== true) throw Error("Not confirmed");
      $("#actionStatus").textContent =
        "Acknowledgment saved. It does not change the evidence or review score.";
      await poll();
    } catch {
      $("#actionStatus").textContent =
        "Acknowledgment unconfirmed. Check the observation before retrying. No automatic write retry.";
    } finally {
      pendingAcks.delete(key);
      if (state) preserveFocus(renderAlerts);
    }
  }
  $("#approve").addEventListener("click", async () => {
    if (
      mode !== "live" ||
      !state ||
      statusOf(state) === "unavailable" ||
      $("#approve").dataset.pending === "true"
    )
      return;
    const ssids = [...document.querySelectorAll("#ssidPick input:checked")].map(
      (i) => i.value,
    );
    if (!ssids.length) {
      $("#approveMsg").textContent = "Choose at least one network you manage.";
      return;
    }
    $("#approve").dataset.pending = "true";
    $("#approve").disabled = true;
    $("#approveMsg").textContent = "Saving the selected baseline…";
    try {
      const result = await request("/api/baseline/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ssids }),
      });
      if (result.ok !== true) throw Error("Approval was not confirmed.");
      $("#approveMsg").textContent =
        "Baseline saved from recent scans. It replaces the previous baseline.";
      await poll();
    } catch (e) {
      $("#approveMsg").textContent =
        e instanceof HttpError && e.status === 409
          ? e.message
          : "Approval unconfirmed. Check the baseline before retrying. No automatic write retry.";
    } finally {
      $("#approve").dataset.pending = "false";
      $("#approve").disabled = statusOf(state) === "unavailable";
    }
  });
  const captions = [
    [
      1,
      "The approved radios are the reference. No review-level mismatch has appeared.",
    ],
    [
      9,
      "An unfamiliar address uses an approved name with weaker security. One sighting is still only Review.",
    ],
    [
      10,
      "The same radio is seen again. Repeated evidence raises the review priority, not certainty.",
    ],
    [
      13,
      "An approved radio also changes channel. Its 12-point finding stays low priority.",
    ],
    [
      17,
      "A lookalike name appears. Its evidence is separate from the unfamiliar-radio incident.",
    ],
  ];
  function setPlaying(value) {
    playing = value;
    clearInterval(timer);
    timer = null;
    $("#play").setAttribute("aria-pressed", String(value));
    $("#play").innerHTML = value
      ? 'Pause sequence <span aria-hidden="true">Ⅱ</span>'
      : 'Play sequence <span aria-hidden="true">▶</span>';
    $("#mode").textContent = "Fixture lab · " + (value ? "playing" : "paused");
    if (value)
      timer = setInterval(() => {
        if (frame >= fixture.frames.length - 1) {
          setPlaying(false);
          showFrame(frame);
          return;
        }
        showFrame(frame + 1);
      }, 1800);
    if (state)
      $("#meta2").textContent = value
        ? "Playing the labelled fixture"
        : "Paused data source, not your Wi-Fi";
  }
  function showFrame(index) {
    frame = Math.max(0, Math.min(fixture.frames.length - 1, Math.trunc(index)));
    const f = fixture.frames[frame];
    render({ ...f, baseline: fixture.baseline, interval: fixture.interval });
    $("#cyc").textContent = f.cycle;
    $("#range").value = f.cycle;
    const current = frame + 1;
    let chapter = 1;
    for (const value of [1, 9, 10, 17]) if (current >= value) chapter = value;
    document
      .querySelectorAll("[data-cycle]")
      .forEach((b) =>
        b.setAttribute("aria-pressed", String(+b.dataset.cycle === chapter)),
      );
    $("#chapterCaption").textContent =
      captions.filter(([start]) => current >= start).at(-1)?.[1] ||
      "Labelled fixture data.";
  }
  $("#range").addEventListener("input", (e) => {
    if (!fixture) return;
    setPlaying(false);
    showFrame(+e.target.value - 1);
  });
  $("#play").addEventListener("click", () => {
    if (!fixture) return;
    if (frame === fixture.frames.length - 1 && !playing) showFrame(0);
    setPlaying(!playing);
  });
  document.querySelectorAll("[data-cycle]").forEach((button) =>
    button.addEventListener("click", () => {
      if (!fixture) return;
      setPlaying(false);
      showFrame(+button.dataset.cycle - 1);
    }),
  );
  async function loadFixture() {
    const data = await request("demo.json");
    if (
      data?.fixture !== true ||
      !Array.isArray(data.frames) ||
      !data.frames.length ||
      data.frames.length > 1000
    )
      throw Error("Invalid fixture data.");
    for (const f of data.frames) validState({ ...f, baseline: data.baseline });
    fixture = data;
    mode = "demo";
    $("#sourceText").textContent =
      "Fixture lab. Scripted test data, not a scan of your Wi-Fi. Real scanning runs only on your laptop.";
    $("#replayCard").hidden = false;
    $("#cycN").textContent = data.frames.length;
    $("#range").max = data.frames.length;
    setPlaying(false);
    showFrame(Math.min(9, data.frames.length - 1));
  }
  function unavailable(message) {
    const prior = state || {
      scan: [],
      incidents: [],
      baseline: null,
      cycle: 0,
      interval: 10,
    };
    render({ ...prior, status: "unavailable", error: message });
  }
  async function poll() {
    if (polling || disposed || !["live", "replay", "connecting"].includes(mode))
      return;
    polling = true;
    try {
      const s = validState(await request("/api/state", { cache: "no-store" }));
      if (!["live", "replay"].includes(s.mode))
        throw Error("Unknown local mode.");
      mode = s.mode;
      localLabels();
      render(s);
    } catch {
      unavailable(
        "Lost contact with the local scanner. Previous observations are stale. No automatic approval or acknowledgment is attempted.",
      );
    } finally {
      polling = false;
    }
  }
  function localLabels() {
    $("#mode").textContent =
      mode === "replay" ? "Local fixture replay" : "Local scanner";
    $("#sourceText").textContent =
      mode === "replay"
        ? "Local replay of a labelled fixture. This is not a hardware scan. The server advances its own observations."
        : "Local scanner. Access-point metadata comes from this machine. Baseline and alert records stay on this machine.";
    $("#open-local-inline").hidden = true;
    $("#replayCard").hidden = true;
  }
  async function start() {
    const loopback = ["localhost", "127.0.0.1"].includes(location.hostname),
      forced = new URLSearchParams(location.search).get("demo") === "1";
    if (!loopback || forced) {
      await loadFixture();
      return;
    }
    mode = "connecting";
    try {
      const s = validState(await request("/api/state", { cache: "no-store" }));
      if (!["live", "replay"].includes(s.mode))
        throw Error("Unknown local mode.");
      mode = s.mode;
      localLabels();
      render(s);
      pollTimer = setInterval(poll, 3000);
    } catch (e) {
      if (e instanceof HttpError && e.status === 404) {
        await loadFixture();
        return;
      }
      $("#mode").textContent = "Source unavailable";
      $("#sourceText").textContent =
        "Could not confirm the local scanner. No live observation is being claimed.";
      unavailable(
        "Could not read the local scanner. Start the Python server, then retry.",
      );
    }
  }
  $("#retry").addEventListener("click", async () => {
    if (polling) return;
    await poll();
    if (["live", "replay"].includes(mode) && !pollTimer)
      pollTimer = setInterval(poll, 3000);
  });
  function bindDialog(id, buttons) {
    const dialog = document.getElementById(id);
    let invoker = null;
    for (const selector of buttons)
      $(selector).addEventListener("click", () => {
        invoker = document.activeElement;
        dialog.showModal();
        dialog.scrollTop = 0;
        dialog.querySelector("[data-close]").focus();
      });
    dialog
      .querySelector("[data-close]")
      .addEventListener("click", () => dialog.close());
    dialog.addEventListener("click", (e) => {
      if (e.target !== dialog) return;
      const r = dialog.getBoundingClientRect();
      if (
        e.clientX < r.left ||
        e.clientX > r.right ||
        e.clientY < r.top ||
        e.clientY > r.bottom
      )
        dialog.close();
    });
    dialog.addEventListener("close", () => {
      if (invoker?.isConnected) invoker.focus({ preventScroll: true });
    });
    dialog.addEventListener("keydown", (e) => {
      if (e.key !== "Tab") return;
      const focusable = [
        ...dialog.querySelectorAll(
          'button:not(:disabled),a[href],input:not(:disabled),[tabindex="0"]',
        ),
      ].filter((x) => x.getClientRects().length);
      const first = focusable[0],
        last = focusable.at(-1);
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    });
  }
  bindDialog("methodDialog", [
    "#open-method",
    "#open-method-top",
    "#open-method-bottom",
  ]);
  bindDialog("localDialog", ["#open-local", "#open-local-inline"]);
  $("#copyCommand").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("#runCommand").textContent);
      $("#copyCommand").textContent = "Copied";
      $("#copyStatus").textContent = "Commands copied.";
    } catch {
      $("#copyStatus").textContent =
        "Clipboard unavailable. Select the commands above to copy them.";
    }
  });
  const observer = new ResizeObserver(() => {
    if (state) preserveFocus(drawPlot);
  });
  observer.observe($("#spectrum"));
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && mode === "demo" && playing) setPlaying(false);
  });
  window.addEventListener("pagehide", () => {
    disposed = true;
    clearInterval(timer);
    clearInterval(pollTimer);
    observer.disconnect();
    for (const c of requests) c.abort();
  });
  start().catch(() => {
    $("#mode").textContent = "Fixture unavailable";
    $("#sourceText").textContent =
      "The labelled fixture could not be loaded. This is not a live scan.";
    unavailable(
      "Could not load the fixture. Reload the page or run the Python replay locally.",
    );
    $("#retry").hidden = true;
  });
})();
