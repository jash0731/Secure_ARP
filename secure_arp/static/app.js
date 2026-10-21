(() => {
  "use strict";
  const $ = (selector) => document.querySelector(selector);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[character]));
  const names = {
    "IP-MAC_BINDING_CONFLICT": "IP–MAC conflict",
    "AUTHENTICATION_FAILURE": "Authentication failure",
    "REPLAY_SUSPECTED": "Repeated authenticated reply",
    "ARP_REPLY_FLOOD": "ARP reply flood",
    "GRATUITOUS_ARP_FLOOD": "ARP reply flood"
  };
  const colors = ["#ff9096", "#d6b7fa", "#70e0c1", "#eac57d", "#75b6e9"];
  const count = (value) => Number(value || 0).toLocaleString();
  const localTime = (value) => new Date(value * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
  const localDate = (value) => new Date(value * 1000).toLocaleDateString([], {month: "short", day: "numeric"});
  let state = null, cursor = null, offset = 0, paused = false, refreshTimer = null;
  let loadNumber = 0, toastTimer = null, lastAlert = -Infinity, audio = null, sound = false;
  let desktopEnabled = false;
  const csrf = $('meta[name="csrf-token"]').content;

  function toast(message, error = false) {
    const element = $("#toast");
    element.textContent = message;
    element.classList.toggle("error", error);
    element.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => element.classList.add("hidden"), error ? 6500 : 4200);
  }

  function filterParams() {
    const params = new URLSearchParams();
    for (const [key, value] of new FormData($("#filters"))) {
      if (!value) continue;
      params.set(key, key === "from" || key === "to" ? new Date(value).toISOString() : value);
    }
    return params;
  }

  async function post(path, value) {
    const response = await fetch(path, {
      method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
      body: JSON.stringify(value)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The change could not be saved");
    return data;
  }

  function renderTimeline(points) {
    const element = $("#timeline");
    if (!points.length) {
      element.innerHTML = '<div class="chart-empty">No events in this selection.</div>';
      return;
    }
    const maximum = Math.max(...points.map((point) => point.count), 1);
    const step = 500 / Math.max(points.length, 1);
    const width = Math.min(32, step * 0.55);
    let svg = '<svg viewBox="0 0 580 170" role="img" aria-label="Selected events per active minute">';
    for (let index = 0; index <= 3; index++) {
      const y = 15 + index * 40;
      svg += '<line x1="42" y1="' + y + '" x2="563" y2="' + y + '" stroke="#253342" stroke-dasharray="3 5"/>';
      svg += '<text x="30" y="' + (y + 3) + '" fill="#768ea3" text-anchor="end" font-size="9">' + Math.round(maximum * (3 - index) / 3) + "</text>";
    }
    points.forEach((point, index) => {
      const x = 52 + index * step + step / 2 - width / 2;
      const height = point.count / maximum * 117;
      svg += '<rect x="' + x + '" y="' + (135 - height) + '" width="' + width + '" height="' + Math.max(height, 2) + '" rx="3" fill="#70e0c1" opacity=".85"><title>' +
        esc(localDate(point.time) + " " + localTime(point.time) + ": " + point.count + " events") + "</title></rect>";
      if (index === 0 || index === points.length - 1 || (points.length > 5 && index === Math.floor(points.length / 2))) {
        const label = new Date(point.time * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
        svg += '<text x="' + (x + width / 2) + '" y="157" fill="#7f96a9" text-anchor="middle" font-size="9">' + esc(label) + "</text>";
      }
    });
    element.innerHTML = svg + "</svg>";
  }

  function renderEvents(data) {
    const summary = data.summary;
    $("#metric-devices").textContent = count(summary.devices);
    $("#metric-critical").textContent = count(summary.critical);
    $("#metric-events").textContent = count(summary.events);
    $("#metric-packets").textContent = count(summary.packets);
    $("#approved-count").textContent = count(summary.approved);
    $("#event-total").textContent = count(summary.events);
    renderTimeline(summary.timeline);
    $("#breakdown").innerHTML = Object.entries(summary.types).map(([type, number], index) =>
      '<div class="breakdown-item"><div class="breakdown-label"><span>' + esc(names[type] || type) +
      "</span><strong>" + count(number) + '</strong></div><div class="breakdown-track"><i style="width:' +
      (number / Math.max(summary.events, 1) * 100) + "%;background:" + colors[index % colors.length] + '"></i></div></div>'
    ).join("") || '<div class="chart-empty">No categories to display.</div>';
    $("#event-rows").innerHTML = data.events.map((event) =>
      "<tr><td>" + esc(localTime(event.timestamp)) + "<small>" + esc(localDate(event.timestamp)) +
      '</small></td><td><span class="severity ' + (event.severity === "WARNING" ? "warning" : "") + '">' +
      esc(event.severity) + '</span><div class="event-name">' + esc(names[event.type] || event.type) +
      '</div></td><td class="mono">' + esc(event.src_ip) + '</td><td class="mono">' + esc(event.claimed_mac) +
      (event.trusted_mac ? "<small>Baseline: " + esc(event.trusted_mac) + "</small>" : "") +
      '</td><td><span class="mode">' + esc(event.mode) + '</span><small>' + esc(event.source) +
      '</small></td><td class="detail">' + esc(event.detail) + "</td></tr>"
    ).join("") || '<tr><td colspan="6" class="empty">No matching events. Adjust your filters or start a demonstration.</td></tr>';
    $("#page-info").textContent = summary.events ? count(offset + 1) + "–" + count(offset + data.events.length) +
      " of " + count(summary.events) + " events · local time" : "0 matching events";
    $("#previous").disabled = offset === 0;
    $("#next").disabled = offset + data.limit >= summary.events;
    const params = filterParams().toString();
    $("#export-csv").href = "/api/export.csv?" + params;
    $("#export-html").href = "/api/report.html?" + params;
  }

  function renderDevices(devices) {
    $("#nav-device-count").textContent = count(state.summary.devices);
    $("#device-rows").innerHTML = devices.map((device, index) => {
      const status = device.approved ? "Approved" : device.conflict ? "Conflict" : "Learned";
      return "<tr><td>" + esc(device.label || "Unnamed device") + '<small class="mono">' + esc(device.ip) +
        '</small></td><td class="mono">' + esc(device.mac) + '</td><td><span class="status-tag ' +
        (device.conflict ? "conflict" : device.approved ? "" : "learned") + '">' + status +
        "</span></td><td>" + (device.hits ? esc(localTime(device.last_seen)) + "<small>" +
        esc(localDate(device.last_seen)) + "</small>" : '<small>Not observed yet</small>') +
        "</td><td>" + count(device.hits) + '</td><td><div class="button-row"><button class="secondary" data-action="edit" data-index="' +
        index + '">' + (device.approved ? "Edit" : "Review") + "</button>" +
        (device.approved ? '<button class="text-btn" data-action="revoke" data-index="' + index + '">Unapprove</button>' : "") +
        "</div></td></tr>";
    }).join("") || '<tr><td colspan="6" class="empty">No devices observed yet. You can approve a known mapping using the form.</td></tr>';
  }

  function renderSettings(settings) {
    const entries = [
      ["Flood threshold", settings.flood_threshold + " replies"],
      ["Flood time window", settings.flood_window_seconds + " seconds"],
      ["Recent-binding window", settings.lock_seconds + " seconds"],
      ["Authentication clock tolerance", settings.max_clock_skew_seconds + " seconds"],
      ["Replay cache capacity", count(settings.replay_cache_size) + " authenticated messages"],
      ["Notification cooldown", settings.alert_cooldown_seconds + " seconds"],
      ["Dashboard refresh", settings.refresh_seconds + " seconds"]
    ];
    $("#settings-list").innerHTML = entries.map(([key, value]) => "<dt>" + esc(key) + "</dt><dd>" + esc(value) + "</dd>").join("");
  }

  function notify(events) {
    if (!events.length || Date.now() - lastAlert < state.settings.alert_cooldown_seconds * 1000) return;
    lastAlert = Date.now();
    const event = events[0];
    const title = names[event.type] || "Critical ARP event";
    toast(title + " · " + event.src_ip, true);
    if (desktopEnabled && "Notification" in window && Notification.permission === "granted") {
      new Notification("Secure ARP: " + title, {body: event.src_ip + " — " + event.detail, tag: "secure-arp-critical"});
    }
    if (sound && audio) {
      const oscillator = audio.createOscillator();
      const gain = audio.createGain();
      oscillator.frequency.value = 680;
      gain.gain.setValueAtTime(0.07, audio.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audio.currentTime + 0.2);
      oscillator.connect(gain);
      gain.connect(audio.destination);
      oscillator.start();
      oscillator.stop(audio.currentTime + 0.2);
    }
  }

  async function loadState(silent = false) {
    const request = ++loadNumber;
    try {
      const params = filterParams();
      params.set("offset", offset);
      if (cursor !== null) params.set("since_id", cursor);
      const response = await fetch("/api/state?" + params);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The dashboard could not refresh");
      if (request !== loadNumber) return;
      state = data;
      if (offset > 0 && offset >= data.summary.events) {
        offset = Math.max(0, Math.floor((data.summary.events - 1) / data.limit) * data.limit);
        return loadState(true);
      }
      $("#environment").textContent = data.demo ? "DEMO" : "LOCAL";
      $("#demo-banner").classList.toggle("hidden", !data.demo);
      $("#run-demo").classList.toggle("hidden", !data.demo);
      $("#sidebar-state").textContent = data.demo ? "Demo workspace" : data.status.running ? "Monitor connected" : "Monitor offline";
      $("#sidebar-description").textContent = data.demo ? "Synthetic traffic. Your real network is unchanged." :
        data.status.running ? data.status.interface + " · " + data.status.mode + " mode" : "History is available. Start the capture monitor to receive new events.";
      $("#updated").textContent = "Updated " + localTime(Date.now() / 1000);
      renderEvents(data);
      renderDevices(data.devices);
      renderSettings(data.settings);
      if (cursor !== null && !silent) notify(data.notifications);
      cursor = data.cursor;
      clearTimeout(refreshTimer);
      refreshTimer = setTimeout(tick, data.settings.refresh_seconds * 1000);
    } catch (error) {
      if (request !== loadNumber) return;
      $("#updated").textContent = "Refresh failed";
      toast(error.message, true);
      clearTimeout(refreshTimer);
      refreshTimer = setTimeout(tick, 5000);
    }
  }

  function tick() {
    if (!paused) loadState();
    else refreshTimer = setTimeout(tick, 1000);
  }

  document.querySelectorAll(".nav").forEach((button) => button.addEventListener("click", () => {
    document.querySelectorAll(".nav").forEach((nav) => nav.classList.toggle("active", nav === button));
    document.querySelectorAll(".view").forEach((view) => view.classList.toggle("hidden", view.id !== button.dataset.view + "-view"));
    $("#page-name").textContent = button.dataset.view.charAt(0).toUpperCase() + button.dataset.view.slice(1);
  }));

  let searchTimer;
  $("#filters").addEventListener("submit", (event) => event.preventDefault());
  $("#filters").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {offset = 0; loadState(true);}, 250);
  });
  $("#filters").addEventListener("reset", () => setTimeout(() => {offset = 0; loadState(true);}, 0));
  $("#previous").addEventListener("click", () => {offset = Math.max(0, offset - 50); loadState(true);});
  $("#next").addEventListener("click", () => {offset += 50; loadState(true);});
  $("#refresh-toggle").addEventListener("click", () => {
    paused = !paused;
    $("#refresh-toggle").textContent = paused ? "▶" : "Ⅱ";
    $("#refresh-toggle").title = paused ? "Resume automatic refresh" : "Pause automatic refresh";
    toast(paused ? "Automatic refresh paused" : "Automatic refresh resumed");
    if (!paused) loadState();
  });

  $("#run-demo").addEventListener("click", async () => {
    const button = $("#run-demo");
    button.disabled = true;
    try {
      const result = await post("/api/demo", {});
      offset = 0;
      await loadState(true);
      toast("Demonstration complete: " + result.new_events + " new events from two comparison passes.");
    } catch (error) {toast(error.message, true);}
    finally {button.disabled = false;}
  });

  $("#device-rows").addEventListener("click", async (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    const device = state.devices[Number(button.dataset.index)];
    if (!device) return;
    if (button.dataset.action === "edit") {
      $("#device-ip").value = device.ip;
      $("#device-mac").value = device.mac;
      $("#device-label").value = device.label || "";
      $("#device-label").focus();
      $(".device-form-panel").scrollIntoView({behavior: "smooth", block: "nearest"});
    } else if (confirm("Remove explicit approval for " + device.ip + "? Its learned baseline and history will remain.")) {
      try {await post("/api/devices/revoke", {ip: device.ip}); await loadState(true); toast("Approval removed.");}
      catch (error) {toast(error.message, true);}
    }
  });

  $("#device-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = {ip: $("#device-ip").value.trim(), mac: $("#device-mac").value.trim(), label: $("#device-label").value.trim()};
    const old = state?.devices.find((device) => device.ip === data.ip && device.approved);
    if (old && old.mac !== data.mac.toLowerCase().replaceAll("-", ":") &&
        !confirm("Replace the approved MAC for " + data.ip + " with " + data.mac + "?")) return;
    try {
      await post("/api/devices/approve", data);
      $("#device-form").reset();
      await loadState(true);
      toast("Trusted mapping saved.");
    } catch (error) {toast(error.message, true);}
  });
  $("#device-cancel").addEventListener("click", () => $("#device-form").reset());

  $("#notifications").addEventListener("click", async () => {
    if (!("Notification" in window)) {toast("This browser does not support desktop notifications.", true); return;}
    if (desktopEnabled) {
      desktopEnabled = false;
      $("#notifications").textContent = "Enable notifications";
      toast("Desktop notifications disabled for this page.");
      return;
    }
    const permission = await Notification.requestPermission();
    desktopEnabled = permission === "granted";
    $("#notifications").textContent = desktopEnabled ? "Notifications on" : "Enable notifications";
    toast(desktopEnabled ? "Desktop notifications enabled for new critical events." : "Desktop permission was not granted. In-page alerts remain available.", !desktopEnabled);
  });
  $("#sound").addEventListener("click", async () => {
    try {
      if (!audio) audio = new (window.AudioContext || window.webkitAudioContext)();
      await audio.resume();
      sound = !sound;
      $("#sound").textContent = sound ? "Sound on" : "Sound off";
      toast(sound ? "Sound enabled for new critical events." : "Sound disabled.");
    } catch {toast("Audio is unavailable in this browser.", true);}
  });

  loadState(true);
})();
