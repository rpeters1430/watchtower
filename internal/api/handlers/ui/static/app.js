// Watchtower web UI.
//
// A single page with no build step. It signs in through /ui/session and then
// reads the same /v1/* endpoints any other API client would. All page content
// is built with DOM nodes, never HTML strings, because container and image
// names come from outside.

(() => {
  "use strict";

  const REFRESH_MS = 60_000;
  // Update progress is polled this often while an update runs. Every request
  // counts toward the API's per-IP rate limit, so keep it gentle.
  const ACTIVITY_MS = 3_000;
  const NOTICE_MS = 8_000;
  const SEARCH_THRESHOLD = 8;

  const state = {
    session: null,
    containers: [],
    containersProblem: "",
    containersLoaded: false,
    checks: new Map(),
    checkedAt: null,
    checking: false,
    updating: new Set(),
    activity: null,
    expanded: new Set(),
    search: "",
    waitingOnly: false,
    groupByCompose: false,
    history: null,
    historyProblem: "",
    historyChangesOnly: false,
    config: null,
    configProblem: "",
    settings: null,
    settingsProblem: "",
    notifications: null,
    notificationsProblem: "",
    notifyDraft: { service: "ntfy", name: "", fields: {} },
    notifyBusy: "",
    removingService: "",
    customSchedule: false,
    customScheduleDraft: null,
    editingTag: new Map(),
    acting: new Set(),
    security: null,
    securityProblem: "",
    securityStarting: false,
    scanLogOpen: false,
    securityDetails: new Map(),
    securityExpanded: new Set(),
    securityShowAll: new Set(),
    securityFixableOnly: false,
  };

  const app = document.getElementById("app");
  const notices = document.getElementById("notices");

  // DOM helpers

  function el(tag, props, ...children) {
    const node = document.createElement(tag);

    for (const [key, value] of Object.entries(props || {})) {
      if (value === false || value === null || value === undefined) {
        continue;
      }

      if (key === "class") {
        node.className = value;
      } else if (key === "checked" || key === "selected" || key === "value") {
        node[key] = value;
      } else if (key.startsWith("on")) {
        node.addEventListener(key.slice(2), value);
      } else if (value === true) {
        node.setAttribute(key, "");
      } else {
        node.setAttribute(key, value);
      }
    }

    for (const child of children.flat(Infinity)) {
      if (child === false || child === null || child === undefined) {
        continue;
      }

      node.append(child);
    }

    return node;
  }

  function code(text) {
    return el("code", null, text);
  }

  // Formatting

  const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const exact = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  const clock = new Intl.DateTimeFormat(undefined, { timeStyle: "medium" });
  const clockShort = new Intl.DateTimeFormat(undefined, { timeStyle: "short" });

  function ago(date) {
    const seconds = Math.round((date.getTime() - Date.now()) / 1000);
    const steps = [
      ["day", 86_400],
      ["hour", 3_600],
      ["minute", 60],
    ];

    for (const [unit, size] of steps) {
      if (Math.abs(seconds) >= size) {
        return relative.format(Math.round(seconds / size), unit);
      }
    }

    return "just now";
  }

  function count(number, singular, plural) {
    return `${number} ${number === 1 ? singular : plural || `${singular}s`}`;
  }

  function capitalise(text) {
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  function shortDigest(value) {
    if (!value) {
      return "";
    }

    const hex = value.includes(":") ? value.split(":")[1] : value;

    return hex.slice(0, 12);
  }

  function cleanName(name) {
    return String(name || "").replace(/^\//, "");
  }

  function bytes(value) {
    const units = ["B", "kB", "MB", "GB", "TB"];
    let size = Number(value) || 0;
    let unit = 0;

    while (size >= 1000 && unit < units.length - 1) {
      size /= 1000;
      unit++;
    }

    return `${unit === 0 ? size : size.toFixed(size < 10 ? 1 : 0)} ${units[unit]}`;
  }

  // Notices

  function notify(message, problem) {
    const close = el("button", { class: "notice-close", type: "button" }, "Dismiss");
    const notice = el("div", { class: problem ? "notice notice-problem" : "notice" }, el("span", null, message), close);
    const remove = () => notice.remove();

    close.addEventListener("click", remove);

    // A new confirmation replaces earlier ones. Problems stay until dismissed.
    if (!problem) {
      notices.querySelectorAll(".notice:not(.notice-problem)").forEach((earlier) => earlier.remove());
    }

    notices.append(notice);

    if (!problem) {
      setTimeout(remove, NOTICE_MS);
    }
  }

  // Requests

  class RequestProblem extends Error {
    constructor(message, status) {
      super(message);
      this.status = status;
    }
  }

  async function request(method, path, body) {
    let response;

    try {
      response = await fetch(path, {
        method,
        credentials: "same-origin",
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new RequestProblem("Watchtower isn't responding. Check that it's still running.", 0);
    }

    if (response.status === 401 && !path.startsWith("/ui/")) {
      state.session = { authenticated: false };
      render();

      throw new RequestProblem("Your sign-in has ended. Sign in again.", 401);
    }

    if (response.status === 429 && !path.startsWith("/v1/update")) {
      throw new RequestProblem("Too many requests in the last minute. Wait a moment and try again.", 429);
    }

    const text = await response.text();
    let data = null;

    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }

    if (!response.ok) {
      const reason = (data && data.error) || text || `Watchtower answered with status ${response.status}.`;

      throw new RequestProblem(reason, response.status);
    }

    return data;
  }

  // Data

  function feature(name) {
    return Boolean(state.session && state.session.features && state.session.features[name]);
  }

  async function loadContainers() {
    if (!feature("containers")) {
      return;
    }

    try {
      const data = await request("GET", "/v1/containers/details");

      state.containers = (data.containers || [])
        .map((item) => ({ ...item, name: cleanName(item.name) }))
        .sort((a, b) => a.name.localeCompare(b.name));
      state.containersProblem = "";
    } catch (problem) {
      state.containersProblem = problem.message;
    }

    state.containersLoaded = true;
  }

  // The server keeps each container's latest check or scan result, so every
  // browser sees the same state, including results from scheduled scans.
  async function loadChecks() {
    if (!feature("check")) {
      return;
    }

    try {
      const data = await request("GET", "/v1/check");
      const next = new Map();

      for (const item of data.containers || []) {
        const name = cleanName(item.name);
        const local = state.checks.get(name);

        // Keep a change this page made that the server hasn't recorded yet.
        next.set(name, local && new Date(local.timestamp) > new Date(item.timestamp) ? local : item);
      }

      state.checks = next;
      state.checkedAt = data.checked_at ? new Date(data.checked_at) : null;
    } catch {
      // Older results stay on the page; the next refresh tries again.
    }
  }

  // Marks containers as up to date straight after this page updated them.
  function markUpdated(names) {
    const now = new Date().toISOString();

    for (const name of names) {
      const check = state.checks.get(name);

      if (check) {
        state.checks.set(name, { ...check, update_available: false, error: "", timestamp: now });
      }
    }
  }

  async function loadHistory() {
    if (!feature("history")) {
      return;
    }

    try {
      // The server keeps at most 500 entries; the Containers view reads each
      // container's own updates out of the whole log.
      const data = await request("GET", "/v1/history");

      state.history = (data.entries || []).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      state.historyProblem = "";
    } catch (problem) {
      state.historyProblem = problem.message;
    }
  }

  async function loadConfig() {
    if (!feature("config")) {
      return;
    }

    try {
      const data = await request("GET", "/v1/config");

      state.config = data.config;
      state.configProblem = "";
    } catch (problem) {
      state.configProblem = problem.message;
    }
  }

  async function loadSettings() {
    if (!feature("settings")) {
      return;
    }

    try {
      state.settings = await request("GET", "/v1/settings");
      state.settingsProblem = "";
    } catch (problem) {
      state.settingsProblem = problem.message;
    }
  }

  async function loadNotifications() {
    if (!feature("settings")) {
      return;
    }

    try {
      state.notifications = await request("GET", "/v1/settings/notifications");
      state.notificationsProblem = "";
    } catch (problem) {
      state.notificationsProblem = problem.message;
    }
  }

  // Update progress

  let activityTimer = null;

  function updateRunning() {
    return state.updating.size > 0 || Boolean(state.activity && state.activity.running);
  }

  function activityFor(name) {
    if (!state.activity || !state.activity.running) {
      return null;
    }

    return (state.activity.containers || []).find((entry) => cleanName(entry.name) === name) || null;
  }

  function scheduleActivity(delay = ACTIVITY_MS) {
    if (!activityTimer && feature("update")) {
      activityTimer = setTimeout(pollActivity, delay);
    }
  }

  async function pollActivity() {
    activityTimer = null;

    if (!feature("update") || !state.session || !state.session.authenticated) {
      return;
    }

    const before = state.activity;
    let data;

    try {
      data = await request("GET", "/v1/update/status");
    } catch {
      // Keep showing the last progress and try again shortly.
      if (updateRunning()) {
        scheduleActivity();
      }

      return;
    }

    // The page's own update finishing resets state.activity; that update has
    // reported itself, so this poll must not report it a second time.
    const resetMeanwhile = state.activity !== before;

    state.activity = data;

    if (!resetMeanwhile && before && before.running && !data.running) {
      await activityEnded(data.last_scan || before);
    }

    if (updateRunning()) {
      scheduleActivity();
    }

    renderProgress();
  }

  // An update this page didn't start (a schedule, another tab, or one started
  // before a reload) has finished, so catch the page up with it. `last` is the
  // server's record of the finished scan, or the last progress seen.
  async function activityEnded(last) {
    const updated = (last.containers || []).filter((entry) => entry.step === "updated").map((entry) => cleanName(entry.name));

    markUpdated(updated);

    if (state.updating.size > 0) {
      // This page's own update request reports the outcome when it returns.
      return;
    }

    await Promise.all([loadContainers(), loadHistory()]);
    await loadChecks();

    if (updated.length > 0) {
      notify(`Updated ${updated.length === 1 ? updated[0] : count(updated.length, "container")}.${updateScanSummary(last.containers || [])}`);
    }

    // Reports now include what each update fixed.
    if (feature("security")) {
      await loadSecurity();
      state.securityDetails.clear();
    }

    render();
  }

  // What a container is doing, in the words the page uses for it.
  function activityStatus(entry) {
    const pull = entry.pull || {};

    switch (entry.step) {
      case "pulling":
        if (pull.phase === "downloading" && pull.total_bytes > 0) {
          return { key: "working", label: `Downloading ${Math.floor((100 * pull.downloaded_bytes) / pull.total_bytes)}%` };
        }

        if (pull.phase === "extracting") {
          return { key: "working", label: "Unpacking" };
        }

        if (pull.phase === "finishing" || pull.phase === "done") {
          return { key: "working", label: "Finishing download" };
        }

        if (pull.phase === "failed") {
          return { key: "failed", label: "Download failed" };
        }

        return { key: "working", label: "Downloading" };
      case "scanning":
        return { key: "working", label: "Scanning" };
      case "scanned":
        return { key: "working", label: "Scanned" };
      case "held":
        return { key: "waiting", label: "Held back" };
      case "stopping":
        return { key: "working", label: "Stopping" };
      case "starting":
        return { key: "working", label: "Starting" };
      case "updated":
        return { key: "fresh", label: "Updated" };
      case "failed":
        return { key: "failed", label: "Couldn't update" };
      default:
        return { key: "working", label: "Updating" };
    }
  }

  // One sentence on what the step is doing, with numbers where Docker gives them.
  function activityDetail(entry) {
    const pull = entry.pull || {};
    const layers = pull.layers ? ` ${pull.layers_done} of ${count(pull.layers, "layer")} in place.` : "";

    switch (entry.step) {
      case "pulling":
        if (pull.phase === "downloading") {
          return pull.total_bytes > 0
            ? `Downloading the new image: ${bytes(pull.downloaded_bytes)} of ${bytes(pull.total_bytes)} so far.${layers}`
            : `Downloading the new image.${layers}`;
        }

        if (pull.phase === "extracting") {
          return `Unpacking the downloaded image.${layers}`;
        }

        if (pull.phase === "finishing" || pull.phase === "done") {
          return "The image is downloaded. Docker is finishing up.";
        }

        return "Asking the registry for the new image.";
      case "scanning":
        return `Checking the new image for known vulnerabilities and comparing it with the running one. ${
          entry.scan && entry.scan.step ? `${entry.scan.step}.` : "Starting the scanner."
        } Images are scanned one at a time.`;
      case "scanned":
        return entry.scan && entry.scan.error
          ? "The new image couldn't be scanned, so it's updated without a review. Waiting its turn to restart."
          : "Scanned. Waiting its turn to restart.";
      case "held":
        return "Held back: the new image adds findings at or above the scan gate, so the container keeps its current image.";
      case "stopping":
        return "Stopping the old container. It gets its stop timeout to shut down cleanly.";
      case "starting":
        return "Creating and starting the new container with the same settings.";
      case "updated":
        return "Running the new image.";
      case "failed":
        return "The update didn't finish. Watchtower's log has the reason.";
      default:
        return "";
    }
  }

  // How an update changes known vulnerabilities, once its scan is done.
  function scanDiffText(scan) {
    if (!scan || !scan.done || scan.error) {
      return "";
    }

    const fixed = total(scan.fixed_counts);
    const introduced = total(scan.introduced_counts);

    if (fixed === 0 && introduced === 0) {
      const latest = total(scan.latest_counts);

      return `The update doesn't change known vulnerabilities${latest > 0 ? ` (the new image has ${count(latest, "finding")})` : ""}.`;
    }

    const parts = [];

    if (fixed > 0) {
      parts.push(`fixes ${count(fixed, "known vulnerability", "known vulnerabilities")} (${severityList(scan.fixed_counts)})`);
    }

    if (introduced > 0) {
      parts.push(`brings in ${count(introduced, "new one")} (${severityList(scan.introduced_counts)})`);
    }

    return `The update ${parts.join(" and ")}.`;
  }

  // One sentence on what the finished update's scans found, for its notice.
  function updateScanSummary(entries) {
    const scanned = entries.filter((entry) => entry.step === "updated" && entry.scan && entry.scan.done && !entry.scan.error);

    if (scanned.length === 0) {
      return "";
    }

    const fixed = scanned.reduce((sum, entry) => sum + total(entry.scan.fixed_counts), 0);
    const introduced = scanned.reduce((sum, entry) => sum + total(entry.scan.introduced_counts), 0);

    if (fixed === 0 && introduced === 0) {
      return " Known vulnerabilities are unchanged.";
    }

    return ` ${capitalise(
      [
        fixed > 0 && `fixed ${count(fixed, "known vulnerability", "known vulnerabilities")}`,
        introduced > 0 && `brought in ${count(introduced, "new one")}`,
      ]
        .filter(Boolean)
        .join(", "),
    )}.`;
  }

  function scanDiff(entry) {
    const text = scanDiffText(entry.scan);

    if (!text) {
      return null;
    }

    // Red only for what the page calls serious elsewhere: new critical or high findings.
    const worse = serious(entry.scan.introduced_counts);

    return el(
      "p",
      { class: worse ? "unit-progress-text scan-diff scan-diff-worse" : "unit-progress-text scan-diff" },
      text,
      feature("security") && [" ", el("a", { class: "link-subtle", href: "#/security" }, "Details")],
    );
  }

  // The bar shows download bytes, then unpacked layers.
  function activityBar(entry) {
    const pull = entry.pull;

    if (entry.step !== "pulling" || !pull) {
      return null;
    }

    let value = null;

    if (pull.phase === "downloading" && pull.total_bytes > 0) {
      value = pull.downloaded_bytes / pull.total_bytes;
    } else if (pull.phase === "extracting" && pull.layers > 0) {
      value = pull.layers_done / pull.layers;
    } else if (pull.phase === "finishing" || pull.phase === "done") {
      value = 1;
    }

    const props = { class: "progress", "aria-label": `Progress for ${cleanName(entry.name)}`, max: "1" };

    // A progress element without a value shows Docker hasn't said how much is left.
    if (value !== null) {
      props.value = String(Math.min(1, Math.max(0, value)));
    }

    return el("progress", props);
  }

  function renderProgress() {
    if (currentView().draw !== containersView) {
      return;
    }

    const slot = document.getElementById("lookout-slot");

    if (slot) {
      slot.replaceChildren(lookout());
    }

    renderManifest();
  }

  async function checkForUpdates() {
    if (state.checking) {
      return;
    }

    state.checking = true;
    render();

    try {
      const data = await request("POST", "/v1/check");

      state.checks = new Map((data.containers || []).map((item) => [cleanName(item.name), item]));
      state.checkedAt = new Date();
      await Promise.all([loadContainers(), loadHistory()]);
    } catch (problem) {
      notify(`Couldn't check for updates. ${problem.message}`, true);
    }

    state.checking = false;
    render();
  }

  // The update endpoint treats each name as an anchored regular expression.
  function exactPattern(name) {
    return name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  async function update(names) {
    const label = names.length === 1 ? names[0] : count(names.length, "container");
    const query = names.map((name) => `container=${encodeURIComponent(exactPattern(name))}`).join("&");

    names.forEach((name) => state.updating.add(name));
    render();
    scheduleActivity(1_000);

    try {
      const data = await request("POST", `/v1/update?${query}`);
      const summary = (data && data.summary) || {};

      if (summary.failed > 0) {
        notify(`Couldn't update ${label}. Watchtower's log has the reason.`, true);
      } else if (summary.updated > 0) {
        notify(`Updated ${label}.`);
      } else {
        notify(`${capitalise(label)} ${names.length === 1 ? "was" : "were"} already up to date.`);
      }

      if (!summary.failed) {
        markUpdated(names);
      }
    } catch (problem) {
      const reason = problem.status === 429 ? "Another update is already running." : problem.message;

      notify(`Couldn't update ${label}. ${reason}`, true);
    }

    names.forEach((name) => state.updating.delete(name));
    names.forEach((name) => state.securityDetails.delete(name));
    // The response above already reported this update, so the next poll
    // must not report it again as one that finished elsewhere.
    state.activity = null;
    await Promise.all([loadContainers(), loadHistory(), feature("security") && loadSecurity()]);
    await loadChecks();
    render();
    if (feature("security") && currentView().draw === securityView) {
      renderSecurity();
    }
  }

  async function containerAction(containerName, action, payload = {}) {
    if (state.acting.has(containerName)) {
      return;
    }

    state.acting.add(containerName);
    render();

    try {
      await request("POST", `/v1/containers/${encodeURIComponent(containerName)}/action`, {
        action,
        ...payload,
      });

      let actionDesc = action;
      if (action === "start") actionDesc = "started";
      else if (action === "stop") actionDesc = "stopped";
      else if (action === "restart") actionDesc = "restarted";
      else if (action === "set_tag") actionDesc = `recreated with tag ${payload.tag || payload.image}`;

      notify(`Container ${containerName} ${actionDesc}.`);
      state.editingTag.delete(containerName);
      await loadContainers();
    } catch (problem) {
      notify(`Action ${action} on ${containerName} failed: ${problem.message}`, true);
    } finally {
      state.acting.delete(containerName);
      render();
    }
  }

  // What a scan did to one container, from the history log.

  const CHANGE_LIMIT = 5;

  // The image change as words, preferring release versions over digests.
  function changeSummary(item) {
    if (item.from_version && item.to_version && item.from_version !== item.to_version) {
      return [" from ", el("strong", null, item.from_version), " to ", el("strong", null, item.to_version)];
    }

    if (item.to_version) {
      return [" to ", el("strong", null, item.to_version)];
    }

    if (item.from_image_id && item.to_image_id) {
      return [" from ", code(shortDigest(item.from_image_id)), " to ", code(shortDigest(item.to_image_id))];
    }

    return [];
  }

  const OUTCOMES = {
    // Colours match the scan bars on the History view.
    updated: { key: "waiting", verb: "updated", change: true },
    available: { key: "waiting", verb: "can be updated", change: true },
    restarted: { key: "unknown", verb: "restarted after a container it depends on was updated" },
    failed: { key: "failed", verb: "failed" },
  };

  // One line saying what happened to a container. `named` leads with the
  // container's name, for lists that cover several containers.
  function changeLine(item, named) {
    const outcome = OUTCOMES[item.outcome] || { key: "unknown", verb: item.outcome };
    const verb = named ? ` ${outcome.verb}` : capitalise(outcome.verb);

    return [
      el("span", { class: `end end-tiny end-${outcome.key}`, "aria-hidden": "true" }),
      el(
        "span",
        null,
        named && el("strong", null, item.name),
        verb,
        outcome.change && changeSummary(item),
        item.error ? `: ${item.error}` : ".",
      ),
    ];
  }

  // The scans that changed or failed on a container, newest first.
  function changesFor(name) {
    const found = [];

    for (const entry of state.history || []) {
      if (entry.kind === "check") {
        continue;
      }

      for (const item of entry.containers || []) {
        if (item.name === name) {
          found.push({ when: new Date(entry.timestamp), item });
        }
      }
    }

    return found;
  }

  function lastUpdated(name) {
    return changesFor(name).find((change) => change.item.outcome === "updated") || null;
  }

  function changeLog(container) {
    if (!feature("history")) {
      return null;
    }

    const changes = changesFor(container.name);
    const title = el("h3", { class: "detail-title" }, "Update history");

    if (changes.length === 0) {
      return el(
        "div",
        { class: "changes" },
        title,
        el("p", { class: "setting-help" }, state.history ? "Watchtower hasn't updated this container in the scans it remembers." : "Loading history."),
      );
    }

    return el(
      "div",
      { class: "changes" },
      title,
      el(
        "ul",
        { class: "change-list" },
        changes.slice(0, CHANGE_LIMIT).map(({ when, item }) =>
          el(
            "li",
            { class: "change" },
            el("time", { class: "change-when", datetime: when.toISOString(), title: exact.format(when) }, capitalise(ago(when))),
            el("span", { class: "change-what" }, changeLine(item, false)),
          ),
        ),
      ),
      changes.length > CHANGE_LIMIT &&
        el("p", { class: "setting-help" }, `${count(changes.length - CHANGE_LIMIT, "older change")} in `, el("a", { href: "#/history" }, "History"), "."),
    );
  }

  // Container state, in the words the page uses for it.

  function describe(container) {
    const check = state.checks.get(container.name);

    const entry = activityFor(container.name);

    if (entry) {
      return activityStatus(entry);
    }

    if (state.updating.has(container.name)) {
      return { key: "working", label: "Waiting to start" };
    }

    if (state.acting.has(container.name)) {
      return { key: "working", label: "Working" };
    }

    if (check && check.error) {
      return { key: "failed", label: check.checked_by === "scan" && check.update_available ? "Update failed" : "Couldn't check" };
    }

    if (check && check.update_available) {
      return { key: "waiting", label: "Update waiting" };
    }

    if (!container.running) {
      return { key: "stopped", label: "Stopped" };
    }

    if (check) {
      return { key: "fresh", label: "Up to date" };
    }

    return { key: "unknown", label: "Not checked yet" };
  }

  // When Watchtower's schedule runs next, or null when nothing is scheduled.
  function nextScan() {
    const settings = state.settings;

    if (!settings || !settings.schedule_active || !settings.next_run) {
      return null;
    }

    const next = new Date(settings.next_run);

    return next > new Date() ? next : null;
  }

  function canUpdate(container) {
    const globalMonitor = Boolean(state.config && state.config.monitor_only);
    const pinned = container.policy === "pinned";

    return feature("update") && !container.monitor_only && !globalMonitor && !pinned;
  }

  function waitingContainers() {
    return state.containers.filter((container) => {
      const check = state.checks.get(container.name);

      return check && check.update_available && !check.error;
    });
  }

  // Confirmation dialog

  function confirmUpdate(containers) {
    const names = containers.map((container) => container.name);
    const single = containers.length === 1;
    const dialog = el("dialog", { class: "confirm", "aria-labelledby": "confirm-title" });
    const close = () => {
      dialog.close();
      dialog.remove();
    };

    dialog.append(
      el(
        "h2",
        { class: "confirm-title", id: "confirm-title" },
        single ? `Update ${names[0]}?` : `Update ${count(names.length, "container")}?`,
      ),
      el(
        "p",
        { class: "confirm-body" },
        single
          ? "Watchtower pulls the new image, stops the container, and starts it again with the same settings. It will be unavailable for a moment."
          : `Watchtower pulls the new images, then stops and restarts each container with the same settings: ${names.join(", ")}.`,
      ),
      el(
        "div",
        { class: "confirm-actions" },
        el("button", { class: "button", type: "button", onclick: close }, "Cancel"),
        el(
          "button",
          {
            class: "button button-primary",
            type: "button",
            onclick: () => {
              close();
              update(names);
            },
          },
          single ? "Update container" : `Update ${count(names.length, "container")}`,
        ),
      ),
    );

    dialog.addEventListener("cancel", () => dialog.remove());
    document.body.append(dialog);
    dialog.showModal();
  }

  // Containers view

  function lookout() {
    const total = state.containers.length;
    const waiting = waitingContainers();
    // The server remembers containers that have since been removed, so count only current ones.
    const unchecked = state.containers.filter((container) => {
      const check = state.checks.get(container.name);

      return check && check.error;
    }).length;
    const updatable = waiting.filter(canUpdate);
    let line;
    let note;
    const activity = state.activity && state.activity.running ? state.activity : null;
    const entries = activity ? activity.containers || [] : [];
    const active = entries.filter((entry) => !["updated", "failed", "held"].includes(entry.step));
    const done = entries.filter((entry) => entry.step === "updated").length;

    if (activity) {
      const started = activity.started_at ? ` Started ${ago(new Date(activity.started_at))}.` : "";

      if (active.length === 1) {
        line = `Updating ${cleanName(active[0].name)}.`;
        note = activityDetail(active[0]) + started;
      } else if (active.length > 1) {
        const names = active.map((entry) => cleanName(entry.name)).join(", ");
        // Containers sharing an image share one download, so its progress speaks for all of them.
        const shared = active.every((entry) => entry.step === active[0].step && entry.image === active[0].image);

        line = `Updating ${count(active.length, "container")}.`;
        note = shared ? `${activityDetail(active[0])} For ${names}.${started}` : `${names}.${started}`;
      } else {
        line = "Checking for new images.";
        note = `Watchtower is comparing each container's image with its registry.${started}`;
      }

      if (done > 0) {
        note += ` ${capitalise(count(done, "container"))} updated so far.`;
      }
    } else if (state.containersProblem && total === 0) {
      line = "The container list didn't load.";
      note = state.containersProblem;
    } else if (!state.containersLoaded) {
      line = "Looking over the yard.";
      note = "Loading the containers Watchtower is watching.";
    } else if (total === 0) {
      line = "No containers on watch.";
      note = "Nothing matches Watchtower's current filter. Settings shows which containers it's set to watch.";
    } else if (!state.checkedAt) {
      line = `${capitalise(count(total, "container"))} on watch.`;
      note = feature("check")
        ? "Check for updates to see which ones have a newer image waiting."
        : "Watchtower is updating these on its own schedule.";
    } else if (waiting.length === 0) {
      line = total === 1 ? "Your container is up to date." : `All ${total} containers are up to date.`;
      note = `Checked ${ago(state.checkedAt)}.`;
    } else {
      line = `${waiting.length} of ${count(total, "container")} ${waiting.length === 1 ? "has" : "have"} an update waiting.`;
      note = `Checked ${ago(state.checkedAt)}.`;
    }

    if (state.checkedAt && unchecked > 0) {
      note += ` ${capitalise(count(unchecked, "container"))} couldn't be checked or updated.`;
    }

    const next = nextScan();

    if (!activity && next) {
      note += ` Next scan ${next - Date.now() < 60_000 ? "in under a minute" : ago(next)}.`;
    }

    return el(
      "header",
      { class: "lookout" },
      el("h1", { class: "lookout-line" }, line),
      el("p", { class: "lookout-note" }, note),
      el(
        "div",
        { class: "actions" },
        feature("check") &&
          total > 0 &&
          el(
            "button",
            {
              class: updatable.length > 0 ? "button" : "button button-primary",
              type: "button",
              disabled: state.checking,
              onclick: checkForUpdates,
            },
            state.checking ? "Checking for updates" : "Check for updates",
          ),
        updatable.length > 1 &&
          el(
            "button",
            {
              class: "button button-primary",
              type: "button",
              disabled: updateRunning(),
              onclick: () => confirmUpdate(updatable),
            },
            `Update all ${updatable.length}`,
          ),
      ),
    );
  }

  function facts(container) {
    const check = state.checks.get(container.name) || {};
    const rows = [];
    const add = (label, value) => {
      if (value) {
        rows.push(el("dt", null, label), el("dd", null, value));
      }
    };
    const link = (href) => (/^https?:\/\//.test(href) ? el("a", { class: "link-subtle", href, rel: "noreferrer", target: "_blank" }, href) : href);

    const isEditingTag = state.editingTag.has(container.name);
    let imageCell;

    if (!container.watchtower) {
      if (isEditingTag) {
        const input = el("input", {
          class: "tag-input",
          type: "text",
          value: state.editingTag.get(container.name) || container.image,
          placeholder: "e.g. latest, 1.40.1, or full image",
          oninput: (e) => state.editingTag.set(container.name, e.target.value),
        });

        imageCell = el(
          "div",
          { class: "tag-field-wrapper" },
          el(
            "div",
            { class: "tag-edit-form" },
            input,
            el(
              "button",
              {
                class: "button button-primary button-tiny",
                type: "button",
                disabled: state.acting.has(container.name),
                onclick: async () => {
                  const val = input.value.trim();
                  if (!val) {
                    notify("Image tag or reference cannot be empty.", true);
                    return;
                  }
                  await containerAction(container.name, "set_tag", { tag: val });
                },
              },
              state.acting.has(container.name) ? "Recreating..." : "Apply & Recreate",
            ),
            el(
              "button",
              {
                class: "button button-quiet button-tiny",
                type: "button",
                disabled: state.acting.has(container.name),
                onclick: () => {
                  state.editingTag.delete(container.name);
                  renderManifest();
                },
              },
              "Cancel",
            ),
          ),
          el("p", { class: "tag-help" }, "Pulls the new image/tag, then recreates the container keeping all ports, volumes, and environment variables."),
        );
      } else {
        imageCell = el(
          "div",
          { class: "tag-field-row" },
          code(container.image),
          el(
            "button",
            {
              class: "button button-quiet button-tiny",
              type: "button",
              disabled: state.acting.has(container.name),
              "aria-label": `Edit tag for ${container.name}`,
              onclick: () => {
                state.editingTag.set(container.name, container.image);
                renderManifest();
              },
            },
            "Edit tag",
          ),
        );
      }
    } else {
      imageCell = code(container.image);
    }

    add("Image", imageCell);

    if (check.current_image_version || check.latest_image_version) {
      add(
        "Version",
        check.update_available && check.latest_image_version
          ? `${check.current_image_version || "unknown"}, with ${check.latest_image_version} waiting`
          : check.current_image_version,
      );
    }

    add("Running digest", container.digest && code(shortDigest(container.digest)));
    add("Newest digest", check.update_available && check.latest_digest && code(shortDigest(check.latest_digest)));
    add("Image ID", container.image_id && code(shortDigest(container.image_id)));
    if (container.compose_project) {
      add("Compose stack", `${container.compose_project}${container.compose_service ? ` (${container.compose_service})` : ""}`);
    }
    if (container.health) {
      add("Health", container.health);
    }
    const sourceLink = container.source || check.oci_source;
    if (sourceLink) {
      add("Release notes / Source", link(sourceLink));
    }
    add("Changes", check.changelog && link(check.changelog));
    add("Git", check.git_repo && `${check.git_repo}${check.git_ref ? ` at ${check.git_ref}` : ""}`);
    add("Scope", container.scope);
    add("Security", securityFact(container.name));

    if (feature("settings")) {
      const currentPolicy = container.policy || "auto";
      const policySelect = el(
        "select",
        {
          class: "policy-select",
          value: currentPolicy,
          onchange: async (event) => {
            const nextPolicy = event.target.value;
            try {
              await changeSettings({
                container_overrides: {
                  [container.name]: nextPolicy,
                },
              });
              await loadContainers();
              renderManifest();
            } catch (err) {
              notify(`Failed to update policy: ${err.message}`, true);
            }
          },
        },
        el("option", { value: "auto", selected: currentPolicy === "auto" }, "Auto (Global settings)"),
        el("option", { value: "update", selected: currentPolicy === "update" }, "Always update"),
        el("option", { value: "monitor_only", selected: currentPolicy === "monitor_only" }, "Monitor only"),
        el("option", { value: "pinned", selected: currentPolicy === "pinned" }, "Pinned (Lock image)"),
      );
      add("Update policy", policySelect);
    }

    const notes = [];

    if (container.watchtower) {
      notes.push("This is Watchtower itself.");
    }

    if (container.policy === "pinned") {
      notes.push("Pinned: This container is locked to its current image and will not be updated.");
    } else if (container.monitor_only) {
      notes.push("Monitor only: Watchtower reports updates for this container but doesn't apply them.");
    }

    if (container.no_pull) {
      notes.push("Watchtower doesn't pull new images for this container.");
    }

    if (!container.running) {
      notes.push("The container isn't running.");
    }

    return el(
      "div",
      { class: "unit-detail", id: `detail-${container.name}` },
      check.error && el("p", { class: "problem" }, `Watchtower couldn't check this image: ${check.error}`),
      el("dl", { class: "facts" }, rows),
      notes.map((text) => el("p", null, text)),
      changeLog(container),
    );
  }

  function unit(container) {
    const status = describe(container);
    const open = state.expanded.has(container.name);
    const check = state.checks.get(container.name);
    const waiting = status.key === "waiting";
    const health = container.health ? String(container.health).toLowerCase() : "";
    const recent = feature("history") ? lastUpdated(container.name) : null;

    const toggle = el(
      "button",
      {
        class: "unit-toggle",
        type: "button",
        "aria-expanded": String(open),
        "aria-controls": `detail-${container.name}`,
        onclick: () => {
          if (open) {
            state.expanded.delete(container.name);
          } else {
            state.expanded.add(container.name);
          }

          renderManifest();
        },
      },
      el("span", { class: `end end-${status.key}`, "aria-hidden": "true" }),
      el(
        "span",
        null,
        el(
          "span",
          { class: "unit-name" },
          container.name,
          health && el("span", { class: `badge-health health-${health}` }, health),
          securityBadge(container.name),
        ),
        el("span", { class: "unit-image" }, container.image),
        recent && el("span", { class: "unit-last" }, `Updated ${ago(recent.when)}`),
      ),
      el("span", { class: `unit-state state-${status.key}` }, status.label),
    );

    const actions = [];
    const isBusy = state.updating.has(container.name) || state.acting.has(container.name) || Boolean(activityFor(container.name));

    if (!container.watchtower) {
      if (container.running) {
        actions.push(
          el(
            "button",
            {
              class: "button button-quiet button-tiny button-restart",
              type: "button",
              disabled: isBusy,
              "aria-label": `Restart ${container.name}`,
              onclick: (e) => {
                e.stopPropagation();
                containerAction(container.name, "restart");
              },
            },
            "Restart",
          ),
          el(
            "button",
            {
              class: "button button-quiet button-tiny button-stop",
              type: "button",
              disabled: isBusy,
              "aria-label": `Stop ${container.name}`,
              onclick: (e) => {
                e.stopPropagation();
                containerAction(container.name, "stop");
              },
            },
            "Stop",
          ),
        );
      } else {
        actions.push(
          el(
            "button",
            {
              class: "button button-quiet button-tiny button-start",
              type: "button",
              disabled: isBusy,
              "aria-label": `Start ${container.name}`,
              onclick: (e) => {
                e.stopPropagation();
                containerAction(container.name, "start");
              },
            },
            "Start",
          ),
        );
      }
    }

    if (container.policy === "pinned") {
      actions.push(el("span", { class: "setting-off" }, "Pinned"));
    } else if (waiting && canUpdate(container)) {
      actions.push(
        el(
          "button",
          {
            class: "button button-quiet button-tiny",
            type: "button",
            disabled: updateRunning() || isBusy,
            "aria-label": `Update ${container.name}`,
            onclick: (e) => {
              e.stopPropagation();
              confirmUpdate([container]);
            },
          },
          "Update",
        ),
      );
    } else if (waiting && (check || container.monitor_only) && feature("update")) {
      actions.push(el("span", { class: "setting-off" }, "Monitor only"));
    }

    const actionWrapper = el("div", { class: "unit-actions-group" }, ...actions);
    const entry = activityFor(container.name);
    const working = entry && entry.step !== "updated" && entry.step !== "failed";

    return el(
      "li",
      { class: "unit" },
      el("div", { class: "unit-head" }, toggle, actions.length > 0 && el("div", { class: "unit-action" }, actionWrapper)),
      working &&
        el(
          "div",
          { class: "unit-progress", role: "status" },
          activityBar(entry),
          el("p", { class: "unit-progress-text" }, activityDetail(entry)),
          scanDiff(entry),
        ),
      open && facts(container),
    );
  }

  function visibleContainers() {
    const term = state.search.trim().toLowerCase();

    return state.containers.filter((container) => {
      if (state.waitingOnly) {
        const check = state.checks.get(container.name);

        if (!check || !check.update_available) {
          return false;
        }
      }

      return !term || container.name.toLowerCase().includes(term) || container.image.toLowerCase().includes(term);
    });
  }

  function manifest() {
    if (state.containersProblem) {
      return el(
        "p",
        { class: "blank" },
        el("strong", null, "The container list didn't load."),
        state.containersProblem,
      );
    }

    const shown = visibleContainers();

    if (state.containers.length > 0 && shown.length === 0) {
      return el(
        "p",
        { class: "blank" },
        el("strong", null, "Nothing matches."),
        state.waitingOnly ? "No container in this view has an update waiting." : "Try a shorter name or part of the image.",
      );
    }

    if (state.groupByCompose) {
      const groups = new Map();

      for (const item of shown) {
        const project = item.compose_project || "Standalone Containers";

        if (!groups.has(project)) {
          groups.set(project, []);
        }

        groups.get(project).push(item);
      }

      const sortedProjects = [...groups.keys()].sort((a, b) => {
        if (a === "Standalone Containers") {
          return 1;
        }

        if (b === "Standalone Containers") {
          return -1;
        }

        return a.localeCompare(b);
      });

      return el(
        "div",
        { id: "manifest" },
        sortedProjects.map((project) => {
          const projectContainers = groups.get(project);
          const updatableInStack = projectContainers.filter((c) => {
            const status = describe(c);

            return status.key === "waiting" && canUpdate(c);
          });

          return el(
            "div",
            { class: "stack-group" },
            el(
              "div",
              { class: "stack-header" },
              el("span", { class: "stack-title" }, project),
              el(
                "div",
                { class: "stack-meta" },
                el("span", { class: "setting-help" }, count(projectContainers.length, "container")),
                updatableInStack.length > 0 &&
                  el(
                    "button",
                    {
                      class: "button button-quiet button-sm",
                      type: "button",
                      disabled: updateRunning(),
                      onclick: () => confirmUpdate(updatableInStack),
                    },
                    `Update Stack (${updatableInStack.length})`,
                  ),
              ),
            ),
            el("ul", { class: "manifest" }, projectContainers.map(unit)),
          );
        }),
      );
    }

    return el("ul", { class: "manifest", id: "manifest" }, shown.map(unit));
  }

  function renderManifest() {
    const current = document.getElementById("manifest-slot");

    if (current) {
      current.replaceChildren(manifest());
    }
  }

  function containersView() {
    if (!feature("containers")) {
      return el(
        "div",
        null,
        el("h1", { class: "title" }, "The container list is switched off."),
        el(
          "p",
          { class: "lede" },
          "Add ",
          code("containers"),
          " to ",
          code("WATCHTOWER_HTTP_API_ENDPOINTS"),
          " and restart Watchtower to see what it's watching.",
        ),
      );
    }

    const hasCompose = state.containers.some((c) => c.compose_project);
    const toolbar =
      state.containers.length > SEARCH_THRESHOLD || state.search || state.waitingOnly || hasCompose
        ? el(
            "div",
            { class: "toolbar" },
            el("input", {
              class: "search",
              type: "search",
              placeholder: "Find a container or image",
              "aria-label": "Find a container or image",
              value: state.search,
              oninput: (event) => {
                state.search = event.target.value;
                renderManifest();
              },
            }),
            hasCompose &&
              el(
                "label",
                { class: "toggle" },
                el("input", {
                  type: "checkbox",
                  checked: state.groupByCompose,
                  onchange: (event) => {
                    state.groupByCompose = event.target.checked;
                    renderManifest();
                  },
                }),
                "Group by Compose stack",
              ),
            state.checkedAt &&
              el(
                "label",
                { class: "toggle" },
                el("input", {
                  type: "checkbox",
                  checked: state.waitingOnly,
                  onchange: (event) => {
                    state.waitingOnly = event.target.checked;
                    renderManifest();
                  },
                }),
                "Only updates waiting",
              ),
          )
        : null;

    return el(
      "div",
      null,
      el("div", { id: "lookout-slot" }, lookout()),
      toolbar,
      state.containersLoaded && state.containers.length > 0 && el("div", { id: "manifest-slot" }, manifest()),
    );
  }

  // History view

  function scan(entry) {
    const when = new Date(entry.timestamp);
    const scanned = entry.scanned || 0;
    const check = entry.kind === "check";
    const waiting = entry.updates_available || 0;
    const parts = [count(scanned, "container") + (check ? " checked" : " scanned")];

    if (check) {
      if (waiting) {
        parts.push(`${count(waiting, "update")} waiting`);
      } else if (!entry.failed) {
        parts.push("all up to date");
      }
    }

    if (entry.updated) {
      parts.push(`${entry.updated} updated`);
    }

    if (entry.failed) {
      parts.push(`${entry.failed} failed`);
    }

    if (entry.restarted) {
      parts.push(`${entry.restarted} restarted`);
    }

    if (entry.skipped) {
      parts.push(`${entry.skipped} skipped`);
    }

    const bar = el("div", { class: "scan-bar", "aria-hidden": "true" });
    const segment = (kind, value) => {
      if (value > 0 && scanned > 0) {
        const part = el("span", { class: `scan-part-${kind}` });

        part.style.setProperty("flex", `${value} 0 0`);
        bar.append(part);
      }
    };

    const changed = check ? waiting : entry.updated || 0;

    segment("updated", changed);
    segment("failed", entry.failed || 0);
    segment("fresh", Math.max(scanned - changed - (entry.failed || 0), 0));

    const named = entry.containers || [];

    return el(
      "li",
      { class: "scan" },
      el("div", { class: "scan-when" }, capitalise(ago(when)), el("span", { class: "scan-exact" }, exact.format(when))),
      el(
        "div",
        null,
        parts.join(", "),
        bar,
        named.length > 0 && el("ul", { class: "change-list scan-changes" }, named.map((item) => el("li", { class: "change-what" }, changeLine(item, true)))),
      ),
    );
  }

  function historyView() {
    const header = [el("h1", { class: "title" }, "Scan history")];

    if (!feature("history")) {
      return el(
        "div",
        null,
        header,
        el(
          "p",
          { class: "lede" },
          "History is switched off. Add ",
          code("history"),
          " to ",
          code("WATCHTOWER_HTTP_API_ENDPOINTS"),
          " and restart Watchtower.",
        ),
      );
    }

    header.push(
      el(
        "p",
        { class: "lede" },
        "Every time Watchtower looks for new images, whether on its schedule or when you check or update from this page, with the containers each scan changed. Watchtower keeps the latest 500 and saves them in its data directory when one is mounted.",
      ),
    );

    if (state.historyProblem) {
      return el(
        "div",
        null,
        header,
        el("p", { class: "blank" }, el("strong", null, "History didn't load."), state.historyProblem),
      );
    }

    if (!state.history) {
      return el("div", null, header, el("p", { class: "blank" }, "Loading scans."));
    }

    if (state.history.length === 0) {
      return el(
        "div",
        null,
        header,
        el(
          "p",
          { class: "blank" },
          el("strong", null, "No scans yet."),
          "The first one appears here after you check for updates, update a container, or Watchtower's next scheduled run.",
        ),
      );
    }

    // Scans that changed something, including checks that found an update waiting.
    const eventful = (entry) => entry.updated || entry.failed || entry.restarted || entry.updates_available;
    const shown = state.historyChangesOnly ? state.history.filter(eventful) : state.history;

    return el(
      "div",
      null,
      header,
      el(
        "div",
        { class: "toolbar" },
        el(
          "label",
          { class: "toggle" },
          el("input", {
            type: "checkbox",
            checked: state.historyChangesOnly,
            onchange: (event) => {
              state.historyChangesOnly = event.target.checked;
              render();
            },
          }),
          "Only scans that found or changed something",
        ),
      ),
      shown.length > 0
        ? el("ul", { class: "manifest" }, shown.map(scan))
        : el("p", { class: "blank" }, el("strong", null, "Nothing changed."), "None of the scans Watchtower remembers updated or found anything."),
    );
  }

  // Security view

  // A scan is polled this often while it runs. Scans take minutes, so a slow
  // poll keeps the page well inside the API's rate limit.
  // A running scan is polled often enough that each step shows up while it
  // happens, and well inside the API's per-minute request limit.
  const SECURITY_POLL_MS = 3_000;
  const SECURITY_FIRST_POLL_MS = 1_000;
  const FINDING_LIMIT = 25;
  const SEVERITIES = ["critical", "high", "medium", "low", "unknown"];
  const GATES = [
    { value: "off", label: "Never hold updates" },
    { value: "critical", label: "Critical findings" },
    { value: "high", label: "High or critical findings" },
    { value: "medium", label: "Medium or worse" },
    { value: "low", label: "Any rated finding" },
  ];

  const SCANNERS = [
    {
      value: "trivy",
      label: "Trivy",
      help: "Trivy looks for known vulnerabilities, leaked secrets, and risky image settings.",
    },
    {
      value: "grype",
      label: "Grype",
      help: "Grype looks for known vulnerabilities only, using Anchore's vulnerability database.",
    },
  ];

  function scannerLabel(name) {
    const known = SCANNERS.find((item) => item.value === name);

    return known ? known.label : capitalise(name || "the scanner");
  }

  let securityTimer = null;
  let scanClockTimer = null;

  async function loadSecurity() {
    if (!feature("security")) {
      return;
    }

    try {
      state.security = await request("GET", "/v1/security");
      state.securityProblem = "";
    } catch (problem) {
      state.securityProblem = problem.message;
    }
  }

  async function loadSecurityDetail(name) {
    try {
      const data = await request("GET", `/v1/security/${encodeURIComponent(name)}`);

      state.securityDetails.set(name, data.container);
    } catch (problem) {
      state.securityDetails.set(name, { problem: problem.message });
    }
  }

  function securityRunning() {
    return Boolean(state.security && state.security.job && state.security.job.running);
  }

  function scheduleSecurityPoll(delay = SECURITY_POLL_MS) {
    if (!securityTimer && securityRunning()) {
      securityTimer = setTimeout(pollSecurity, delay);
    }

    scheduleScanClock();
  }

  // Ticks the elapsed times on the scan status panel once a second, without
  // asking Watchtower for anything.
  function scheduleScanClock() {
    const wanted = securityRunning() || state.securityStarting;

    if (wanted && !scanClockTimer) {
      scanClockTimer = setInterval(tickScanClock, 1_000);
    } else if (!wanted && scanClockTimer) {
      clearInterval(scanClockTimer);
      scanClockTimer = null;
    }
  }

  function tickScanClock() {
    document.querySelectorAll("[data-since]").forEach((node) => {
      node.textContent = elapsed(new Date(node.dataset.since));
    });
    document.querySelectorAll("[data-until]").forEach((node) => {
      node.textContent = remaining(new Date(node.dataset.until));
    });
  }

  function elapsed(since) {
    const seconds = Math.max(0, Math.floor((Date.now() - since.getTime()) / 1000));
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const pad = (n) => String(n).padStart(2, "0");

    return hours > 0 ? `${hours}:${pad(minutes % 60)}:${pad(seconds % 60)}` : `${minutes}:${pad(seconds % 60)}`;
  }

  async function pollSecurity() {
    securityTimer = null;

    if (!state.session || !state.session.authenticated) {
      return;
    }

    const wasRunning = securityRunning();

    await loadSecurity();

    if (wasRunning && !securityRunning()) {
      const job = state.security.job;
      const scanned = job.total - job.failed;

      if (job.failed > 0) {
        state.scanLogOpen = true;
        notify(
          scanned > 0
            ? `Scanned ${count(scanned, "container")}. ${capitalise(count(job.failed, "container"))} couldn't be scanned; the scan's steps on the Security page say why.`
            : "The scan didn't finish. The scan's steps on the Security page say why.",
          true,
        );
      } else {
        notify(`Scanned ${count(job.total, "container")}.`);
      }

      // Open reports are now out of date.
      state.securityDetails.clear();
      await Promise.all([...state.securityExpanded].map(loadSecurityDetail));
    }

    renderSecurity();
    renderManifest();
    scheduleSecurityPoll();
  }

  async function startSecurityScan(names) {
    // Watchtower lists the containers before it answers, which can take a
    // while with many containers, so say so straight away.
    state.securityStarting = { at: new Date().toISOString(), names: names || null };
    renderSecurity();
    renderManifest();
    scheduleScanClock();

    try {
      const data = await request("POST", "/v1/security/scan", names ? { containers: names } : undefined);

      state.security = { ...(state.security || {}), job: data.job };
    } catch (problem) {
      notify(`Couldn't start the scan. ${capitalise(problem.message)}.`, true);
    }

    state.securityStarting = false;
    renderSecurity();
    renderManifest();
    scheduleSecurityPoll(SECURITY_FIRST_POLL_MS);
  }

  // What the scan is doing, step by step: shown from the moment the button
  // is pressed until the scan ends, then kept as a record of the last scan.
  function scanStatus() {
    const security = state.security;
    const job = security && security.job;
    const starting = state.securityStarting;

    if (!security || !security.available || (!starting && !(job && job.started_at))) {
      return null;
    }

    if (starting) {
      return el(
        "section",
        { class: "scan-status", "aria-live": "polite", "aria-label": "Scan progress" },
        el(
          "div",
          { class: "scan-status-head" },
          el("span", { class: "end end-tiny end-working", "aria-hidden": "true" }),
          el("p", { class: "scan-status-step" }, "Asking Watchtower to start the scan"),
          el("span", { class: "scan-status-clock", "data-since": starting.at }, elapsed(new Date(starting.at))),
        ),
        el("progress", { class: "progress", "aria-label": "Scan progress" }),
        el(
          "p",
          { class: "scan-status-count" },
          starting.names ? `Looking up ${starting.names.join(", ")}.` : "Watchtower lists your containers and their images first.",
        ),
      );
    }

    const activity = (job.activity || []).slice().reverse();
    const log =
      activity.length > 0 &&
      el(
        "ol",
        { class: "scan-log" },
        activity.map((entry) =>
          el(
            "li",
            { class: entry.problem ? "scan-log-entry scan-log-problem" : "scan-log-entry" },
            el("time", { datetime: entry.at, title: exact.format(new Date(entry.at)) }, clock.format(new Date(entry.at))),
            el("span", null, entry.message),
          ),
        ),
      );

    if (!job.running) {
      if (!log) {
        return null;
      }

      const finished = job.finished_at ? new Date(job.finished_at) : null;
      const took = finished && job.started_at ? elapsedBetween(new Date(job.started_at), finished) : "";

      return el(
        "details",
        {
          class: "scan-status scan-status-done",
          open: state.scanLogOpen,
          ontoggle: (event) => {
            state.scanLogOpen = event.currentTarget.open;
          },
        },
        el(
          "summary",
          null,
          `What the last scan did${finished ? `, ${ago(finished)}` : ""}${took ? ` (took ${took})` : ""}`,
        ),
        log,
      );
    }

    const step = job.step || "Starting the scan";
    const since = job.step_started_at || job.started_at;
    const current = (job.current || []).join(", ");
    const waiting = job.waiting || [];
    const images = job.images || 0;
    const finish = job.estimated_finish_at ? new Date(job.estimated_finish_at) : null;

    return el(
      "section",
      { class: "scan-status", "aria-live": "polite", "aria-label": "Scan progress" },
      el(
        "div",
        { class: "scan-status-head" },
        el("span", { class: "end end-tiny end-working", "aria-hidden": "true" }),
        el("p", { class: "scan-status-step" }, step),
        el("span", { class: "scan-status-clock", "data-since": since, title: "Time on this step" }, elapsed(new Date(since))),
      ),
      el("progress", {
        class: "progress",
        "aria-label": "Images scanned",
        max: String(images || job.total),
        value: String(images ? job.images_done : job.done),
      }),
      el(
        "dl",
        { class: "scan-status-facts" },
        el("dt", null, "Now scanning"),
        el(
          "dd",
          null,
          current || "Nothing yet",
          images > 0 && current ? ` (image ${Math.min(job.images_done + 1, images)} of ${images})` : "",
          job.current_started_at && [" for ", el("span", { "data-since": job.current_started_at }, elapsed(new Date(job.current_started_at)))],
        ),
        el("dt", null, "Done"),
        el(
          "dd",
          null,
          `${job.done} of ${count(job.total, "container")}`,
          job.failed > 0 ? `, ${job.failed} couldn't be scanned` : "",
          ". Running for ",
          el("span", { "data-since": job.started_at }, elapsed(new Date(job.started_at))),
        ),
        el("dt", null, "Time left"),
        el(
          "dd",
          null,
          finish
            ? [
                "About ",
                el("span", { "data-until": job.estimated_finish_at }, remaining(finish)),
                `, finishing around ${clockShort.format(finish)}`,
              ]
            : "Worked out once the first image is done",
        ),
        waiting.length > 0 && el("dt", null, "Up next"),
        waiting.length > 0 && el("dd", null, waitingList(waiting)),
      ),
      log,
    );
  }

  function remaining(finish) {
    const seconds = Math.round((finish - Date.now()) / 1000);

    if (seconds < 60) {
      return "under a minute";
    }

    const minutes = Math.round(seconds / 60);

    return minutes < 60 ? count(minutes, "minute") : `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
  }

  function waitingList(names) {
    const shown = names.slice(0, 5).join(", ");

    return names.length > 5 ? `${shown}, and ${names.length - 5} more` : shown;
  }

  function elapsedBetween(start, end) {
    const seconds = Math.max(0, Math.round((end - start) / 1000));

    if (seconds < 60) {
      return count(seconds, "second");
    }

    const minutes = Math.round(seconds / 60);

    return minutes < 60 ? count(minutes, "minute") : `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
  }

  function securityReport(name) {
    if (!state.security) {
      return null;
    }

    return (state.security.containers || []).find((report) => report.name === name) || null;
  }

  function total(counts) {
    return SEVERITIES.reduce((sum, level) => sum + ((counts && counts[level]) || 0), 0);
  }

  function serious(counts) {
    return Boolean(counts) && counts.critical + counts.high > 0;
  }

  // "3 critical, 5 high", naming at most `limit` levels, worst first.
  function severityList(counts, limit = SEVERITIES.length) {
    return SEVERITIES.filter((level) => counts && counts[level] > 0)
      .slice(0, limit)
      .map((level) => `${counts[level]} ${level}`)
      .join(", ");
  }

  // A container's scan state, in the words the page uses for it.
  function securityStatus(report) {
    if (!report) {
      return { key: "unknown", label: "Not scanned yet" };
    }

    if (report.error && total(report.counts) === 0) {
      return { key: "unknown", label: "Couldn't scan" };
    }

    if (serious(report.counts)) {
      return { key: "failed", label: severityList(report.counts, 2) };
    }

    if (total(report.counts) > 0) {
      return { key: "waiting", label: severityList(report.counts, 2) };
    }

    return { key: "fresh", label: "No known issues" };
  }

  // The containers to list: every watched container, scanned or not. Reports
  // of removed containers are left out once the container list has loaded.
  function securityRows() {
    const reports = (state.security && state.security.containers) || [];

    if (!state.containersLoaded || state.containers.length === 0) {
      return reports.map((report) => ({ name: report.name, report, container: null }));
    }

    return state.containers.map((container) => ({
      name: container.name,
      report: reports.find((report) => report.name === container.name) || null,
      container,
    }));
  }

  // Worst first, then by name, with unscanned containers last.
  function rank(row) {
    const counts = row.report && row.report.counts;

    if (!counts) {
      return [-1, 0, 0];
    }

    return [counts.critical, counts.high, total(counts)];
  }

  function sortedSecurityRows() {
    return securityRows().sort((a, b) => {
      const left = rank(a);
      const right = rank(b);

      for (let i = 0; i < left.length; i++) {
        if (left[i] !== right[i]) {
          return right[i] - left[i];
        }
      }

      return a.name.localeCompare(b.name);
    });
  }

  function securityLookout(rows) {
    const security = state.security;
    const job = security && security.job;
    const scanned = rows.filter((row) => row.report && !(row.report.error && total(row.report.counts) === 0));
    const unscanned = rows.length - scanned.length;
    let line;
    let note;

    if (state.securityProblem && !security) {
      line = "The scan results didn't load.";
      note = state.securityProblem;
    } else if (!security) {
      line = "Reading the scan results.";
      note = "Loading what Watchtower knows about each image.";
    } else if (!security.available) {
      line = "The image scanner isn't available.";
      note = security.reason || "";
    } else if (state.securityStarting) {
      line = "Starting the scan.";
      note = "";
    } else if (securityRunning()) {
      const current = (job.current || []).join(", ");

      line = current ? `Scanning ${current}.` : "Starting the scan.";
      note =
        scanned.length === 0
          ? `The first scan downloads ${scannerLabel(security.scanner)}'s vulnerability database, which can take a few minutes.`
          : "";
    } else if (scanned.length === 0) {
      line = "No image has been scanned yet.";
      note =
        security.scanner === "grype"
          ? "A scan looks for known vulnerabilities in each running image. It only reads images and changes nothing."
          : "A scan looks for known vulnerabilities, leaked secrets, and risky settings in each running image. It only reads images and changes nothing.";
    } else {
      const flagged = scanned.filter((row) => serious(row.report.counts)).length;
      const newest = scanned.map((row) => new Date(row.report.scanned_at)).sort((a, b) => b - a)[0];
      const fixing = scanned.filter((row) => row.report.update && !row.report.update.held && total(row.report.update.fixed_counts) > 0);
      const fixes = fixing.reduce((sum, row) => sum + total(row.report.update.fixed_counts), 0);

      line =
        flagged === 0
          ? `No critical or high vulnerabilities in ${scanned.length === 1 ? "the scanned image" : `the ${scanned.length} scanned images`}.`
          : `${flagged} of ${count(scanned.length, "scanned container")} ${flagged === 1 ? "has" : "have"} critical or high vulnerabilities.`;
      note = `Last scanned ${ago(newest)} with ${scannerLabel(security.scanner)}.`;

      if (fixes > 0) {
        note += ` ${capitalise(count(fixing.length, "waiting update"))} would fix ${count(fixes, "known issue")}.`;
      }

      if (unscanned > 0) {
        note += ` ${capitalise(count(unscanned, "container"))} not scanned yet.`;
      }
    }

    return el(
      "header",
      { class: "lookout" },
      el("h1", { class: "lookout-line" }, line),
      note && el("p", { class: "lookout-note" }, note),
      security &&
        security.available &&
        el(
          "div",
          { class: "actions" },
          el(
            "button",
            {
              class: "button button-primary",
              type: "button",
              disabled: securityRunning() || state.securityStarting || rows.length === 0,
              onclick: () => startSecurityScan(),
            },
            state.securityStarting ? "Starting" : securityRunning() ? "Scanning" : scanned.length > 0 ? "Scan all again" : "Scan all containers",
          ),
        ),
    );
  }

  // Whether updates are scanned before they're applied, and how to change it.
  function securityPolicy() {
    const security = state.security;

    if (!security || !security.available) {
      return null;
    }

    const where = feature("settings") ? [" ", el("a", { href: "#/settings" }, "Change this in Settings"), "."] : "";

    if (!security.scan_updates) {
      return el(
        "p",
        { class: "section-note" },
        "Updates are applied without being scanned first. Turn on Scan updates first to see what each update fixes and to hold back ones that add serious vulnerabilities.",
        where,
      );
    }

    const gate = GATES.find((item) => item.value === security.gate);

    return el(
      "p",
      { class: "section-note" },
      "Each update's new image is scanned before it's applied. ",
      security.gate === "off" || !gate
        ? "None are held back."
        : `Updates whose new image adds ${gate.label.toLowerCase()} are held back.`,
      where,
    );
  }

  function findingKey(finding) {
    return finding.kind === "vulnerability" ? `${finding.kind}|${finding.id}|${finding.package}` : `${finding.kind}|${finding.id}|${finding.target}`;
  }

  // What the user can do about a container's findings, most useful first.
  function fixAdvice(report, detail, container) {
    const items = [];
    const update = report.update;
    const findings = (detail && detail.findings) || [];
    const fixedByUpdate = new Set(((detail && detail.update && detail.update.fixed) || []).map(findingKey));
    const fixedTotal = update ? total(update.fixed_counts) : 0;
    const introducedTotal = update ? total(update.introduced_counts) : 0;

    if (total(report.counts) === 0 && !report.error) {
      items.push(
        `${scannerLabel(report.scanner)} found nothing it knows about in this image. Scan again now and then: new advisories are published every day.`,
      );

      return items;
    }

    if (update && update.held) {
      items.push([
        el("strong", null, "The waiting update is held back. "),
        `Its new image adds ${severityList(update.introduced_counts)} that this one doesn't have, which is at or above the ${update.gate} gate. The container keeps its current image until a cleaner one is published.`,
        feature("settings") && [" To apply it anyway, lower the gate in ", el("a", { href: "#/settings" }, "Settings"), "."],
      ]);
    } else if (update && fixedTotal > 0) {
      const button =
        container &&
        canUpdate(container) &&
        el(
          "button",
          {
            class: "button button-primary button-tiny",
            type: "button",
            disabled: updateRunning(),
            onclick: () => confirmUpdate([container]),
          },
          "Update to fix",
        );

      items.push([
        el("strong", null, `The waiting update fixes ${fixedTotal} of these`),
        ` (${severityList(update.fixed_counts)})`,
        introducedTotal > 0 ? `, and brings in ${count(introducedTotal, "new one")} (${severityList(update.introduced_counts)}).` : ".",
        button && [" ", button],
      ]);
    } else if (update) {
      items.push("An update is waiting, but its new image has the same findings.");
    }

    const lastUpdate = report.last_update;
    if (lastUpdate && total(lastUpdate.fixed_counts) > 0) {
      const fixedCount = total(lastUpdate.fixed_counts);
      items.push([
        el("strong", null, `The most recent update fixed ${count(fixedCount, "vulnerability")}`),
        ` (${severityList(lastUpdate.fixed_counts)})`,
        lastUpdate.applied_at ? ` applied ${ago(new Date(lastUpdate.applied_at))}.` : ".",
      ]);
    }

    if (detail && !detail.problem) {
      const vulnerabilities = findings.filter((finding) => finding.kind === "vulnerability");
      const waitingForImage = vulnerabilities.filter((finding) => finding.fixed_version && !fixedByUpdate.has(findingKey(finding))).length;
      const unfixed = vulnerabilities.filter((finding) => !finding.fixed_version).length;
      const secrets = findings.filter((finding) => finding.kind === "secret").length;
      const settings = findings.filter((finding) => finding.kind === "misconfiguration").length;

      if (waitingForImage > 0) {
        items.push([
          el("strong", null, `${waitingForImage} ${waitingForImage === 1 ? "has" : "have"} a fixed package version this image doesn't include yet. `),
          "The fix arrives when the image's maintainer publishes a rebuilt image, and Watchtower updates the container then. If you build this image yourself, rebuild it on an updated base image.",
        ]);
      }

      if (unfixed > 0) {
        items.push([
          el("strong", null, `${unfixed} ${unfixed === 1 ? "has" : "have"} no fix published yet. `),
          "These wait on the package's own project to release a patch. The advisory link says whether there's a workaround.",
        ]);
      }

      if (secrets > 0) {
        items.push([
          el("strong", null, `${count(secrets, "secret")} found in the image. `),
          "Anyone who can pull the image can read them. Rotate them, and pass them to the container at run time instead.",
        ]);
      }

      if (settings > 0) {
        items.push([
          el("strong", null, `${count(settings, "image setting")} ${settings === 1 ? "is" : "are"} risky, `),
          "such as running as root. Each one below says how to change it.",
        ]);
      }
    }

    return items;
  }

  function findingRow(finding, fixedByUpdate, wasFixed) {
    const id = /^https?:\/\//.test(finding.url || "")
      ? el("a", { class: "finding-id", href: finding.url, rel: "noreferrer", target: "_blank" }, finding.id)
      : el("span", { class: "finding-id" }, finding.id);
    let where;

    if (finding.kind === "vulnerability") {
      where = [
        code(finding.package || "unknown package"),
        " ",
        finding.installed_version || "",
        finding.fixed_version ? [" → fixed in ", el("strong", null, finding.fixed_version)] : ", no fix yet",
      ];
    } else if (finding.resolution) {
      where = finding.resolution;
    } else {
      where = finding.target && code(finding.target);
    }

    return el(
      "li",
      { class: "finding" },
      el("span", { class: `sev sev-${finding.severity}` }, finding.severity),
      el(
        "span",
        { class: "finding-body" },
        el(
          "span",
          { class: "finding-head" },
          id,
          finding.kind !== "vulnerability" && el("span", { class: "finding-kind" }, finding.kind === "secret" ? "Secret" : "Image setting"),
          fixedByUpdate && el("span", { class: "finding-kind finding-fixed" }, "Fixed by the update"),
          wasFixed && el("span", { class: "finding-kind finding-fixed" }, "Fixed by last update"),
        ),
        finding.title && el("span", { class: "finding-title" }, finding.title),
        where && el("span", { class: "finding-where" }, where),
      ),
    );
  }

  function findingList(name, detail) {
    const all = detail.findings || [];
    const fixedByUpdate = new Set(((detail.update && detail.update.fixed) || []).map(findingKey));
    const shown = state.securityFixableOnly ? all.filter((finding) => finding.fixed_version || fixedByUpdate.has(findingKey(finding))) : all;
    const showAll = state.securityShowAll.has(name);
    const visible = showAll ? shown : shown.slice(0, FINDING_LIMIT);

    if (all.length === 0) {
      return null;
    }

    return el(
      "div",
      { class: "changes" },
      el(
        "div",
        { class: "findings-head" },
        el("h3", { class: "detail-title" }, "Findings"),
        el(
          "label",
          { class: "toggle" },
          el("input", {
            type: "checkbox",
            checked: state.securityFixableOnly,
            onchange: (event) => {
              state.securityFixableOnly = event.target.checked;
              renderSecurity();
            },
          }),
          "Only ones with a fix",
        ),
      ),
      shown.length === 0
        ? el("p", { class: "setting-help" }, "None of these has a fix published yet.")
        : el("ul", { class: "finding-list" }, visible.map((finding) => findingRow(finding, fixedByUpdate.has(findingKey(finding))))),
      shown.length > visible.length &&
        el(
          "button",
          {
            class: "button button-quiet button-tiny",
            type: "button",
            onclick: () => {
              state.securityShowAll.add(name);
              renderSecurity();
            },
          },
          `Show all ${shown.length}`,
        ),
      detail.truncated && el("p", { class: "setting-help" }, `Only the ${all.length} most severe findings are kept.`),
      state.security && state.security.ignore_unfixed && el("p", { class: "setting-help" }, "Findings with no published fix are left out of this scan."),
    );
  }

  function securityDetail(row) {
    const { name, report, container } = row;

    if (!report) {
      return el(
        "div",
        { class: "unit-detail", id: `security-${name}` },
        el("p", null, "This container's image hasn't been scanned yet."),
        scanOneButton(name),
      );
    }

    let detail = state.securityDetails.get(name);

    // The summary moved on, so the open report is out of date.
    if (detail && !detail.problem && new Date(detail.scanned_at) < new Date(report.scanned_at)) {
      detail = null;
    }

    if (!detail) {
      state.securityDetails.set(name, { loading: true, scanned_at: report.scanned_at });
      loadSecurityDetail(name).then(renderSecurity);
    }

    const ready = detail && !detail.loading && !detail.problem ? detail : null;
    const advice = fixAdvice(report, ready, container);
    const counts = report.counts || {};

    return el(
      "div",
      { class: "unit-detail", id: `security-${name}` },
      report.error && el("p", { class: "problem" }, `Watchtower couldn't scan this image: ${report.error}`),
      total(counts) > 0 &&
        el(
          "ul",
          { class: "severity-counts", "aria-label": "Findings by severity" },
          SEVERITIES.filter((level) => counts[level] > 0).map((level) =>
            el("li", { class: `sev sev-${level}` }, el("strong", null, String(counts[level])), ` ${level}`),
          ),
          report.fixable > 0 && el("li", { class: "severity-fixable" }, `${report.fixable} with a fix`),
        ),
      advice.length > 0 &&
        el(
          "div",
          { class: "changes" },
          el("h3", { class: "detail-title" }, "How to fix"),
          el("ul", { class: "advice" }, advice.map((item) => el("li", null, item))),
        ),
      detail && detail.problem && el("p", { class: "problem" }, `The findings didn't load. ${detail.problem}`),
      !ready && !(detail && detail.problem) && total(counts) > 0 && el("p", { class: "setting-help" }, "Loading findings."),
      ready && findingList(name, ready),
      ready && ready.last_update && ready.last_update.fixed && ready.last_update.fixed.length > 0 && el(
        "div",
        { class: "changes" },
        el("h3", { class: "detail-title" }, `Fixed by most recent update (${ready.last_update.fixed.length})`),
        el("ul", { class: "finding-list" }, ready.last_update.fixed.map((finding) => findingRow(finding, false, true))),
      ),
      ready && ready.last_update && ready.last_update.introduced && ready.last_update.introduced.length > 0 && el(
        "div",
        { class: "changes" },
        el("h3", { class: "detail-title" }, `Brought in by most recent update (${ready.last_update.introduced.length})`),
        el("ul", { class: "finding-list" }, ready.last_update.introduced.map((finding) => findingRow(finding, false))),
      ),
      el(
        "p",
        { class: "setting-help" },
        `Scanned ${ago(new Date(report.scanned_at))}`,
        report.scanner && ` with ${capitalise(report.scanner)}${report.scanner_version ? ` ${report.scanner_version}` : ""}`,
        report.image_id && [" (image ", code(shortDigest(report.image_id)), ")"],
        ". ",
        scanOneButton(name),
      ),
    );
  }

  function scanOneButton(name) {
    if (!state.security || !state.security.available) {
      return null;
    }

    return el(
      "button",
      { class: "link-button", type: "button", disabled: securityRunning() || state.securityStarting, onclick: () => startSecurityScan([name]) },
      securityReport(name) ? "Scan again" : "Scan now",
    );
  }

  function securityUnit(row) {
    const { name, report, container } = row;
    const status = securityStatus(report);
    const open = state.securityExpanded.has(name);
    const scanning = securityRunning() && (state.security.job.current || []).includes(name);
    const shown = scanning ? { key: "working", label: "Scanning" } : status;
    const update = report && report.update;
    let note = null;

    if (update && update.held) {
      note = "Update held back";
    } else if (update && total(update.fixed_counts) > 0) {
      note = `Waiting update fixes ${total(update.fixed_counts)}`;
    } else if (report && report.last_update && total(report.last_update.fixed_counts) > 0) {
      note = `Last update fixed ${total(report.last_update.fixed_counts)}`;
    }

    return el(
      "li",
      { class: "unit" },
      el(
        "div",
        { class: "unit-head unit-head-solo" },
        el(
          "button",
          {
            class: "unit-toggle",
            type: "button",
            "aria-expanded": String(open),
            "aria-controls": `security-${name}`,
            onclick: () => {
              if (open) {
                state.securityExpanded.delete(name);
              } else {
                state.securityExpanded.add(name);
              }

              renderSecurity();
            },
          },
          el("span", { class: `end end-${shown.key}`, "aria-hidden": "true" }),
          el(
            "span",
            null,
            el("span", { class: "unit-name" }, name),
            el("span", { class: "unit-image" }, (report && report.image) || (container && container.image) || ""),
            note && el("span", { class: "unit-last" }, note),
          ),
          el("span", { class: `unit-state state-${shown.key}` }, shown.label),
        ),
      ),
      open && securityDetail(row),
    );
  }

  function securityContent() {
    const rows = sortedSecurityRows();
    const available = state.security && state.security.available;

    return [
      securityLookout(rows),
      scanStatus(),
      securityPolicy(),
      available && rows.length > 0 && el("ul", { class: "manifest" }, rows.map(securityUnit)),
      available &&
        state.security.saved === false &&
        rows.some((row) => row.report) &&
        el("p", { class: "section-note" }, "Scan results last until Watchtower restarts. Mount a folder at ", code("/data"), " to keep them."),
    ];
  }

  function renderSecurity() {
    const slot = document.getElementById("security-slot");

    if (slot) {
      slot.replaceChildren(...securityContent().filter(Boolean));
    }
  }

  function securityView() {
    if (!feature("security")) {
      return el(
        "div",
        null,
        el("h1", { class: "title" }, "Image scanning is switched off."),
        el(
          "p",
          { class: "lede" },
          "Watchtower can scan each container's image for known vulnerabilities with Trivy or Grype, show what's affected and how to fix it, and hold back updates that make things worse. Add ",
          code("security"),
          " to ",
          code("WATCHTOWER_HTTP_API_ENDPOINTS"),
          " and restart Watchtower to use it here.",
        ),
        el(
          "p",
          { class: "section-note" },
          "The scanner runs in a short-lived container next to Watchtower, so nothing extra is installed. Its vulnerability database is kept in a Docker volume between scans, and its image is checked for a newer release once a day.",
        ),
      );
    }

    return el("div", { id: "security-slot" }, securityContent().filter(Boolean));
  }

  // A small mark on the Containers view for images with serious findings.
  function securityBadge(name) {
    const report = feature("security") ? securityReport(name) : null;

    if (!report || !serious(report.counts)) {
      return null;
    }

    const level = report.counts.critical > 0 ? "critical" : "high";

    return el("span", { class: `sev badge-security sev-${level}` }, `${report.counts[level]} ${level}`);
  }

  // The security row in a container's details on the Containers view.
  function securityFact(name) {
    if (!feature("security")) {
      return null;
    }

    const report = securityReport(name);
    const open = () => state.securityExpanded.add(name);

    if (!report) {
      return el("span", null, "Not scanned yet. ", el("a", { class: "link-subtle", href: "#/security", onclick: open }, "Security"));
    }

    const status = securityStatus(report);
    let label = capitalise(status.label);
    if (report.last_update && total(report.last_update.fixed_counts) > 0) {
      label += ` (last update fixed ${total(report.last_update.fixed_counts)})`;
    }

    return el("span", null, `${label}. `, el("a", { class: "link-subtle", href: "#/security", onclick: open }, "How to fix"));
  }

  // Settings view

  const SCHEDULES = [
    { label: "Every hour", seconds: 3_600 },
    { label: "Every 6 hours", seconds: 21_600 },
    { label: "Every 12 hours", seconds: 43_200 },
    { label: "Every day", seconds: 86_400 },
    { label: "Every week", seconds: 604_800 },
  ];

  // Reads the length of an "@every" schedule in seconds, or null for a cron expression.
  function everySeconds(spec) {
    const match = /^@every\s+(.+)$/.exec(spec || "");

    if (!match) {
      return null;
    }

    const units = { h: 3_600, m: 60, s: 1 };
    let total = 0;
    let rest = match[1].trim();

    while (rest) {
      const part = /^(\d+)([hms])/.exec(rest);

      if (!part) {
        return null;
      }

      total += Number(part[1]) * units[part[2]];
      rest = rest.slice(part[0].length);
    }

    return total;
  }

  function scheduleChoice(spec) {
    if (!spec) {
      return "off";
    }

    const seconds = everySeconds(spec);
    const preset = SCHEDULES.find((item) => item.seconds === seconds);

    return preset ? String(preset.seconds) : "custom";
  }

  async function changeSettings(changes, focusId) {
    try {
      state.settings = await request("PATCH", "/v1/settings", changes);
      state.customSchedule = false;
      state.customScheduleDraft = null;
      await loadConfig();

      if ("include_stopped" in changes) {
        await loadContainers();
      }

      if ("scan" in changes || "scan_gate" in changes || "scanner" in changes) {
        await loadSecurity();
      }

      notify(state.settings.saved ? "Settings saved." : "Settings changed until Watchtower restarts.");
    } catch (problem) {
      notify(`That change wasn't made. ${capitalise(problem.message)}.`, true);
    }

    render();

    const focused = focusId && document.getElementById(focusId);

    if (focused) {
      focused.focus();
    }
  }

  function setting(name, on, help) {
    return el(
      "li",
      { class: "setting" },
      el("span", { class: "setting-name" }, name),
      el("span", { class: on ? "setting-value" : "setting-value setting-off" }, on ? "On" : "Off"),
      el("span", { class: "setting-help" }, help),
    );
  }

  // A setting that can be switched from this page. `inverted` is for settings
  // whose stored value is the opposite of how the page words them.
  function switchSetting(key, name, help, inverted) {
    const entry = state.settings.settings[key];
    const on = inverted ? !entry.value : entry.value;
    const id = `setting-${key}`;

    return el(
      "li",
      { class: "setting" },
      el("label", { class: "setting-name", for: id }, name),
      el(
        "span",
        { class: "setting-value" },
        el("input", {
          class: "switch",
          id,
          type: "checkbox",
          role: "switch",
          checked: on,
          onchange: (event) => changeSettings({ [key]: inverted ? !event.target.checked : event.target.checked }, id),
        }),
      ),
      el(
        "span",
        { class: "setting-help" },
        help,
        entry.changed && [
          " Changed on this page. ",
          el(
            "button",
            { class: "link-button", type: "button", onclick: () => changeSettings({ [key]: null }, id) },
            "Go back to the startup value",
          ),
        ],
      ),
    );
  }

  function scheduleSetting() {
    const entry = state.settings.settings.schedule;
    const choice = state.customSchedule ? "custom" : scheduleChoice(entry.value);
    const selectId = "setting-schedule";
    const customId = "setting-schedule-custom";

    const select = el(
      "select",
      {
        class: "select",
        id: selectId,
        onchange: (event) => {
          const picked = event.target.value;

          if (picked === "custom") {
            state.customSchedule = true;
            render();
            document.getElementById(customId).focus();
          } else {
            changeSettings({ schedule: picked === "off" ? "" : `@every ${Number(picked) / 3_600}h` }, selectId);
          }
        },
      },
      SCHEDULES.map((item) =>
        el("option", { value: String(item.seconds), selected: choice === String(item.seconds) }, item.label),
      ),
      el("option", { value: "custom", selected: choice === "custom" }, "A custom schedule"),
      el("option", { value: "off", selected: choice === "off" }, "Never"),
    );

    const custom =
      choice === "custom" &&
      el(
        "form",
        {
          class: "inline-form",
          onsubmit: (event) => {
            event.preventDefault();
            // Kept so a rejected schedule stays in the field to be corrected.
            state.customScheduleDraft = document.getElementById(customId).value;
            changeSettings({ schedule: state.customScheduleDraft }, customId);
          },
        },
        el("input", {
          class: "search",
          id: customId,
          type: "text",
          spellcheck: "false",
          autocomplete: "off",
          "aria-label": "Custom schedule",
          value: state.customScheduleDraft === null ? entry.value : state.customScheduleDraft,
        }),
        el("button", { class: "button button-quiet", type: "submit" }, "Save schedule"),
      );

    return el(
      "li",
      { class: "setting setting-wide" },
      el("label", { class: "setting-name", for: selectId }, "Look for updates"),
      el("span", { class: "setting-value" }, select),
      el(
        "span",
        { class: "setting-help" },
        state.settings.schedule_active
          ? "How often Watchtower checks every container on its own. The first check comes one interval after you change this."
          : [
              "Scheduled checks are off because the update endpoint is on without ",
              code("WATCHTOWER_HTTP_API_PERIODIC_POLLS=true"),
              ". Watchtower only updates when asked, so this has no effect yet.",
            ],
        choice === "custom" && [
          " A custom schedule is a cron expression with seconds first, such as ",
          code("0 0 4 * * *"),
          " for every day at 4:00.",
        ],
        entry.changed && [
          " Changed on this page. ",
          el(
            "button",
            { class: "link-button", type: "button", onclick: () => changeSettings({ schedule: null }, selectId) },
            "Go back to the startup value",
          ),
        ],
      ),
      custom,
    );
  }

  function gateSetting() {
    const entry = state.settings.settings.scan_gate;
    const id = "setting-scan_gate";

    return el(
      "li",
      { class: "setting setting-wide" },
      el("label", { class: "setting-name", for: id }, "Hold back updates that add"),
      el(
        "span",
        { class: "setting-value" },
        el(
          "select",
          {
            class: "select",
            id,
            disabled: !state.settings.settings.scan.value,
            onchange: (event) => changeSettings({ scan_gate: event.target.value }, id),
          },
          GATES.map((item) => el("option", { value: item.value, selected: entry.value === item.value }, item.label)),
        ),
      ),
      el(
        "span",
        { class: "setting-help" },
        "A held update is skipped and reported, and the container keeps its current image. Only findings the running image doesn't already have count, and a scan that fails never holds an update.",
        !state.settings.settings.scan.value && " Needs Scan updates first to be on.",
        entry.changed && [
          " Changed on this page. ",
          el(
            "button",
            { class: "link-button", type: "button", onclick: () => changeSettings({ scan_gate: null }, id) },
            "Go back to the startup value",
          ),
        ],
      ),
    );
  }

  function scannerSetting(security) {
    const entry = state.settings.settings.scanner;
    const id = "setting-scanner";
    const chosen = SCANNERS.find((item) => item.value === entry.value);

    return el(
      "li",
      { class: "setting setting-wide" },
      el("label", { class: "setting-name", for: id }, "Scan with"),
      el(
        "span",
        { class: "setting-value" },
        el(
          "select",
          { class: "select", id, onchange: (event) => changeSettings({ scanner: event.target.value }, id) },
          SCANNERS.map((item) => el("option", { value: item.value, selected: entry.value === item.value }, item.label)),
        ),
      ),
      el(
        "span",
        { class: "setting-help" },
        chosen && `${chosen.help} `,
        security && security.available && security.scanner === entry.value && [
          code(security.scanner_image || security.scanner),
          " runs in a short-lived container for each scan, and Watchtower checks for a newer release of it once a day. ",
        ],
        "Results from each scanner are kept until that container is scanned again.",
        entry.changed && [
          " Changed on this page. ",
          el(
            "button",
            { class: "link-button", type: "button", onclick: () => changeSettings({ scanner: null }, id) },
            "Go back to the startup value",
          ),
        ],
      ),
    );
  }

  function securitySettings() {
    const security = state.security;
    const rows = [
      switchSetting(
        "scan",
        "Scan updates first",
        "Scan the new image of each waiting update before applying it, and note which known vulnerabilities it fixes. Each scan adds a little time to an update.",
      ),
      gateSetting(),
    ];

    if (security && security.available) {
      rows.push(scannerSetting(security));
    } else if (security) {
      rows.push(el("li", { class: "setting" }, el("p", { class: "problem" }, security.reason || "The image scanner isn't available.")));
    }

    return el(
      "section",
      { class: "section" },
      el("h2", { class: "section-title" }, "Security"),
      el("ul", { class: "manifest" }, rows),
      feature("security") &&
        el("p", { class: "section-note" }, "Scan results and fixes are on the ", el("a", { href: "#/security" }, "Security"), " page."),
    );
  }

  function enableHint(endpoint, extra) {
    return ["To turn it on, add ", code(endpoint), " to ", code("WATCHTOWER_HTTP_API_ENDPOINTS"), ".", extra || ""];
  }

  // Notifications

  // Reads a server address typed as "host", "host:port", or a full http(s) URL.
  function serverAddress(text, fallback) {
    const raw = String(text || "").trim() || fallback || "";
    const withScheme = /^[a-z]+:\/\//i.test(raw) ? raw : `https://${raw}`;
    let parsed;

    try {
      parsed = new URL(withScheme);
    } catch {
      throw new Error("The server address isn't valid.");
    }

    if (!parsed.hostname) {
      throw new Error("Enter the server address.");
    }

    return {
      host: parsed.host,
      path: parsed.pathname.replace(/\/+$/, ""),
      insecure: parsed.protocol === "http:",
    };
  }

  function required(fields, key, label) {
    const value = String(fields[key] || "").trim();

    if (!value) {
      throw new Error(`${label} is required.`);
    }

    return value;
  }

  const enc = encodeURIComponent;

  // Each service lists the fields the form asks for and turns them into the
  // Shoutrrr URL Watchtower stores. Secrets are typed into password fields.
  const SERVICES = [
    {
      id: "ntfy",
      label: "ntfy",
      help: "Push notifications to the ntfy app, from ntfy.sh or your own server.",
      fields: [
        { key: "server", label: "Server", placeholder: "ntfy.sh", help: "Leave as ntfy.sh, or enter your own server, for example http://ntfy.lan:8080." },
        { key: "topic", label: "Topic", placeholder: "watchtower-updates", help: "On ntfy.sh anyone who knows the topic can read it, so pick something hard to guess." },
        { key: "token", label: "Access token", secret: true, optional: true, help: "Only for protected topics." },
      ],
      build(fields) {
        const server = serverAddress(fields.server, "ntfy.sh");
        const query = new URLSearchParams();

        if (fields.token) {
          query.set("token", fields.token.trim());
        }

        if (server.insecure) {
          query.set("scheme", "http");
        }

        const suffix = query.toString() ? `?${query}` : "";

        return `ntfy://${server.host}${server.path}/${enc(required(fields, "topic", "Topic"))}${suffix}`;
      },
    },
    {
      id: "discord",
      label: "Discord",
      help: "Post to a Discord channel through a webhook.",
      fields: [
        { key: "webhook", label: "Webhook URL", secret: true, placeholder: "https://discord.com/api/webhooks/…", help: "Channel settings, Integrations, Webhooks, Copy webhook URL." },
      ],
      build(fields) {
        const match = required(fields, "webhook", "Webhook URL").match(/\/api\/webhooks\/(\d+)\/([^/?#\s]+)/);

        if (!match) {
          throw new Error("That doesn't look like a Discord webhook URL.");
        }

        return `discord://${match[2]}@${match[1]}`;
      },
    },
    {
      id: "telegram",
      label: "Telegram",
      help: "Message a Telegram chat or channel from your bot.",
      fields: [
        { key: "token", label: "Bot token", secret: true, placeholder: "123456:ABC-DEF…", help: "From @BotFather." },
        { key: "chats", label: "Chat IDs", placeholder: "-1001234567890, @mychannel", help: "Separate several with commas. Forward a message to @shoutrrrbot to find a chat's ID." },
      ],
      build(fields) {
        const chats = required(fields, "chats", "Chat IDs")
          .split(",")
          .map((chat) => chat.trim())
          .filter(Boolean)
          .join(",");

        return `telegram://${required(fields, "token", "Bot token")}@telegram?chats=${enc(chats)}`;
      },
    },
    {
      id: "gotify",
      label: "Gotify",
      help: "Push to your own Gotify server.",
      fields: [
        { key: "server", label: "Server", placeholder: "https://gotify.example.com" },
        { key: "token", label: "Application token", secret: true, placeholder: "A…", help: "Create an application in Gotify and copy its token." },
      ],
      build(fields) {
        const server = serverAddress(required(fields, "server", "Server"));
        const suffix = server.insecure ? "?disabletls=yes" : "";

        return `gotify://${server.host}${server.path}/${enc(required(fields, "token", "Application token"))}${suffix}`;
      },
    },
    {
      id: "pushover",
      label: "Pushover",
      help: "Push to the Pushover app.",
      fields: [
        { key: "user", label: "User key", secret: true, help: "Shown at the top right of your Pushover dashboard." },
        { key: "token", label: "API token", secret: true, help: "From the application you created for Watchtower." },
      ],
      build(fields) {
        return `pushover://shoutrrr:${enc(required(fields, "token", "API token"))}@${enc(required(fields, "user", "User key"))}/`;
      },
    },
    {
      id: "slack",
      label: "Slack",
      help: "Post to a Slack channel through an incoming webhook.",
      fields: [
        { key: "webhook", label: "Webhook URL", secret: true, placeholder: "https://hooks.slack.com/services/…" },
      ],
      build(fields) {
        const match = required(fields, "webhook", "Webhook URL").match(/hooks\.slack\.com\/services\/([^/]+)\/([^/]+)\/([^/?#\s]+)/);

        if (!match) {
          throw new Error("That doesn't look like a Slack webhook URL.");
        }

        return `slack://hook:${match[1]}-${match[2]}-${match[3]}@webhook`;
      },
    },
    {
      id: "smtp",
      label: "Email",
      help: "Send email through an SMTP server.",
      fields: [
        { key: "host", label: "SMTP server", placeholder: "smtp.gmail.com" },
        { key: "port", label: "Port", placeholder: "587" },
        { key: "username", label: "Username", optional: true },
        { key: "password", label: "Password", secret: true, optional: true, help: "For Gmail and similar, use an app password." },
        { key: "from", label: "From address", placeholder: "watchtower@example.com" },
        { key: "to", label: "To addresses", placeholder: "you@example.com", help: "Separate several with commas." },
      ],
      build(fields) {
        const user = String(fields.username || "").trim();
        const password = String(fields.password || "");
        const auth = user ? `${enc(user)}${password ? `:${enc(password)}` : ""}@` : "";
        const port = String(fields.port || "").trim() || "587";
        const query = new URLSearchParams({
          fromaddress: required(fields, "from", "From address"),
          toaddresses: required(fields, "to", "To addresses")
            .split(",")
            .map((to) => to.trim())
            .filter(Boolean)
            .join(","),
        });

        if (!user) {
          query.set("auth", "None");
        }

        return `smtp://${auth}${required(fields, "host", "SMTP server")}:${port}/?${query}`;
      },
    },
    {
      id: "webhook",
      label: "Webhook",
      help: "POST a JSON message to any URL, for Home Assistant, n8n, and similar.",
      fields: [{ key: "url", label: "URL", placeholder: "https://example.com/hooks/watchtower" }],
      build(fields) {
        const target = required(fields, "url", "URL");

        if (!/^https?:\/\//i.test(target)) {
          throw new Error("The URL must start with http:// or https://.");
        }

        return `generic+${target}`;
      },
    },
    {
      id: "custom",
      label: "Other",
      help: "Any service Shoutrrr supports, such as Matrix, Teams, Mattermost, or Bark.",
      fields: [
        {
          key: "url",
          label: "Shoutrrr URL",
          secret: true,
          placeholder: "matrix://user:password@matrix.example.com/?rooms=!room",
          help: "Each service's format is in the Shoutrrr documentation.",
        },
      ],
      build(fields) {
        return required(fields, "url", "Shoutrrr URL");
      },
    },
  ];

  function serviceLabel(id) {
    const known = SERVICES.find((service) => service.id === id || (id === "generic" && service.id === "webhook"));

    return known ? known.label : capitalise(id);
  }

  async function notificationAction(kind) {
    const draft = state.notifyDraft;
    const service = SERVICES.find((item) => item.id === draft.service);
    let url;

    try {
      url = service.build(draft.fields);
    } catch (problem) {
      notify(problem.message, true);

      return;
    }

    state.notifyBusy = kind;
    render();

    try {
      if (kind === "test") {
        await request("POST", "/v1/settings/test-notification", { url });
        notify(`Sent a test message to ${service.label}. Check that it arrived.`);
      } else {
        state.notifications = await request("POST", "/v1/settings/notifications", { name: draft.name, url });
        state.notifyDraft = { service: draft.service, name: "", fields: {} };
        notify(`${service.label} added. Watchtower sends its update reports there from now on.`);
      }
    } catch (problem) {
      notify(kind === "test" ? `The test message didn't send. ${problem.message}` : `Couldn't add ${service.label}. ${problem.message}`, true);
    }

    state.notifyBusy = "";
    render();
  }

  async function removeNotification(id) {
    if (state.removingService !== id) {
      state.removingService = id;
      render();

      return;
    }

    state.notifyBusy = id;
    render();

    try {
      state.notifications = await request("DELETE", `/v1/settings/notifications/${encodeURIComponent(id)}`);
      notify("Notification service removed.");
    } catch (problem) {
      notify(`Couldn't remove it. ${problem.message}`, true);
    }

    state.notifyBusy = "";
    state.removingService = "";
    render();
  }

  async function testAll(event) {
    const button = event.currentTarget;

    button.disabled = true;

    try {
      await request("POST", "/v1/settings/test-notification", {});
      notify("Sent a test message to every service. Check that they arrived.");
    } catch (problem) {
      notify(`The test message didn't send. ${problem.message}`, true);
    }

    button.disabled = false;
  }

  function notificationRow(service) {
    const fromConfig = service.source === "config";
    const confirming = state.removingService === service.id;
    const title = service.name || serviceLabel(service.service);
    const detail = [service.name ? serviceLabel(service.service) : "", service.host].filter(Boolean).join(", ");

    return el(
      "li",
      { class: "setting" },
      el("span", { class: "setting-name" }, title),
      el(
        "span",
        { class: "setting-value" },
        fromConfig
          ? el("span", { class: "setting-off" }, "From config")
          : el(
              "button",
              {
                class: confirming ? "button button-quiet button-tiny button-stop" : "button button-quiet button-tiny",
                type: "button",
                disabled: state.notifyBusy === service.id,
                "aria-label": confirming ? `Confirm removing ${title}` : `Remove ${title}`,
                onclick: () => removeNotification(service.id),
              },
              confirming ? "Confirm remove" : "Remove",
            ),
      ),
      el(
        "span",
        { class: "setting-help" },
        [detail, fromConfig ? "Set with WATCHTOWER_NOTIFICATION_URL, so change it there." : ""].filter(Boolean).join(". "),
      ),
    );
  }

  function notificationForm() {
    const draft = state.notifyDraft;
    const service = SERVICES.find((item) => item.id === draft.service) || SERVICES[0];
    const busy = Boolean(state.notifyBusy);
    const field = (spec) => {
      const id = `notify-${spec.key}`;

      return el(
        "div",
        { class: "field" },
        el("label", { class: "field-label", for: id }, spec.label, spec.optional && el("span", { class: "field-optional" }, " (optional)")),
        el("input", {
          class: "field-input",
          id,
          type: spec.secret ? "password" : "text",
          autocomplete: "off",
          spellcheck: "false",
          placeholder: spec.placeholder,
          value: draft.fields[spec.key] || "",
          "aria-describedby": spec.help && `${id}-help`,
          oninput: (event) => {
            draft.fields[spec.key] = event.target.value;
          },
        }),
        spec.help && el("p", { class: "field-help", id: `${id}-help` }, spec.help),
      );
    };

    return el(
      "form",
      {
        class: "form notify-form",
        onsubmit: (event) => {
          event.preventDefault();
          notificationAction("add");
        },
      },
      el(
        "div",
        { class: "field" },
        el("label", { class: "field-label", for: "notify-service" }, "Service"),
        el(
          "select",
          {
            class: "select",
            id: "notify-service",
            onchange: (event) => {
              state.notifyDraft = { service: event.target.value, name: draft.name, fields: {} };
              render();
              document.getElementById("notify-service")?.focus();
            },
          },
          SERVICES.map((item) => el("option", { value: item.id, selected: item.id === service.id }, item.label)),
        ),
        el("p", { class: "field-help" }, service.help),
      ),
      service.fields.map(field),
      el(
        "div",
        { class: "field" },
        el("label", { class: "field-label", for: "notify-name" }, "Name", el("span", { class: "field-optional" }, " (optional)")),
        el("input", {
          class: "field-input field-input-text",
          id: "notify-name",
          type: "text",
          autocomplete: "off",
          maxlength: "80",
          placeholder: `${service.label} on my phone`,
          value: draft.name,
          oninput: (event) => {
            draft.name = event.target.value;
          },
        }),
      ),
      el(
        "div",
        { class: "actions" },
        el(
          "button",
          { class: "button", type: "button", disabled: busy, onclick: () => notificationAction("test") },
          state.notifyBusy === "test" ? "Sending" : "Send a test",
        ),
        el("button", { class: "button button-primary", type: "submit", disabled: busy }, state.notifyBusy === "add" ? "Adding" : `Add ${service.label}`),
      ),
    );
  }

  function notificationsSection() {
    const data = state.notifications;
    const parts = [
      el("h2", { class: "section-title" }, "Notifications"),
      el(
        "p",
        { class: "section-note" },
        "Watchtower sends a report to these services after each scan that updates or fails on something.",
      ),
    ];

    if (state.notificationsProblem && !data) {
      parts.push(el("p", { class: "blank" }, el("strong", null, "Notification services didn't load."), state.notificationsProblem));

      return el("section", { class: "section" }, parts);
    }

    if (!data) {
      return el("section", { class: "section" }, parts, el("p", { class: "setting-help" }, "Loading notification services."));
    }

    const services = data.services || [];

    parts.push(
      services.length > 0
        ? el(
            "ul",
            { class: "manifest" },
            services.map(notificationRow),
            el(
              "li",
              { class: "setting" },
              el("span", { class: "setting-name" }, "Test every service"),
              el(
                "span",
                { class: "setting-value" },
                el("button", { class: "button button-quiet button-tiny", type: "button", onclick: testAll }, "Send test"),
              ),
              el("span", { class: "setting-help" }, "Sends one message to each service above."),
            ),
          )
        : el("p", { class: "blank" }, el("strong", null, "No notifications set up."), "Add a service below to hear about updates on your phone or in chat."),
    );

    if (!data.saved) {
      parts.push(
        el("p", { class: "problem" }, "Services added here are forgotten when Watchtower restarts, because no ", code("/data"), " folder is mounted."),
      );
    }

    parts.push(el("h3", { class: "detail-title notify-add-title" }, "Add a service"), notificationForm());

    return el("section", { class: "section" }, parts);
  }

  function settingsView() {
    const config = state.config;
    const editable = feature("settings") && state.settings;
    const sections = [
      el("h1", { class: "title" }, "Settings"),
      el(
        "p",
        { class: "lede" },
        editable
          ? "Switches and the schedule can be changed here and take effect straight away. Everything else comes from Watchtower's flags and environment variables."
          : "How this Watchtower is set up. These come from its flags and environment variables, so change them there and restart.",
      ),
    ];

    if (editable && !state.settings.saved) {
      sections.push(
        el(
          "p",
          { class: "problem" },
          "Changes made here last until Watchtower restarts. To keep them, mount a folder at ",
          code("/data"),
          " in the container, for example ",
          code("./watchtower-data:/data"),
          ".",
        ),
      );
    }

    if (feature("settings") && state.settingsProblem) {
      sections.push(
        el("p", { class: "blank" }, el("strong", null, "The editable settings didn't load."), state.settingsProblem),
      );
    }

    if (editable) {
      sections.push(
        el(
          "section",
          { class: "section" },
          el("h2", { class: "section-title" }, "Schedule"),
          el("ul", { class: "manifest" }, scheduleSetting()),
        ),
      );
    }

    if (editable || (feature("config") && config)) {
      const rows = [];

      if (editable) {
        rows.push(
          switchSetting(
            "monitor_only",
            "Apply updates",
            "When off, Watchtower reports new images but leaves containers alone.",
            true,
          ),
          switchSetting("cleanup", "Remove old images", "Delete the previous image once a container is running the new one."),
          switchSetting(
            "rolling_restart",
            "Rolling restart",
            "Restart containers one at a time instead of all together. Needs Apply updates to be on.",
          ),
          switchSetting(
            "auto_rollback",
            "Automatic rollback",
            "Revert containers to their previous image if a new image fails to start or crashes.",
          ),
        );
      } else {
        rows.push(
          setting(
            "Apply updates",
            !config.monitor_only,
            config.monitor_only
              ? "Monitor only. Watchtower reports new images but leaves containers alone."
              : "Watchtower replaces a container when its image has a newer version.",
          ),
          setting("Remove old images", config.cleanup, "Delete the previous image once a container is running the new one."),
          setting("Rolling restart", config.rolling_restart, "Restart containers one at a time instead of all together."),
        );
      }

      if (config) {
        rows.push(
          setting("Pull new images", !config.no_pull, "Fetch images from the registry before comparing them."),
          setting("Restart containers", !config.no_restart, "Restart a container after its image is updated."),
          setting("Lifecycle hooks", config.lifecycle_hooks, "Run the commands set in container labels before and after an update."),
          setting("Git watching", config.git_enable, "Watch Git repositories as well as image registries."),
        );
      }

      sections.push(
        el(
          "section",
          { class: "section" },
          el("h2", { class: "section-title" }, "Updating"),
          el("ul", { class: "manifest" }, rows),
        ),
      );
    }

    if (editable && state.settings.settings.scan) {
      sections.push(securitySettings());
    }

    if (feature("settings")) {
      sections.push(notificationsSection());
    }

    if (feature("config") && config) {
      sections.push(
        el(
          "section",
          { class: "section" },
          el("h2", { class: "section-title" }, "Which containers"),
          el(
            "ul",
            { class: "manifest" },
            el(
              "li",
              { class: "setting" },
              el("span", { class: "setting-name" }, "Watching"),
              el("span", { class: "setting-help" }, config.filter_desc || "All containers"),
            ),
            setting("Only labelled containers", config.label_enable, [
              "Watch only containers with the label ",
              code("com.centurylinklabs.watchtower.enable=true"),
              ".",
            ]),
            editable && state.settings.settings.include_stopped
              ? switchSetting(
                  "include_stopped",
                  "Stopped containers",
                  "List, check, and update containers that aren't running. An updated container stays stopped.",
                )
              : setting("Stopped containers", config.include_stopped, "Include containers that aren't running."),
            setting("Restarting containers", config.include_restarting, "Include containers that are restarting."),
            config.scope &&
              el(
                "li",
                { class: "setting" },
                el("span", { class: "setting-name" }, "Scope"),
                el("span", { class: "setting-help" }, code(config.scope)),
              ),
          ),
        ),
      );
    } else if (feature("config") && state.configProblem) {
      sections.push(el("p", { class: "blank" }, el("strong", null, "Settings didn't load."), state.configProblem));
    } else if (!feature("config")) {
      sections.push(
        el(
          "p",
          { class: "lede" },
          "Watchtower isn't sharing the rest of its settings. Add ",
          code("config"),
          " to ",
          code("WATCHTOWER_HTTP_API_ENDPOINTS"),
          " to see them here.",
        ),
      );
    }

    sections.push(
      el(
        "section",
        { class: "section" },
        el("h2", { class: "section-title" }, "What this page can do"),
        el(
          "ul",
          { class: "manifest" },
          setting(
            "List containers",
            feature("containers"),
            feature("containers") ? "Shows the containers Watchtower is watching." : enableHint("containers"),
          ),
          setting(
            "Check for updates",
            feature("check"),
            feature("check") ? "Looks for newer images without changing anything." : enableHint("check"),
          ),
          setting(
            "Update containers",
            feature("update"),
            feature("update")
              ? "Updates a container when you ask."
              : enableHint("update", [
                  " Also set ",
                  code("WATCHTOWER_HTTP_API_PERIODIC_POLLS=true"),
                  ", or Watchtower stops updating on its own schedule.",
                ]),
          ),
          setting(
            "Scan history",
            feature("history"),
            feature("history") ? "Lists Watchtower's recent scans." : enableHint("history"),
          ),
          setting("Show settings", feature("config"), feature("config") ? "Shows the setup above." : enableHint("config")),
          setting(
            "Scan images",
            feature("security"),
            feature("security") ? "Scans running images for known vulnerabilities and shows how to fix them." : enableHint("security"),
          ),
          setting(
            "Change settings",
            feature("settings"),
            feature("settings") ? "Lets you change the schedule and switches above." : enableHint("settings"),
          ),
        ),
      ),
    );

    return el("div", null, sections);
  }

  // Sign in

  function gate() {
    const input = el("input", {
      class: "field-input",
      id: "token",
      type: "password",
      autocomplete: "current-password",
      required: true,
      "aria-describedby": "token-help",
    });
    const error = el("p", { class: "field-error", role: "alert" });
    const submit = el("button", { class: "button button-primary", type: "submit" }, "Sign in");

    const form = el(
      "form",
      {
        class: "form",
        onsubmit: async (event) => {
          event.preventDefault();
          submit.disabled = true;
          error.textContent = "";

          try {
            state.session = await request("POST", "/ui/session", { token: input.value });
            await start();
          } catch (problem) {
            error.textContent =
              problem.status === 401
                ? "That token doesn't match. Check WATCHTOWER_HTTP_API_TOKEN and try again."
                : problem.message;
            submit.disabled = false;
            input.select();
          }
        },
      },
      el(
        "div",
        { class: "field" },
        el("label", { class: "field-label", for: "token" }, "API token"),
        input,
        el(
          "p",
          { class: "field-help", id: "token-help" },
          "The value you set for ",
          code("WATCHTOWER_HTTP_API_TOKEN"),
          ". This browser stays signed in for 30 days.",
        ),
      ),
      error,
      submit,
    );

    queueMicrotask(() => input.focus());

    return el(
      "main",
      { class: "gate", id: "main" },
      el(
        "div",
        { class: "gate-ends", "aria-hidden": "true" },
        el("span", { class: "end end-fresh" }),
        el("span", { class: "end end-fresh" }),
        el("span", { class: "end end-waiting" }),
        el("span", { class: "end end-fresh" }),
      ),
      el("h1", { class: "title" }, "Watchtower"),
      form,
    );
  }

  // Frame and routing

  const views = [
    { hash: "#/containers", label: "Containers", draw: containersView },
    { hash: "#/security", label: "Security", draw: securityView },
    { hash: "#/history", label: "History", draw: historyView },
    { hash: "#/settings", label: "Settings", draw: settingsView },
  ];

  function currentView() {
    return views.find((view) => view.hash === location.hash) || views[0];
  }

  async function signOut() {
    try {
      await request("DELETE", "/ui/session");
    } catch {
      // The cookie may already be gone. Showing the sign-in page is right either way.
    }

    state.session = { authenticated: false };
    state.checks = new Map();
    state.checkedAt = null;
    render();
  }

  function render() {
    if (!state.session) {
      app.replaceChildren();

      return;
    }

    if (!state.session.authenticated) {
      app.replaceChildren(gate());

      return;
    }

    const view = currentView();

    document.title = `${view.label} | Watchtower`;

    app.replaceChildren(
      el(
        "header",
        { class: "masthead" },
        el(
          "a",
          { class: "wordmark", href: views[0].hash },
          el("span", { class: "end end-small end-fresh", "aria-hidden": "true" }),
          "Watchtower",
        ),
        el(
          "nav",
          { class: "nav", "aria-label": "Sections" },
          views.map((item) =>
            el("a", { class: "nav-link", href: item.hash, "aria-current": item === view && "page" }, item.label),
          ),
        ),
        el("button", { class: "link-button", type: "button", onclick: signOut }, "Sign out"),
      ),
      el("main", { class: "page", id: "main" }, view.draw()),
      el(
        "footer",
        { class: "foot" },
        state.session.version ? `Watchtower ${state.session.version}` : "Watchtower",
        feature("swagger") && [". ", el("a", { href: "/swagger/index.html" }, "API reference")],
      ),
    );
  }

  async function refresh() {
    if (!state.session || !state.session.authenticated || document.hidden) {
      return;
    }

    // A scheduled update shows up here within a minute; while one runs the
    // progress poll keeps the page current instead.
    if (!activityTimer) {
      await pollActivity();
    }

    if (updateRunning() || state.checking || document.querySelector("dialog[open]")) {
      return;
    }

    const view = currentView();

    if (view.draw === historyView) {
      await loadHistory();
      render();
    } else if (view.draw === containersView) {
      const nextRun = state.settings && state.settings.next_run ? new Date(state.settings.next_run) : null;

      await Promise.all([
        loadContainers(),
        loadHistory(),
        loadChecks(),
        // The next scan time moves on once a scan has started.
        nextRun && nextRun <= new Date() && loadSettings(),
      ]);
      // Redraw only the parts that change, so typing in the search box isn't interrupted.
      const slot = document.getElementById("lookout-slot");

      if (slot) {
        slot.replaceChildren(lookout());
      }

      renderManifest();
    } else if (view.draw === securityView) {
      await Promise.all([loadContainers(), loadChecks(), !securityTimer && loadSecurity()]);
      renderSecurity();
    }
  }

  async function start() {
    render();
    // History also feeds each container's update history on the Containers view.
    await Promise.all([
      loadContainers(),
      loadConfig(),
      loadSettings(),
      loadHistory(),
      loadChecks(),
      loadNotifications(),
      loadSecurity(),
    ]);
    render();
    // Picks up a security scan that was already running.
    scheduleSecurityPoll();
    // Picks up an update that was already running, for example before a reload.
    await pollActivity();
  }

  window.addEventListener("hashchange", async () => {
    render();
    window.scrollTo(0, 0);

    if (currentView().draw === historyView) {
      await loadHistory();
      render();
    } else if (currentView().draw === securityView && !securityTimer) {
      await loadSecurity();
      renderSecurity();
    }
  });

  (async () => {
    try {
      state.session = await request("GET", "/ui/session");
    } catch (problem) {
      state.session = { authenticated: false };
      notify(problem.message, true);
    }

    if (state.session.authenticated) {
      await start();
    } else {
      render();
    }

    setInterval(refresh, REFRESH_MS);
  })();
})();
