"use strict";

// Everything shown here that came from a scanned page -- names, bios, evidence
// quoting them -- is attacker-controlled. It is only ever inserted with
// textContent (via el()), never innerHTML, and links pass an http(s) allowlist.

const TOKEN_HEADER = "X-Whoseeme-Token";
let token = "";
let jobId = "";

function initToken() {
  const params = new URLSearchParams(location.search);
  const fromUrl = params.get("token");
  if (fromUrl) {
    token = fromUrl;
    try { sessionStorage.setItem("whoseeme-token", fromUrl); } catch (_) { /* storage blocked */ }
    // Drop the token from the address bar and history.
    history.replaceState(null, "", location.pathname);
  } else {
    try { token = sessionStorage.getItem("whoseeme-token") || ""; } catch (_) { token = ""; }
  }
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function safeLink(url, label) {
  let allowed = false;
  try { allowed = ["http:", "https:"].includes(new URL(url).protocol); } catch (_) { allowed = false; }
  if (!allowed) return document.createTextNode(label || url || "");
  return el("a", { href: url, rel: "noopener noreferrer", target: "_blank" }, label || url);
}

function show(id) {
  for (const section of document.querySelectorAll("main > section")) section.hidden = section.id !== id;
  window.scrollTo(0, 0);
}

function showError(id, message) {
  const node = document.getElementById(id);
  node.textContent = message;
  node.hidden = !message;
}

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", [TOKEN_HEADER]: token },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(response.status === 403
      ? "This page lost its access key. Close it and run whoseeme again."
      : (text || response.statusText));
  }
  return JSON.parse(text);
}

// --- start ---------------------------------------------------------------------

async function startScan(event) {
  event.preventDefault();
  showError("start-error", "");
  const handles = document.getElementById("handles").value;
  const email = document.getElementById("email").value.trim();
  const includeAdult = document.getElementById("include-adult").checked;
  try {
    const job = await post("/api/scan", { handles, email, include_adult: includeAdult });
    jobId = job.job_id;
    watchScan(job.total);
  } catch (error) {
    showError("start-error", error.message);
  }
}

function watchScan(total) {
  show("scanning");
  showError("scan-error", "");
  const bar = document.getElementById("progress");
  const text = document.getElementById("progress-text");
  const live = document.getElementById("live-hits");
  live.replaceChildren();
  bar.max = Math.max(total, 1);
  bar.value = 0;

  const url = `/api/scan/${encodeURIComponent(jobId)}/events?token=${encodeURIComponent(token)}`;
  const events = new EventSource(url);
  // The server replays every event from the start on each connection, so a
  // reconnect after a network hiccup must not duplicate what's already shown.
  events.addEventListener("open", () => live.replaceChildren());
  events.addEventListener("progress", (e) => {
    const p = JSON.parse(e.data);
    bar.value = p.done;
    text.textContent = `Checked ${p.done} of ${p.total} sites · ${p.found} possible account${p.found === 1 ? "" : "s"}`;
  });
  events.addEventListener("hit", (e) => {
    const hit = JSON.parse(e.data);
    live.append(el("li", { class: hit.status === "Found" ? "found" : "maybe", text: hit.site }));
  });
  events.addEventListener("done", (e) => {
    events.close();  // otherwise EventSource reconnects and replays the stream
    renderChoices(JSON.parse(e.data).hits);
  });
  events.addEventListener("error", (e) => {
    if (e.data) {
      events.close();
      showError("scan-error", JSON.parse(e.data).message);
    }
  });
}

// --- choose --------------------------------------------------------------------

function choiceTable() {
  const table = el("table", { class: "choices" });
  table.append(el("tr", {}, el("th", { text: "Site" }), el("th", { text: "Profile" }),
    el("th", { text: "Name shown" }), el("th", { text: "Is this you?" })));
  return table;
}

function renderChoices(hits) {
  show("choose");
  const container = document.getElementById("choices");
  container.replaceChildren();
  const build = document.getElementById("build");
  const filter = document.getElementById("filter");
  filter.value = "";

  if (!hits.length) {
    container.append(el("p", { text: "No accounts were found under these usernames." }));
    build.hidden = true;
    filter.hidden = true;
    return;
  }
  build.hidden = false;
  filter.hidden = false;

  // A common handle can match hundreds of sites, most of them other people or
  // false positives. Confident matches are listed; Maybe results -- mostly bot
  // walls and error pages -- are folded away until asked for.
  const found = el("tbody");
  const maybe = el("tbody");
  const foundTable = choiceTable();
  const maybeTable = choiceTable();
  foundTable.append(found);
  maybeTable.append(maybe);

  hits.forEach((hit, i) => {
    const group = el("div", { class: "segmented", role: "radiogroup", "aria-label": `Is ${hit.site} yours?` });
    for (const [value, label] of [["mine", "Mine"], ["unsure", "Not sure"], ["notmine", "Not mine"]]) {
      const id = `c${i}-${value}`;
      const input = el("input", { type: "radio", name: `c${i}`, id, value, "data-key": hit.key });
      if (value === "unsure") input.checked = true;
      input.addEventListener("change", updateBuildButton);
      group.append(input, el("label", { for: id, text: label }));
    }
    const row = el("tr", { "data-site": hit.site.toLowerCase() },
      el("td", { text: hit.site }),
      el("td", {}, safeLink(hit.url)),
      el("td", { text: hit.name || "—" }),
      el("td", {}, group));
    (hit.status === "Maybe" ? maybe : found).append(row);
  });

  const maybeCount = maybe.children.length;
  if (found.children.length) container.append(foundTable);
  if (maybeCount) {
    const details = el("details", { class: "maybe-block" },
      el("summary", { text: `${maybeCount} lower-confidence match${maybeCount === 1 ? "" : "es"}` }),
      el("p", { class: "hint", text: "Often a sign-in wall or an error page rather than a real profile." }),
      maybeTable);
    if (!found.children.length) details.open = true;
    container.append(details);
  }
  applyFilter();
  updateBuildButton();
}

function applyFilter() {
  const term = document.getElementById("filter").value.trim().toLowerCase();
  let shown = 0;
  let total = 0;
  for (const row of document.querySelectorAll("#choices tr[data-site]")) {
    total += 1;
    const match = !term || row.dataset.site.includes(term);
    row.hidden = !match;
    if (match) shown += 1;
  }
  // Expand the folded Maybe list when a search hits something inside it.
  const details = document.querySelector("#choices details");
  if (details && term && details.querySelector("tr[data-site]:not([hidden])")) details.open = true;
  document.getElementById("choice-count").textContent = term
    ? `${shown} of ${total} match "${term}"`
    : `${total} possible account${total === 1 ? "" : "s"}. Search for one you know is yours.`;
}

function choices() {
  const anchors = [];
  const rejected = [];
  for (const input of document.querySelectorAll("#choices input[type=radio]:checked")) {
    if (input.value === "mine") anchors.push(input.dataset.key);
    if (input.value === "notmine") rejected.push(input.dataset.key);
  }
  return { anchors, rejected };
}

function updateBuildButton() {
  document.getElementById("build").disabled = choices().anchors.length === 0;
}

async function buildReport() {
  showError("choose-error", "");
  const button = document.getElementById("build");
  button.disabled = true;
  button.textContent = "Building…";
  try {
    const audit = await post("/api/report", { job_id: jobId, ...choices() });
    renderReport(audit);
  } catch (error) {
    showError("choose-error", error.message);
  } finally {
    button.textContent = "Build my report";
    updateBuildButton();
  }
}

// --- report --------------------------------------------------------------------

function renderReport(audit) {
  show("report");
  const s = audit.summary;
  const f = s.findings;
  document.getElementById("summary").replaceChildren(
    `${s.accounts} account${s.accounts === 1 ? "" : "s"} traced to you — ${s.confirmed} you confirmed, `,
    `${s.linked_by_evidence} linked to them by evidence. `,
    el("span", { class: "sev high", text: `${f.high} high` }),
    el("span", { class: "sev medium", text: `${f.medium} medium` }),
    el("span", { class: "sev low", text: `${f.low} low` }),
  );
  document.getElementById("avatar-note").hidden = s.avatar_matching;

  const accounts = Object.fromEntries(audit.accounts.map((a) => [a.key, a]));

  const findings = document.getElementById("findings");
  findings.replaceChildren();
  if (!audit.findings.length) findings.append(el("p", { class: "hint", text: "No findings." }));
  for (const finding of audit.findings) {
    findings.append(el("div", { class: "card" },
      el("span", { class: `sev ${finding.severity}`, text: finding.severity }),
      el("strong", { text: finding.title }),
      el("p", { text: finding.evidence }),
      el("p", { class: "hint", text: finding.advice })));
  }

  const links = document.getElementById("links");
  links.replaceChildren(el("tr", {}, el("th", { text: "Account" }), el("th", { text: "Account" }),
    el("th", { text: "Linked by" })));
  for (const edge of audit.links) {
    links.append(el("tr", {},
      el("td", { text: accounts[edge.a]?.site || edge.a }),
      el("td", { text: accounts[edge.b]?.site || edge.b }),
      el("td", { text: edge.via.map((v) => v.replaceAll("_", " ")).join(", ") })));
  }
  document.getElementById("links-block").hidden = audit.links.length === 0;

  const table = document.getElementById("accounts");
  table.replaceChildren(el("tr", {}, el("th", { text: "Site" }), el("th", { text: "Profile" }),
    el("th", { text: "How it was traced" }), el("th", { text: "Delete it" })));
  for (const account of audit.accounts) {
    const fix = account.remediation;
    const del = fix
      ? el("span", {}, safeLink(fix.url, "instructions"), " ", el("span", { class: `tag ${fix.difficulty}`, text: fix.difficulty }))
      : el("span", { class: "hint", text: "no guidance on file" });
    table.append(el("tr", {},
      el("td", { text: account.site }),
      el("td", {}, safeLink(account.url)),
      el("td", {
        text: account.source === "confirmed" ? "you confirmed it" : (account.linked_via?.text || "linked to your accounts"),
        title: account.linked_via?.detail || "",
      }),
      el("td", {}, del)));
  }

  const unconfirmed = document.getElementById("unconfirmed");
  unconfirmed.replaceChildren();
  for (const row of audit.unconfirmed) {
    unconfirmed.append(el("tr", {}, el("td", { text: row.site }), el("td", {}, safeLink(row.url)),
      el("td", { text: row.status })));
  }
  document.getElementById("unconfirmed-block").hidden = audit.unconfirmed.length === 0;

  const base = `/api/report/${encodeURIComponent(jobId)}`;
  const q = `?token=${encodeURIComponent(token)}`;
  document.getElementById("download-html").href = `${base}.html${q}`;
  document.getElementById("download-json").href = `${base}.json${q}`;
}

function restart() {
  jobId = "";
  document.getElementById("start-form").reset();
  show("start");
}

initToken();
document.getElementById("start-form").addEventListener("submit", startScan);
document.getElementById("filter").addEventListener("input", applyFilter);
document.getElementById("build").addEventListener("click", buildReport);
document.getElementById("restart-choose").addEventListener("click", restart);
document.getElementById("restart-report").addEventListener("click", restart);
