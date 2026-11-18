/**
 * MCP Apps view (extension io.modelcontextprotocol/ui, spec 2026-01-26).
 *
 * One self-contained HTML document (no external scripts, styles or network
 * access) that renders results from bug_search, bug_get, psirt_search,
 * psirt_get, device_lookup and assess_upgrade as tables. It speaks the
 * MCP Apps JSON-RPC protocol over postMessage: ui/initialize, then it
 * receives ui/notifications/tool-input and ui/notifications/tool-result
 * (structuredContent), opens Cisco links with ui/open-link, and can page
 * through results by calling tools/call.
 */

export const UI_EXTENSION_ID = 'io.modelcontextprotocol/ui';
export const UI_MIME_TYPE = 'text/html;profile=mcp-app';
export const RESULTS_APP_URI = 'ui://mcp-cisco-support/results.html';

/** Tools whose results the view can render */
export const UI_TOOLS = ['bug_get', 'bug_search', 'psirt_get', 'psirt_search', 'device_lookup', 'assess_upgrade'];

// The view script avoids template literals so this file can embed it in String.raw
export const RESULTS_APP_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cisco Support results</title>
<style>
  :root {
    --bg: #ffffff; --fg: #1c1f24; --muted: #5f6672; --line: #e3e6ea; --head: #f5f6f8;
    --link: #0a5fb4; --chip: #eef1f5; --chip-on: #0a5fb4; --chip-on-fg: #ffffff;
    --sev1: #b42318; --sev2: #c4320a; --sev3: #b54708; --sev4: #475467; --ok: #067647; --bad: #b42318;
  }
  :root[data-theme="dark"] {
    --bg: #17191c; --fg: #e8eaed; --muted: #9aa1ab; --line: #2c3036; --head: #1f2226;
    --link: #6cb0ff; --chip: #262a30; --chip-on: #3d8bfd; --chip-on-fg: #0b0d10;
    --sev1: #ff8a80; --sev2: #ffab70; --sev3: #f5c26b; --sev4: #aab4c0; --ok: #6fd39b; --bad: #ff8a80;
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 12px; background: var(--bg); color: var(--fg);
    font: 13px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  h2 { font-size: 14px; margin: 14px 0 6px; }
  .meta { color: var(--muted); margin: 4px 0 8px; }
  .bar { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 6px 0; }
  .chip { border: 1px solid var(--line); background: var(--chip); color: var(--fg); border-radius: 999px;
    padding: 2px 10px; cursor: pointer; font: inherit; }
  .chip[aria-pressed="true"] { background: var(--chip-on); color: var(--chip-on-fg); border-color: var(--chip-on); }
  input[type=search] { font: inherit; padding: 3px 8px; border: 1px solid var(--line); border-radius: 6px;
    background: var(--bg); color: var(--fg); min-width: 180px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { background: var(--head); font-weight: 600; position: sticky; top: 0; }
  a { color: var(--link); text-decoration: none; cursor: pointer; }
  a:hover { text-decoration: underline; }
  .sev { font-weight: 600; }
  .sev-1, .sir-Critical { color: var(--sev1); } .sev-2, .sir-High { color: var(--sev2); }
  .sev-3, .sir-Medium { color: var(--sev3); } .sev-4, .sev-5, .sev-6, .sir-Low, .sir-Informational { color: var(--sev4); }
  .yes { color: var(--ok); font-weight: 600; } .no { color: var(--bad); font-weight: 600; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; margin: 8px 0; }
  .card { border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; }
  .card b { display: block; font-size: 18px; }
  .card span { color: var(--muted); }
  .small { color: var(--muted); font-size: 12px; }
  pre { white-space: pre-wrap; word-break: break-word; }
  button.more { margin-top: 8px; }
</style>
</head>
<body>
<div id="app"><p class="meta">Waiting for results…</p></div>
<script>
(function () {
  "use strict";
  var nextId = 1;
  var pending = {};
  var state = { tool: null, args: {}, result: null, sevFilter: {}, text: "" };

  function send(msg) { window.parent.postMessage(msg, "*"); }
  function request(method, params) {
    var id = nextId++;
    send({ jsonrpc: "2.0", id: id, method: method, params: params });
    return new Promise(function (resolve, reject) { pending[id] = { resolve: resolve, reject: reject }; });
  }
  function notify(method, params) { send({ jsonrpc: "2.0", method: method, params: params || {} }); }

  // DOM helper: text is always set with textContent (results are untrusted)
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "text") node.textContent = attrs[k];
      else if (k === "onclick") node.addEventListener("click", attrs[k]);
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c != null) node.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return node;
  }
  function link(text, url) {
    if (!url || url.indexOf("https://") !== 0) return document.createTextNode(text || "");
    return el("a", { text: text || url, title: url, onclick: function (e) {
      e.preventDefault();
      request("ui/open-link", { url: url }).catch(function () { window.open(url, "_blank", "noopener"); });
    } });
  }
  function list(v) { return Array.isArray(v) ? v.join(", ") : (v == null ? "" : String(v)); }
  function bugUrl(id) { return "https://bst.cloudapps.cisco.com/bugsearch/bug/" + encodeURIComponent(id); }

  function table(headers, rows) {
    var thead = el("thead", null, [el("tr", null, headers.map(function (h) { return el("th", { text: h }); }))]);
    var tbody = el("tbody", null, rows.map(function (r) {
      return el("tr", null, r.map(function (c) { return el("td", null, [c == null ? "" : c]); }));
    }));
    return el("table", null, [thead, tbody]);
  }

  function severityBar(items, key, labels) {
    var present = {};
    items.forEach(function (i) { if (i[key] != null) present[i[key]] = true; });
    var values = Object.keys(present).sort();
    if (values.length < 2) return null;
    var bar = el("div", { class: "bar" }, [el("span", { class: "small", text: "Filter:" })]);
    values.forEach(function (v) {
      bar.appendChild(el("button", { class: "chip", "aria-pressed": state.sevFilter[v] ? "true" : "false",
        text: labels ? labels(v) : v, onclick: function () { state.sevFilter[v] = !state.sevFilter[v]; render(); } }));
    });
    return bar;
  }
  function searchBox() {
    var input = el("input", { type: "search", placeholder: "Filter text…", value: state.text });
    input.addEventListener("input", function () { state.text = input.value; render(); input.focus(); });
    return input;
  }
  function keep(item, key) {
    var on = Object.keys(state.sevFilter).filter(function (k) { return state.sevFilter[k]; });
    if (on.length && on.indexOf(String(item[key])) < 0) return false;
    if (state.text && JSON.stringify(item).toLowerCase().indexOf(state.text.toLowerCase()) < 0) return false;
    return true;
  }
  function pagingLine(data, shown) {
    var p = data.paging;
    var text = "Showing " + shown + (p && p.total_records != null ? " of " + p.total_records : "") +
      (p && p.last_page ? " (page " + p.page + " of " + p.last_page + ")" : "");
    return el("p", { class: "meta", text: text });
  }
  function moreButton(data) {
    if (!data.paging || !data.paging.next_page || !state.tool) return null;
    return el("button", { class: "chip more", text: "Load page " + data.paging.next_page, onclick: function () {
      var args = Object.assign({}, state.args, { page: data.paging.next_page });
      request("tools/call", { name: state.tool, arguments: args }).then(function (r) {
        if (r && r.structuredContent) { state.args = args; state.result = r.structuredContent; render(); }
      });
    } });
  }

  function bugTable(bugs) {
    return table(["Bug", "Sev", "Status", "Headline", "Fixed in"], bugs.map(function (b) {
      return [link(b.bug_id, b.url || bugUrl(b.bug_id)), el("span", { class: "sev sev-" + b.severity, text: b.severity }),
        b.status || "", b.headline || "", list(b.fixed_releases)];
    }));
  }
  function advisoryTable(advs) {
    return table(["Advisory", "SIR", "CVSS", "CVEs", "First fixed", "Published"], advs.map(function (a) {
      return [link(a.title || a.advisory_id, a.url), el("span", { class: "sev sir-" + a.sir, text: a.sir || "" }),
        a.cvss_base_score || "", list(a.cves), list(a.first_fixed), (a.first_published || "").slice(0, 10)];
    }));
  }

  function renderBugs(root, data) {
    var bugs = data.bugs || [];
    root.appendChild(el("div", { class: "bar" }, [searchBox()]));
    var bar = severityBar(bugs, "severity", function (v) { return "Sev " + v; });
    if (bar) root.appendChild(bar);
    var shown = bugs.filter(function (b) { return keep(b, "severity"); });
    root.appendChild(pagingLine(data, shown.length));
    root.appendChild(bugTable(shown));
    var more = moreButton(data); if (more) root.appendChild(more);
  }
  function renderAdvisories(root, data) {
    var advs = data.advisories || [];
    root.appendChild(el("div", { class: "bar" }, [searchBox()]));
    var bar = severityBar(advs, "sir");
    if (bar) root.appendChild(bar);
    var shown = advs.filter(function (a) { return keep(a, "sir"); });
    root.appendChild(pagingLine(data, shown.length));
    root.appendChild(advisoryTable(shown));
    var more = moreButton(data); if (more) root.appendChild(more);
  }
  function renderDevices(root, data) {
    var rows = (data.devices || []).map(function (d) {
      var c = d.coverage || {}, p = d.product || {}, x = d.eox || {};
      return [d.serial_number, p.product_id || c.orderable_pid || "", p.name || "",
        c.is_covered === true ? el("span", { class: "yes", text: "Yes" }) : c.is_covered === false ? el("span", { class: "no", text: "No" }) : "",
        c.coverage_end_date || "", c.warranty_end_date || "", c.service_contract_number || "",
        x.eox_announced ? (x.last_date_of_support || "announced") : (x.eox_announced === false ? "none" : "")];
    });
    root.appendChild(table(["Serial", "Product", "Name", "Contract", "Coverage end", "Warranty end", "Contract #", "Last support"], rows));
  }
  function renderUpgrade(root, data) {
    var s = data.summary || {};
    root.appendChild(el("p", { class: "meta", text: data.product_id + ": " + data.current_version + " → " + data.target_version }));
    var cards = el("div", { class: "cards" });
    [["Open bugs now", s.open_bugs_current], ["Fixed by target", s.fixed_by_target], ["Open bugs on target", s.open_bugs_target],
     ["Advisories fixed", s.advisories_fixed_by_upgrade], ["New advisories", s.advisories_new_in_target],
     ["Last date of support", s.last_date_of_support]].forEach(function (c) {
      if (c[1] != null) cards.appendChild(el("div", { class: "card" }, [el("b", { text: String(c[1]) }), el("span", { text: c[0] })]));
    });
    root.appendChild(cards);
    function section(title, items, render) {
      if (!items || !items.length) return;
      root.appendChild(el("h2", { text: title + " (" + items.length + ")" }));
      root.appendChild(render(items));
    }
    section("Bugs fixed by the target", data.bugs_fixed_by_target, bugTable);
    section("Bugs still open after upgrade", data.bugs_still_open, bugTable);
    section("Bugs affecting the target", data.bugs_affecting_target, bugTable);
    if (data.security) {
      section("Advisories fixed by upgrading", data.security.fixed_by_upgrade, advisoryTable);
      section("Advisories still affecting the target", data.security.still_affected_after_upgrade, advisoryTable);
      section("Advisories new in the target", data.security.new_in_target, advisoryTable);
    }
    (data.notes || []).forEach(function (n) { root.appendChild(el("p", { class: "small", text: n })); });
    if (data.caveat) root.appendChild(el("p", { class: "small", text: data.caveat }));
  }

  function render() {
    var root = document.getElementById("app");
    root.textContent = "";
    var data = state.result;
    if (!data) { root.appendChild(el("p", { class: "meta", text: "No structured result." })); return; }
    if (data.hint) root.appendChild(el("p", { class: "meta", text: data.hint }));
    if (data.target_version && data.summary) renderUpgrade(root, data);
    else if (data.devices) renderDevices(root, data);
    else if (data.advisories) renderAdvisories(root, data);
    else if (data.bugs) renderBugs(root, data);
    else root.appendChild(el("pre", { text: JSON.stringify(data, null, 2) }));
    reportSize();
  }

  function reportSize() {
    notify("ui/notifications/size-changed", { height: document.documentElement.scrollHeight });
  }
  function applyContext(ctx) {
    if (!ctx) return;
    if (ctx.theme) document.documentElement.setAttribute("data-theme", ctx.theme);
    var vars = ctx.styles && ctx.styles.variables;
    if (vars) Object.keys(vars).forEach(function (k) { if (vars[k]) document.documentElement.style.setProperty(k, vars[k]); });
    var tool = ctx.toolInfo && ctx.toolInfo.tool && ctx.toolInfo.tool.name;
    if (tool) state.tool = tool;
  }

  window.addEventListener("message", function (event) {
    if (event.source !== window.parent) return;
    var msg = event.data;
    if (!msg || msg.jsonrpc !== "2.0") return;
    if (msg.id != null && (msg.result !== undefined || msg.error !== undefined) && pending[msg.id]) {
      var p = pending[msg.id]; delete pending[msg.id];
      if (msg.error) p.reject(msg.error); else p.resolve(msg.result);
      return;
    }
    switch (msg.method) {
      case "ui/notifications/tool-input":
        state.args = (msg.params && msg.params.arguments) || {};
        break;
      case "ui/notifications/tool-result":
        state.result = msg.params && msg.params.structuredContent;
        if (!state.result && msg.params && msg.params.content) {
          var text = msg.params.content.filter(function (c) { return c.type === "text"; }).map(function (c) { return c.text; }).join("\n");
          state.result = { raw: text };
        }
        render();
        break;
      case "ui/notifications/tool-cancelled":
        document.getElementById("app").textContent = "Cancelled.";
        break;
      case "ui/notifications/host-context-changed":
        applyContext(msg.params);
        break;
      case "ui/resource-teardown":
        if (msg.id != null) send({ jsonrpc: "2.0", id: msg.id, result: {} });
        break;
      case "ping":
        if (msg.id != null) send({ jsonrpc: "2.0", id: msg.id, result: {} });
        break;
    }
  });

  request("ui/initialize", {
    protocolVersion: "2026-01-26",
    appInfo: { name: "mcp-cisco-support-results", version: "3.0.0" },
    appCapabilities: {}
  }).then(function (result) {
    applyContext(result && result.hostContext);
    notify("ui/notifications/initialized", {});
  }).catch(function () {
    notify("ui/notifications/initialized", {});
  });

  if (window.ResizeObserver) new ResizeObserver(reportSize).observe(document.body);
})();
</script>
</body>
</html>`;
