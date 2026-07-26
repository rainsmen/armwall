const $ = (id) => document.getElementById(id);

let token = localStorage.armwallToken || "";
let appState = { nodes: [], subscriptions: [] };
const nodeTests = new Map();
const strategyRuntime = new Map();
let selectedCore = "sing-box";
let toastTimer;

const sites = [
  ["google", "Google", "https://www.google.com/favicon.ico", "G"],
  ["youtube", "YouTube", "https://www.youtube.com/favicon.ico", "Y"],
  ["github", "GitHub", "https://github.com/favicon.ico", "GH"],
  ["facebook", "Facebook", "https://www.facebook.com/favicon.ico", "f"],
  ["baidu", "百度", "https://www.baidu.com/favicon.ico", "百"],
  ["qq", "腾讯", "https://www.qq.com/favicon.ico", "腾"],
  ["bilibili", "哔哩哔哩", "https://www.bilibili.com/favicon.ico", "B"],
  ["microsoft", "Microsoft", "https://www.microsoft.com/favicon.ico", "M"],
];

function toast(message, error = false) {
  const box = $("toast");
  box.textContent = message;
  box.style.background = error ? "#a94343" : "#172335";
  box.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => box.classList.remove("show"), 3200);
}

async function request(path, options = {}, text = false, retry = true) {
  const headers = new Headers(options.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (
    options.body &&
    typeof options.body !== "string" &&
    !(options.body instanceof FormData)
  ) {
    headers.set("Content-Type", "application/json");
    options.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401 && retry) {
    token = window.prompt("请输入 ArmWall 管理 Token") || "";
    localStorage.armwallToken = token;
    return request(path, options, text, false);
  }
  if (!response.ok) {
    const message =
      (await response.text()).trim() || `请求失败 (${response.status})`;
    throw new Error(message);
  }
  if (text) return response.text();
  const type = response.headers.get("content-type") || "";
  return type.includes("application/json") ? response.json() : response.text();
}

function escapeHTML(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[char],
  );
}

function delayValue(data) {
  const values = [
    data?.ms,
    data?.delay,
    data?.latency,
    data?.data?.ms,
    data?.data?.delay,
    data?.data?.latency,
  ];
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number) && number >= 0) return Math.round(number);
  }
  return null;
}

function modeName(mode) {
  return (
    { bypass_cn: "绕过国内", gfw: "GFW 模式", global: "全局代理" }[mode] ||
    mode ||
    "-"
  );
}

function formatDate(value) {
  if (!value || String(value).startsWith("0001-")) return "从未更新";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "从未更新";
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(date);
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function downloadText(data, filename, type = "application/json") {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function subscriptionMap() {
  return new Map((appState.subscriptions || []).map((sub) => [sub.id, sub]));
}

async function loadState(showErrors = true) {
  try {
    appState = await request("/api/state");
    appState.nodes ||= [];
    appState.subscriptions ||= [];
    renderState();
    $("connectionText").textContent = "已连接";
    document.querySelector(".top-status").classList.add("ready");
    await refreshServiceStatus(false);
  } catch (error) {
    $("connectionText").textContent = "连接失败";
    document.querySelector(".top-status").classList.remove("ready");
    if (showErrors) toast(error.message, true);
  }
}

function renderState() {
  $("nodeMetric").textContent = appState.nodes.length;
  $("modeMetric").textContent = modeName(appState.mode);
  $("routeMode").value = appState.mode || "bypass_cn";
  $("proxyPort").value = appState.proxy_port || 11080;
  $("proxyEndpoint").textContent =
    `mixed SOCKS5 / HTTP · ${appState.proxy_port || 11080}`;
  $("logLevel").value = appState.log_level || "info";
  renderNodeSelector();
  renderNodeFilters();
  renderNodes();
  renderSubscriptions();
  renderRouting();
}

function renderNodeSelector() {
  const select = $("activeNode");
  const enabled = appState.nodes.filter((node) => node.enabled);
  select.innerHTML = enabled
    .map(
      (node) =>
        `<option value="${escapeHTML(node.id)}" ${node.id === appState.selected_node ? "selected" : ""}>${escapeHTML(node.name || "未命名")} [${escapeHTML(node.type)}]</option>`,
    )
    .join("");
  select.disabled = enabled.length === 0;
}

function renderNodeFilters() {
  const select = $("nodeGroupFilter");
  const current = select.value;
  const groups = [
    ...new Set(appState.nodes.map((node) => node.group || "未分组")),
  ].sort();
  select.innerHTML =
    '<option value="">全部分组</option>' +
    groups
      .map(
        (group) =>
          `<option value="${escapeHTML(group)}">${escapeHTML(group)}</option>`,
      )
      .join("");
  if (groups.includes(current)) select.value = current;
}

function filteredNodes() {
  const keyword = $("nodeSearch").value.trim().toLowerCase();
  const group = $("nodeGroupFilter").value;
  const status = $("nodeStatusFilter").value;
  return appState.nodes.filter((node) => {
    const haystack =
      `${node.name || ""} ${node.server || ""} ${node.type || ""}`.toLowerCase();
    if (keyword && !haystack.includes(keyword)) return false;
    if (group && (node.group || "未分组") !== group) return false;
    if (status === "enabled" && !node.enabled) return false;
    if (status === "disabled" && node.enabled) return false;
    return true;
  });
}

function renderNodes() {
  const nodes = filteredNodes();
  const subs = subscriptionMap();
  $("nodesTable").innerHTML = nodes
    .map((node) => {
      const source = subs.get(node.subscription_id);
      const group = node.group || "未分组";
      const result = nodeTests.get(node.id);
      const measured = result && !result.error ? delayValue(result) : null;
      const delay = result
        ? result.error
          ? "失败"
          : measured === null
            ? "-"
            : `${measured}ms`
        : "-";
      const selected =
        node.id === appState.selected_node
          ? '<span class="pill green">当前</span>'
          : "";
      return `<tr data-node-id="${escapeHTML(node.id)}">
      <td><input class="node-check" type="checkbox" value="${escapeHTML(node.id)}" aria-label="选择 ${escapeHTML(node.name || "节点")}"></td>
      <td><div class="node-title">${escapeHTML(node.name || "未命名")} ${selected}</div><div class="node-server">${escapeHTML(node.id)}</div></td>
      <td><span class="pill">${escapeHTML(node.type || "-")}</span></td>
      <td><div>${escapeHTML(group)}</div><div class="node-server">${escapeHTML(source?.name || "手动节点")}</div></td>
      <td><div>${escapeHTML(node.server || "-")}</div><div class="node-server">端口 ${escapeHTML(node.port || "-")}</div></td>
      <td><button class="small-btn" data-action="toggle-node" data-id="${escapeHTML(node.id)}">${node.enabled ? "已启用" : "已停用"}</button></td>
      <td class="delay">${escapeHTML(delay)}</td>
      <td><div class="row-actions"><button class="small-btn" data-action="test-node" data-method="ping" data-id="${escapeHTML(node.id)}">Ping</button><button class="small-btn" data-action="test-node" data-method="tcp" data-id="${escapeHTML(node.id)}">TCP</button><button class="small-btn" data-action="test-node" data-method="urltest" data-id="${escapeHTML(node.id)}">URLTest</button><button class="small-btn" data-action="edit-node" data-id="${escapeHTML(node.id)}">编辑</button><button class="small-btn" data-action="copy-node" data-id="${escapeHTML(node.id)}">复制</button><button class="small-btn" data-action="move-node" data-direction="-1" data-id="${escapeHTML(node.id)}">上移</button><button class="small-btn" data-action="move-node" data-direction="1" data-id="${escapeHTML(node.id)}">下移</button><button class="small-btn danger" data-action="delete-node" data-id="${escapeHTML(node.id)}">删除</button></div></td>
    </tr>`;
    })
    .join("");
  $("nodeEmpty").hidden = nodes.length > 0;
  $("selectAllNodes").checked = false;
}

function renderSubscriptions() {
  const subscriptions = appState.subscriptions || [];
  $("subscriptionsTable").innerHTML = subscriptions
    .map((sub) => {
      const count = appState.nodes.filter(
        (node) => node.subscription_id === sub.id,
      ).length;
      return `<tr><td><div class="node-title">${escapeHTML(sub.name || "未命名订阅")}</div><div class="node-server">${escapeHTML(sub.id)}</div></td><td title="${escapeHTML(sub.url)}">${escapeHTML(sub.url)}</td><td><button class="small-btn" data-action="toggle-subscription" data-id="${escapeHTML(sub.id)}">${sub.enabled ? "已启用" : "已停用"}</button></td><td>${escapeHTML(sub.update_hours || 6)} 小时</td><td>${escapeHTML(formatDate(sub.last_updated))}</td><td>${count}</td><td><div class="row-actions"><button class="small-btn" data-action="update-subscription" data-id="${escapeHTML(sub.id)}">更新</button><button class="small-btn" data-action="edit-subscription" data-id="${escapeHTML(sub.id)}">编辑</button><button class="small-btn danger" data-action="delete-subscription" data-id="${escapeHTML(sub.id)}">删除</button></div></td></tr>`;
    })
    .join("");
  $("subscriptionEmpty").hidden = subscriptions.length > 0;
}

function outboundOptionList(includeSame = false) {
  const options = [];
  if (includeSame) options.push(["same", "跟随 TCP"]);
  else options.push(["", "当前运行节点"]);
  options.push(["direct", "直连"]);
  for (const group of appState.strategy_groups || [])
    options.push([group.id, `策略：${group.name}`]);
  for (const node of appState.nodes.filter((item) => item.enabled))
    options.push([node.id, `节点：${node.name || "未命名"}`]);
  return options;
}

function fillOutboundSelect(select, options, selected) {
  select.innerHTML = options
    .map(
      ([value, label]) =>
        `<option value="${escapeHTML(value)}" ${value === selected ? "selected" : ""}>${escapeHTML(label)}</option>`,
    )
    .join("");
  if (![...select.options].some((option) => option.value === selected))
    select.value = options[0]?.[0] || "";
}

function renderRouting() {
  appState.strategy_groups ||= [];
  appState.acl_rules ||= [];
  fillOutboundSelect(
    $("tcpOutbound"),
    outboundOptionList(false),
    appState.tcp_outbound || "",
  );
  fillOutboundSelect(
    $("udpOutbound"),
    outboundOptionList(true),
    appState.udp_outbound || "same",
  );
  renderStrategies();
  renderRoutingSettings();
  void loadStrategyStatus();
}

function renderStrategies() {
  const names = new Map(
    appState.nodes.map((node) => [node.id, node.name || "未命名"]),
  );
  $("strategyManager").innerHTML = appState.strategy_groups.length
    ? appState.strategy_groups
        .map((group) => {
          const members = (group.node_ids || [])
            .map((id) => names.get(id) || id)
            .join("、");
          const type =
            { selector: "Selector", urltest: "URLTest", fallback: "Fallback" }[
              group.type
            ] || group.type;
          const runtime = strategyRuntime.get(group.id);
          const selected = runtime?.selected || group.selected || "";
          const currentName = names.get(selected) || selected || "-";
          const delay =
            Number(runtime?.delay_ms) > 0 ? ` · ${runtime.delay_ms}ms` : "";
          const status = runtime?.available
            ? `当前：${currentName}${delay}`
            : "运行状态不可用";
          const selector =
            group.type === "selector"
              ? `<select class="strategy-runtime-select">${(group.node_ids || []).map((id) => `<option value="${escapeHTML(id)}" ${id === selected ? "selected" : ""}>${escapeHTML(names.get(id) || id)}</option>`).join("")}</select>`
              : "";
          const switchButton =
            group.type === "selector"
              ? `<button class="small-btn" data-action="select-strategy-member" data-id="${escapeHTML(group.id)}">切换</button>`
              : "";
          return `<div class="strategy-row" data-strategy-id="${escapeHTML(group.id)}"><div><strong>${escapeHTML(group.name)}</strong><div class="node-server">${escapeHTML(group.id)}</div></div><span class="pill">${escapeHTML(type)}</span><div class="strategy-detail"><div class="muted">${escapeHTML(members || "无可用节点")}</div><div class="strategy-status">${escapeHTML(status)}</div>${selector}</div><div class="row-actions"><button class="small-btn" data-action="test-strategy" data-id="${escapeHTML(group.id)}">测速</button>${switchButton}<button class="small-btn" data-action="edit-strategy" data-id="${escapeHTML(group.id)}">编辑</button><button class="small-btn danger" data-action="delete-strategy" data-id="${escapeHTML(group.id)}">删除</button></div></div>`;
        })
        .join("")
    : '<div class="empty">尚未创建策略组</div>';
}

async function loadStrategyStatus() {
  if (!(appState.strategy_groups || []).length) return;
  try {
    const data = await request("/api/strategy/status");
    strategyRuntime.clear();
    for (const group of data.groups || []) strategyRuntime.set(group.id, group);
    renderStrategies();
  } catch {
    strategyRuntime.clear();
    renderStrategies();
  }
}

function renderRoutingSettings() {
  const dns = appState.dns || {};
  $("dnsMode").value = !dns.enabled
    ? "disabled"
    : dns.fake_ip
      ? "fakeip"
      : "remote";
  $("dnsListen").value =
    dns.listen_address ||
    (/^\d{1,3}(\.\d{1,3}){3}$/.test(location.hostname)
      ? location.hostname
      : "");
  $("dnsPort").value = dns.listen_port || 53;
  $("dnsRemote").value = dns.remote_server || "https://1.1.1.1/dns-query";
  $("dnsSNI").value = dns.remote_sni || "cloudflare-dns.com";
  $("dnsDirect").value = dns.direct_server || "udp://223.5.5.5";
  $("dnsStrategy").value = dns.strategy || "prefer_ipv4";
  $("dnsHijack").checked = dns.enabled ? Boolean(dns.hijack) : true;
  updateDNSFields();
  const outboundNames = new Map([
    ["direct", "直连"],
    ["block", "阻止"],
  ]);
  for (const group of appState.strategy_groups)
    outboundNames.set(group.id, `策略：${group.name}`);
  for (const node of appState.nodes)
    outboundNames.set(node.id, `节点：${node.name || "未命名"}`);
  $("aclManager").innerHTML = appState.acl_rules.length
    ? appState.acl_rules
        .map((rule) => {
          const sources = [
            ...(rule.source_cidrs || []),
            ...(rule.source_macs || []),
          ].join("、");
          const match = [
            rule.network ? rule.network.toUpperCase() : "TCP+UDP",
            ...(rule.port_ranges || []).map((port) => `端口 ${port}`),
          ].join(" / ");
          return `<div class="acl-row"><div><strong>${escapeHTML(rule.name)}</strong><div class="node-server">${escapeHTML(rule.id)}</div></div><div class="muted">${escapeHTML(sources)}</div><button class="small-btn" data-action="toggle-acl" data-id="${escapeHTML(rule.id)}">${rule.enabled ? "已启用" : "已停用"}</button><div><div>${escapeHTML(outboundNames.get(rule.outbound) || rule.outbound)}</div><div class="node-server">${escapeHTML(match)}</div></div><div class="row-actions"><button class="small-btn" data-action="edit-acl" data-id="${escapeHTML(rule.id)}">编辑</button><button class="small-btn danger" data-action="delete-acl" data-id="${escapeHTML(rule.id)}">删除</button></div></div>`;
        })
        .join("")
    : '<div class="empty">尚未添加访问控制规则</div>';
}

function updateDNSFields() {
  const disabled = $("dnsMode").value === "disabled";
  $("dnsSettings")
    .querySelectorAll("input,select")
    .forEach((control) => {
      control.disabled = disabled;
    });
}

function splitList(value) {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function renderSites() {
  $("siteGrid").innerHTML = sites
    .map(
      ([id, name, icon, fallback]) =>
        `<button class="site-card" type="button" data-action="test-site" data-site="${id}"><span class="site-visual"><img src="${icon}" alt="${name} logo" data-fallback="${fallback}"></span><span class="site-name">${name}</span><span class="test-result" aria-live="polite">点击测试</span></button>`,
    )
    .join("");
  document.querySelectorAll(".site-card img").forEach((image) => {
    image.addEventListener(
      "error",
      () => {
        const fallback = document.createElement("span");
        fallback.className = "site-fallback";
        fallback.textContent = image.dataset.fallback;
        image.replaceWith(fallback);
      },
      { once: true },
    );
  });
}

function selectedNodeIDs() {
  return [...document.querySelectorAll(".node-check:checked")].map(
    (input) => input.value,
  );
}

function nodeByID(id) {
  return appState.nodes.find((node) => node.id === id);
}

function updateNodeFields() {
  const protocol = $("nodeType").value;
  document.querySelectorAll("#nodeForm [data-protocols]").forEach((field) => {
    field.hidden = !field.dataset.protocols.split(/\s+/).includes(protocol);
  });
}

function openNodeEditor(node = null) {
  $("nodeEditor").hidden = false;
  $("linkImporter").hidden = true;
  $("nodeEditorTitle").textContent = node ? "编辑节点" : "添加节点";
  $("nodeId").value = node?.id || "";
  $("nodeName").value = node?.name || "";
  $("nodeType").value = node?.type || "vless";
  $("nodeGroup").value = node?.group || (node ? "" : "手动节点");
  $("nodeServer").value = node?.server || "";
  $("nodePort").value = node?.port || 443;
  $("nodeUsername").value = node?.username || "";
  $("nodeUUID").value = node?.uuid || "";
  $("nodePassword").value = node?.password || "";
  $("nodeSNI").value = node?.server_name || "";
  $("nodeHost").value = node?.host || "";
  $("nodePath").value = node?.path || "";
  $("nodeServiceName").value = node?.service_name || "";
  $("nodeTransport").value = node?.transport || "";
  $("nodeALPN").value = node?.alpn || "";
  $("nodeFlow").value = node?.flow || "";
  $("nodeMethod").value = node?.method || "";
  $("nodeSecurity").value = node?.security || "auto";
  $("nodeAlterID").value = node?.alter_id || 0;
  $("nodePlugin").value = node?.plugin || "";
  $("nodePluginOpts").value = node?.plugin_opts || "";
  $("nodeRealityPublicKey").value = node?.reality_public_key || "";
  $("nodeRealityShortID").value = node?.reality_short_id || "";
  $("nodeObfs").value = node?.obfs || "";
  $("nodeObfsPassword").value = node?.obfs_password || "";
  $("nodeUpMbps").value = node?.up_mbps || 0;
  $("nodeDownMbps").value = node?.down_mbps || 0;
  $("nodeFingerprint").value = node?.fingerprint || "";
  $("nodeTLS").checked = node ? Boolean(node.tls) : true;
  $("nodeInsecure").checked = Boolean(node?.insecure);
  $("nodeEnabled").checked = node ? Boolean(node.enabled) : true;
  updateNodeFields();
  $("nodeEditor").scrollIntoView({ behavior: "smooth", block: "start" });
}

function closeNodeEditor() {
  $("nodeEditor").hidden = true;
  $("nodeForm").reset();
}

function nodePayload() {
  return {
    id: $("nodeId").value,
    name: $("nodeName").value.trim(),
    type: $("nodeType").value,
    group: $("nodeGroup").value.trim(),
    server: $("nodeServer").value.trim(),
    port: Number($("nodePort").value),
    username: $("nodeUsername").value,
    uuid: $("nodeUUID").value,
    password: $("nodePassword").value,
    server_name: $("nodeSNI").value.trim(),
    host: $("nodeHost").value.trim(),
    path: $("nodePath").value,
    service_name: $("nodeServiceName").value.trim(),
    transport: $("nodeTransport").value.trim(),
    alpn: $("nodeALPN").value.trim(),
    flow: $("nodeFlow").value.trim(),
    method: $("nodeMethod").value.trim(),
    security: $("nodeSecurity").value.trim(),
    alter_id: Number($("nodeAlterID").value) || 0,
    plugin: $("nodePlugin").value.trim(),
    plugin_opts: $("nodePluginOpts").value.trim(),
    reality_public_key: $("nodeRealityPublicKey").value.trim(),
    reality_short_id: $("nodeRealityShortID").value.trim(),
    obfs: $("nodeObfs").value.trim(),
    obfs_password: $("nodeObfsPassword").value,
    up_mbps: Number($("nodeUpMbps").value) || 0,
    down_mbps: Number($("nodeDownMbps").value) || 0,
    fingerprint: $("nodeFingerprint").value.trim(),
    tls: $("nodeTLS").checked,
    insecure: $("nodeInsecure").checked,
    enabled: $("nodeEnabled").checked,
  };
}

async function saveNode(event) {
  event.preventDefault();
  const payload = nodePayload();
  const updating = Boolean(payload.id);
  if (!updating) delete payload.id;
  try {
    await request(updating ? "/api/node/update" : "/api/node", {
      method: "POST",
      body: payload,
    });
    toast(updating ? "节点已更新" : "节点已添加");
    closeNodeEditor();
    await loadState(false);
  } catch (error) {
    toast(error.message, true);
  }
}

function openSubscriptionEditor(sub = null) {
  $("subscriptionEditor").hidden = false;
  $("subscriptionEditorTitle").textContent = sub ? "编辑订阅" : "添加订阅";
  $("subscriptionId").value = sub?.id || "";
  $("subscriptionName").value = sub?.name || "";
  $("subscriptionURL").value = sub?.url || "";
  $("subscriptionHours").value = sub?.update_hours || 6;
  $("subscriptionEnabled").checked = sub ? Boolean(sub.enabled) : true;
  $("subscriptionEditor").scrollIntoView({
    behavior: "smooth",
    block: "start",
  });
}

function closeSubscriptionEditor() {
  $("subscriptionEditor").hidden = true;
  $("subscriptionForm").reset();
}

async function saveSubscription(event) {
  event.preventDefault();
  const id = $("subscriptionId").value;
  const existing = appState.subscriptions.find((sub) => sub.id === id);
  const payload = {
    id,
    name: $("subscriptionName").value.trim(),
    url: $("subscriptionURL").value.trim(),
    update_hours: Number($("subscriptionHours").value),
    enabled: $("subscriptionEnabled").checked,
    last_updated: existing?.last_updated,
  };
  try {
    await request(id ? "/api/subscription/edit" : "/api/subscription", {
      method: "POST",
      body: payload,
    });
    toast(id ? "订阅已保存" : "订阅已添加并导入");
    closeSubscriptionEditor();
    await loadState(false);
  } catch (error) {
    toast(error.message, true);
  }
}

function refreshStrategySelected(preferred = "") {
  const checked = [...document.querySelectorAll(".strategy-member:checked")];
  const select = $("strategySelected");
  const current = preferred || select.value;
  select.innerHTML = checked
    .map(
      (input) =>
        `<option value="${escapeHTML(input.value)}">${escapeHTML(input.dataset.name)}</option>`,
    )
    .join("");
  if (checked.some((input) => input.value === current)) select.value = current;
}

function openStrategyEditor(group = null) {
  $("strategyEditor").hidden = false;
  $("strategyEditorTitle").textContent = group ? "编辑策略组" : "新建策略组";
  $("strategyId").value = group?.id || "";
  $("strategyName").value = group?.name || "";
  $("strategyType").value = group?.type || "selector";
  $("strategyURL").value =
    group?.test_url || "https://www.gstatic.com/generate_204";
  $("strategyInterval").value = group?.interval_sec || 180;
  $("strategyTolerance").value = group?.tolerance_ms ?? 50;
  const selected = new Set(group?.node_ids || []);
  $("strategyMembers").innerHTML = appState.nodes
    .filter((node) => node.enabled)
    .map(
      (node) =>
        `<label class="member-option"><input class="strategy-member" type="checkbox" value="${escapeHTML(node.id)}" data-name="${escapeHTML(node.name || "未命名")}" ${selected.has(node.id) ? "checked" : ""}><span>${escapeHTML(node.name || "未命名")} <span class="muted">[${escapeHTML(node.type)}]</span></span></label>`,
    )
    .join("");
  refreshStrategySelected(group?.selected || "");
  $("strategyEditor").scrollIntoView({ behavior: "smooth", block: "start" });
}

function closeStrategyEditor() {
  $("strategyEditor").hidden = true;
  $("strategyForm").reset();
}

async function saveStrategy(event) {
  event.preventDefault();
  const nodeIDs = [
    ...document.querySelectorAll(".strategy-member:checked"),
  ].map((input) => input.value);
  const payload = {
    id: $("strategyId").value,
    name: $("strategyName").value.trim(),
    type: $("strategyType").value,
    node_ids: nodeIDs,
    selected: $("strategySelected").value,
    test_url: $("strategyURL").value.trim(),
    interval_sec: Number($("strategyInterval").value),
    tolerance_ms: Number($("strategyTolerance").value),
  };
  if (!payload.id) delete payload.id;
  try {
    await request("/api/strategy", { method: "POST", body: payload });
    toast("策略组已保存");
    closeStrategyEditor();
    await loadState(false);
  } catch (error) {
    toast(error.message, true);
  }
}

function aclOutboundOptions() {
  const options = [
    ["direct", "直连"],
    ["block", "阻止"],
  ];
  for (const group of appState.strategy_groups || [])
    options.push([group.id, `策略：${group.name}`]);
  for (const node of appState.nodes.filter((item) => item.enabled))
    options.push([node.id, `节点：${node.name || "未命名"}`]);
  return options;
}

function openACLEditor(rule = null) {
  $("aclEditor").hidden = false;
  $("aclEditorTitle").textContent = rule ? "编辑 ACL" : "添加 ACL";
  $("aclId").value = rule?.id || "";
  $("aclName").value = rule?.name || "";
  $("aclNetwork").value = rule?.network || "";
  fillOutboundSelect(
    $("aclOutbound"),
    aclOutboundOptions(),
    rule?.outbound || "direct",
  );
  $("aclPorts").value = (rule?.port_ranges || []).join(",");
  $("aclCIDRs").value = (rule?.source_cidrs || []).join("\n");
  $("aclMACs").value = (rule?.source_macs || []).join("\n");
  $("aclEnabled").checked = rule ? Boolean(rule.enabled) : true;
  $("aclEditor").scrollIntoView({ behavior: "smooth", block: "start" });
}

function closeACLEditor() {
  $("aclEditor").hidden = true;
  $("aclForm").reset();
}

async function saveACL(event) {
  event.preventDefault();
  const payload = {
    id: $("aclId").value,
    name: $("aclName").value.trim(),
    enabled: $("aclEnabled").checked,
    source_cidrs: splitList($("aclCIDRs").value),
    source_macs: splitList($("aclMACs").value),
    network: $("aclNetwork").value,
    port_ranges: splitList($("aclPorts").value),
    outbound: $("aclOutbound").value,
  };
  if (!payload.id) delete payload.id;
  try {
    await request("/api/acl", { method: "POST", body: payload });
    toast("ACL 规则已保存");
    closeACLEditor();
    await loadState(false);
  } catch (error) {
    toast(error.message, true);
  }
}

function dnsPayload() {
  const mode = $("dnsMode").value;
  return {
    enabled: mode !== "disabled",
    listen_address: $("dnsListen").value.trim(),
    listen_port: Number($("dnsPort").value),
    remote_server: $("dnsRemote").value.trim(),
    remote_sni: $("dnsSNI").value.trim(),
    direct_server: $("dnsDirect").value.trim(),
    strategy: $("dnsStrategy").value,
    hijack: $("dnsHijack").checked,
    fake_ip: mode === "fakeip",
  };
}

async function testNode(id, method, button) {
  const old = button.textContent;
  button.disabled = true;
  button.textContent = "测试中";
  try {
    const data = await request(
      `/api/node/test?id=${encodeURIComponent(id)}&method=${encodeURIComponent(method)}`,
      { method: "POST" },
    );
    const ms = delayValue(data);
    if (ms === null) throw new Error("测速未返回延迟");
    nodeTests.set(id, { ms, method });
    renderNodes();
    toast(`${method.toUpperCase()}：${ms}ms`);
  } catch (error) {
    nodeTests.set(id, { error: true, method });
    renderNodes();
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = old;
  }
}

async function testSite(site, card) {
  const result = card.querySelector(".test-result");
  card.setAttribute("aria-busy", "true");
  card.disabled = true;
  result.classList.remove("error");
  result.textContent = "测试中...";
  try {
    const data = await request(
      `/api/network/test?target=${encodeURIComponent(site)}`,
    );
    const ms = delayValue(data);
    if (ms === null) throw new Error("未返回延迟");
    result.textContent = `${ms}ms`;
  } catch (error) {
    result.classList.add("error");
    result.textContent = "测试失败";
  } finally {
    card.removeAttribute("aria-busy");
    card.disabled = false;
  }
}

async function refreshServiceStatus(notify = true) {
  try {
    const status = (
      await request("/api/service/status", { method: "POST" }, true)
    ).trim();
    $("serviceMetric").textContent = status || "未知";
    $("serviceOutput").textContent = status || "未知";
    if (notify) toast(`代理服务：${status}`);
  } catch (error) {
    $("serviceMetric").textContent = "异常";
    if (notify) toast(error.message, true);
  }
}

async function service(action) {
  try {
    const output = await request(
      `/api/service/${action}`,
      { method: "POST" },
      true,
    );
    $("serviceOutput").textContent = output.trim() || "操作已完成";
    toast(action === "stop" ? "代理服务已停止" : "代理服务已启动");
    await refreshServiceStatus(false);
  } catch (error) {
    toast(error.message, true);
  }
}

async function renderRules() {
  try {
    const data = await request("/api/rules");
    const names = {
      "geosite-ads": "广告规则",
      "geosite-cn": "中国域名",
      "geoip-cn": "中国 IP",
      "geosite-proxy": "代理域名",
    };
    $("ruleManager").innerHTML = Object.entries(data.rules || {})
      .map(([tag, primary]) => {
        const setting = (data.settings || {})[tag] || {};
        const lastUpdated =
          setting.last_updated && !setting.last_updated.startsWith("0001-")
            ? formatDate(setting.last_updated)
            : "尚未更新";
        return `<div class="rule-row" data-rule="${escapeHTML(tag)}">
          <div class="rule-source"><strong>${escapeHTML(names[tag] || tag)}</strong><div class="node-server">${escapeHTML(primary)}</div></div>
          <label class="rule-field"><span>备用地址</span><input class="rule-backup" value="${escapeHTML(setting.backup_url || (data.backups || {})[tag] || "")}" placeholder="https://"></label>
          <label class="rule-field rule-interval"><span>更新间隔</span><span class="inline"><input class="rule-hours" type="number" min="1" max="168" value="${escapeHTML(setting.update_hours || data.update_hours || 6)}"><span>小时</span></span></label>
          <label class="rule-auto"><input type="checkbox" ${setting.auto_update ? "checked" : ""}>自动更新</label>
          <div class="rule-updated"><span>上次更新</span><strong>${escapeHTML(lastUpdated)}</strong></div>
          <div class="row-actions"><button class="small-btn" data-action="save-rule" data-tag="${escapeHTML(tag)}">保存</button><button class="small-btn" data-action="update-rule" data-tag="${escapeHTML(tag)}">立即更新</button></div>
        </div>`;
      })
      .join("");
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadBackups() {
  try {
    const backups = await request("/api/backups");
    $("backupTable").innerHTML = (backups || [])
      .map(
        (backup) => `<tr>
          <td><div class="node-title">${escapeHTML(backup.name)}</div></td>
          <td>${escapeHTML(formatDate(backup.created_at))}</td>
          <td>${escapeHTML(formatBytes(backup.size))}</td>
          <td><div class="row-actions"><button class="small-btn" data-action="download-backup" data-name="${escapeHTML(backup.name)}">下载</button><button class="small-btn" data-action="restore-backup" data-name="${escapeHTML(backup.name)}">恢复</button><button class="small-btn danger" data-action="delete-backup" data-name="${escapeHTML(backup.name)}">删除</button></div></td>
        </tr>`,
      )
      .join("");
    $("backupEmpty").hidden = Boolean((backups || []).length);
  } catch (error) {
    toast(error.message, true);
  }
}

function selectCore(core) {
  selectedCore = core;
  document
    .querySelectorAll("#coreSelector button")
    .forEach((button) =>
      button.classList.toggle("active", button.dataset.core === core),
    );
  $("coreVersion").textContent = "点击检查版本";
}

async function uploadCore(file) {
  const form = new FormData();
  form.append("core", selectedCore);
  form.append("file", file);
  $("coreVersion").textContent = "上传并校验中";
  const output = await request(
    "/api/core/upload",
    { method: "POST", body: form },
    true,
  );
  $("coreVersion").textContent = output.trim() || "更新完成";
  toast(`${selectedCore} 已更新`);
}

async function handleAction(button) {
  const { action, id, method, direction, tag, name, core } = button.dataset;
  try {
    if (action === "new-node") openNodeEditor();
    else if (action === "close-node") closeNodeEditor();
    else if (action === "import-links") {
      $("linkImporter").hidden = false;
      $("nodeEditor").hidden = true;
      $("linkImporter").scrollIntoView({ behavior: "smooth" });
    } else if (action === "close-import") $("linkImporter").hidden = true;
    else if (action === "submit-import") {
      const links = $("shareLinks").value.trim();
      if (!links) throw new Error("请输入分享链接");
      await request("/api/node/import", { method: "POST", body: { links } });
      $("shareLinks").value = "";
      $("linkImporter").hidden = true;
      toast("节点已导入");
      await loadState(false);
    } else if (action === "edit-node") openNodeEditor(nodeByID(id));
    else if (action === "copy-node") {
      await request("/api/node/copy", { method: "POST", body: { id } });
      toast("节点副本已创建");
      await loadState(false);
    } else if (action === "toggle-node") {
      const node = nodeByID(id);
      await request("/api/node/toggle", {
        method: "POST",
        body: { id, enabled: !node.enabled },
      });
      toast(node.enabled ? "节点已停用" : "节点已启用");
      await loadState(false);
    } else if (action === "delete-node") {
      if (!confirm("确认删除此节点？")) return;
      await request("/api/node/delete", { method: "POST", body: { id } });
      toast("节点已删除");
      await loadState(false);
    } else if (action === "test-node") await testNode(id, method, button);
    else if (action === "move-node") {
      const ids = appState.nodes.map((node) => node.id);
      const from = ids.indexOf(id);
      const to = from + Number(direction);
      if (from < 0 || to < 0 || to >= ids.length) return;
      [ids[from], ids[to]] = [ids[to], ids[from]];
      await request("/api/node/reorder", { method: "POST", body: { ids } });
      await loadState(false);
    } else if (action === "batch-enable" || action === "batch-disable") {
      const ids = selectedNodeIDs();
      if (!ids.length) throw new Error("请先选择节点");
      await request("/api/node/batch-toggle", {
        method: "POST",
        body: { ids, enabled: action === "batch-enable" },
      });
      toast(action === "batch-enable" ? "选中节点已启用" : "选中节点已停用");
      await loadState(false);
    } else if (action === "batch-delete") {
      const ids = selectedNodeIDs();
      if (!ids.length) throw new Error("请先选择节点");
      if (!confirm(`确认删除选中的 ${ids.length} 个节点？`)) return;
      await request("/api/node/batch-delete", {
        method: "POST",
        body: { ids },
      });
      toast("选中节点已删除");
      await loadState(false);
    } else if (action === "new-subscription") openSubscriptionEditor();
    else if (action === "close-subscription") closeSubscriptionEditor();
    else if (action === "edit-subscription")
      openSubscriptionEditor(
        appState.subscriptions.find((sub) => sub.id === id),
      );
    else if (action === "toggle-subscription") {
      const sub = appState.subscriptions.find((item) => item.id === id);
      await request("/api/subscription/toggle", {
        method: "POST",
        body: { id, enabled: !sub.enabled },
      });
      toast(sub.enabled ? "订阅自动更新已停用" : "订阅自动更新已启用");
      await loadState(false);
    } else if (action === "update-subscription") {
      button.disabled = true;
      await request("/api/subscription/update-one", {
        method: "POST",
        body: { id },
      });
      toast("订阅已更新");
      await loadState(false);
    } else if (action === "update-all-subscriptions") {
      button.disabled = true;
      await request("/api/subscription/update", { method: "POST" });
      toast("全部订阅已更新");
      await loadState(false);
    } else if (action === "delete-subscription") {
      if (!confirm("删除订阅会同时删除其节点，确认继续？")) return;
      await request("/api/subscription/delete", {
        method: "POST",
        body: { id },
      });
      toast("订阅及其节点已删除");
      await loadState(false);
    } else if (action === "new-strategy") openStrategyEditor();
    else if (action === "close-strategy") closeStrategyEditor();
    else if (action === "edit-strategy")
      openStrategyEditor(
        (appState.strategy_groups || []).find((group) => group.id === id),
      );
    else if (action === "delete-strategy") {
      if (!confirm("确认删除此策略组？")) return;
      await request("/api/strategy/delete", { method: "POST", body: { id } });
      toast("策略组已删除");
      await loadState(false);
    } else if (action === "test-strategy") {
      const data = await request("/api/strategy/test", {
        method: "POST",
        body: { id },
      });
      const current = strategyRuntime.get(id) || { id, available: true };
      current.available = true;
      current.delay_ms = delayValue(data) || 0;
      strategyRuntime.set(id, current);
      renderStrategies();
      toast(`策略组延迟：${current.delay_ms}ms`);
    } else if (action === "select-strategy-member") {
      const row = button.closest("[data-strategy-id]");
      const nodeID = row.querySelector(".strategy-runtime-select").value;
      await request("/api/strategy/select", {
        method: "POST",
        body: { id, nodeID },
      });
      toast("策略组成员已切换");
      await loadState(false);
    } else if (action === "new-acl") openACLEditor();
    else if (action === "close-acl") closeACLEditor();
    else if (action === "edit-acl")
      openACLEditor((appState.acl_rules || []).find((rule) => rule.id === id));
    else if (action === "toggle-acl") {
      const rule = (appState.acl_rules || []).find((item) => item.id === id);
      await request("/api/acl/toggle", {
        method: "POST",
        body: { id, enabled: !rule.enabled },
      });
      toast(rule.enabled ? "ACL 已停用" : "ACL 已启用");
      await loadState(false);
    } else if (action === "delete-acl") {
      if (!confirm("确认删除此 ACL 规则？")) return;
      await request("/api/acl/delete", { method: "POST", body: { id } });
      toast("ACL 已删除");
      await loadState(false);
    } else if (action === "select-node") {
      await request("/api/node/select", {
        method: "POST",
        body: { id: $("activeNode").value },
      });
      toast("运行节点已切换");
      await loadState(false);
    } else if (action === "save-port") {
      await request("/api/settings", {
        method: "POST",
        body: { proxyPort: Number($("proxyPort").value) },
      });
      toast("代理端口已应用");
      await loadState(false);
    } else if (action === "test-site")
      await testSite(button.dataset.site, button.closest(".site-card"));
    else if (action === "restart-service" || action === "start-service")
      await service("start");
    else if (action === "stop-service") await service("stop");
    else if (action === "save-routing") {
      await request("/api/routing", {
        method: "POST",
        body: {
          mode: $("routeMode").value,
          tcpOutbound: $("tcpOutbound").value,
          udpOutbound: $("udpOutbound").value,
          dns: dnsPayload(),
        },
      });
      toast("分流、DNS 与出站策略已保存");
      await loadState(false);
    } else if (action === "gateway-enable") {
      $("gatewayOut").textContent = await request(
        "/api/gateway/enable",
        {
          method: "POST",
          body: { lan: $("lanIf").value, wan: $("wanIf").value },
        },
        true,
      );
    } else if (action === "gateway-status") {
      $("gatewayOut").textContent = await request(
        "/api/gateway/status",
        {},
        true,
      );
    } else if (action === "gateway-disable") {
      $("gatewayOut").textContent = await request(
        "/api/gateway/disable",
        { method: "POST" },
        true,
      );
    } else if (action === "save-rule") {
      const row = button.closest(".rule-row");
      await request("/api/rules/settings", {
        method: "POST",
        body: {
          tag,
          backup: row.querySelector(".rule-backup").value.trim(),
          hours: Number(row.querySelector(".rule-hours").value),
          autoUpdate: row.querySelector(".rule-auto input").checked,
        },
      });
      toast("规则设置已保存");
      await renderRules();
    } else if (action === "update-rule") {
      button.disabled = true;
      await request("/api/rules/update", { method: "POST", body: { tag } });
      toast("规则已更新");
      await renderRules();
    } else if (action === "select-core") selectCore(core);
    else if (action === "core-version") {
      $("coreVersion").textContent = (
        await request(
          "/api/core/update",
          { method: "POST", body: { core: selectedCore, action: "version" } },
          true,
        )
      ).trim();
    } else if (action === "core-latest") {
      button.disabled = true;
      $("coreVersion").textContent = (
        await request(
          "/api/core/update",
          { method: "POST", body: { core: selectedCore, action: "latest" } },
          true,
        )
      ).trim();
      toast(`${selectedCore} 已更新`);
    } else if (action === "core-upload") {
      $("coreUploadFile").click();
    } else if (action === "export-config") {
      const data = await request("/api/config/export", {}, true);
      downloadText(data, "armwall-config.json");
    } else if (action === "import-config") {
      $("configImportFile").click();
    } else if (action === "create-backup") {
      await request("/api/backups/create", { method: "POST" });
      toast("配置备份已创建");
      await loadBackups();
    } else if (action === "download-backup") {
      const data = await request(
        `/api/backups/download?name=${encodeURIComponent(name)}`,
        {},
        true,
      );
      downloadText(data, name);
    } else if (action === "restore-backup") {
      if (!confirm(`确认恢复备份 ${name}？当前配置会先自动备份。`)) return;
      await request("/api/backups/restore", {
        method: "POST",
        body: { name },
      });
      toast("配置已恢复");
      await loadState(false);
      await loadBackups();
    } else if (action === "delete-backup") {
      if (!confirm(`确认删除备份 ${name}？`)) return;
      await request("/api/backups/delete", {
        method: "POST",
        body: { name },
      });
      toast("备份已删除");
      await loadBackups();
    } else if (action === "refresh-logs")
      $("logOut").textContent = await request("/api/logs", {}, true);
    else if (action === "save-log-level") {
      await request("/api/log/level", {
        method: "POST",
        body: { level: $("logLevel").value },
      });
      toast("日志级别已应用");
    } else if (action === "clear-logs") {
      if (!confirm("确认永久清空运行日志？")) return;
      await request("/api/log/clear", { method: "POST" });
      $("logOut").textContent = "";
      toast("日志已清空");
    } else if (action === "export-logs") {
      const data = await request("/api/logs?download=1", {}, true);
      const url = URL.createObjectURL(
        new Blob([data], { type: "text/plain;charset=utf-8" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = "armwall.log";
      link.click();
      URL.revokeObjectURL(url);
    }
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
}

document.querySelectorAll(".nav-item").forEach((button) =>
  button.addEventListener("click", () => {
    document
      .querySelectorAll(".nav-item")
      .forEach((item) => item.classList.toggle("active", item === button));
    document
      .querySelectorAll(".view")
      .forEach((view) =>
        view.classList.toggle("active", view.id === button.dataset.view),
      );
    if (button.dataset.view === "routing") renderRules();
    if (button.dataset.view === "system") loadBackups();
    if (button.dataset.view === "logs")
      handleAction(document.querySelector('[data-action="refresh-logs"]'));
  }),
);

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (button) handleAction(button);
});

$("nodeSearch").addEventListener("input", renderNodes);
$("nodeGroupFilter").addEventListener("change", renderNodes);
$("nodeStatusFilter").addEventListener("change", renderNodes);
$("selectAllNodes").addEventListener("change", (event) =>
  document.querySelectorAll(".node-check").forEach((checkbox) => {
    checkbox.checked = event.target.checked;
  }),
);
$("nodeForm").addEventListener("submit", saveNode);
$("nodeType").addEventListener("change", updateNodeFields);
$("subscriptionForm").addEventListener("submit", saveSubscription);
$("strategyForm").addEventListener("submit", saveStrategy);
$("strategyMembers").addEventListener("change", () =>
  refreshStrategySelected(),
);
$("aclForm").addEventListener("submit", saveACL);
$("dnsMode").addEventListener("change", updateDNSFields);
$("coreUploadFile").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  try {
    await uploadCore(file);
  } catch (error) {
    toast(error.message, true);
  } finally {
    event.target.value = "";
  }
});
$("configImportFile").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    if (!confirm("确认导入此配置？当前配置会先自动备份。")) return;
    await request("/api/config/import", { method: "POST", body: data });
    toast("配置已导入");
    await loadState(false);
    await loadBackups();
  } catch (error) {
    toast(error.message, true);
  } finally {
    event.target.value = "";
  }
});

renderSites();
loadState();
