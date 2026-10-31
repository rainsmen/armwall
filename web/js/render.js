// ArmWall web UI: rendering of state, nodes, subscriptions, routing and strategies.

function pruneNodeTests() {
  const ids = new Set((appState.nodes || []).map((node) => node.id));
  for (const id of nodeTests.keys()) {
    if (!ids.has(id)) nodeTests.delete(id);
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
      let delay = "-";
      if (result) {
        if (result.error) {
          delay = `<span class="pill red" title="${escapeHTML(result.message || "测试超时或失败")}">失败</span>`;
        } else if (measured !== null) {
          const color = measured < 150 ? "green" : measured < 350 ? "yellow" : "red";
          const methodLabel = result.method ? result.method.toUpperCase() + ": " : "";
          delay = `<span class="pill ${color}">${methodLabel}${measured}ms</span>`;
        }
      }
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
      <td class="delay">${delay}</td>
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
            { selector: "Selector", urltest: "URLTest" }[group.type] ||
            group.type;
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
