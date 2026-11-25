// ArmWall web UI: rendering of state, nodes, subscriptions, routing and strategies.

function pruneNodeTests() {
  const ids = new Set((appState.nodes || []).map((node) => node.id));
  for (const id of nodeTests.keys()) {
    if (!ids.has(id)) nodeTests.delete(id);
  }
}

// selectedNodes keeps checkbox state across re-renders (search, filters,
// tests); batch actions only apply to selected nodes that are visible (F4).
const selectedNodes = new Set();

function pruneNodeSelection() {
  const ids = new Set((appState.nodes || []).map((node) => node.id));
  for (const id of selectedNodes) {
    if (!ids.has(id)) selectedNodes.delete(id);
  }
}

// pendingStrategySelection keeps a member chosen in a selector dropdown until
// it is switched, so status polling does not reset it (F2).
const pendingStrategySelection = new Map();

function renderState() {
  $("nodeMetric").textContent = appState.nodes.length;
  $("modeMetric").textContent = modeName(appState.mode);
  $("routeMode").value = appState.mode || "bypass_cn";
  $("proxyPort").value = appState.proxy_port || 11080;
  $("proxyEndpoint").textContent =
    `mixed SOCKS5 / HTTP · ${appState.proxy_port || 11080}`;
  $("logLevel").value = appState.log_level || "info";
  renderNodeSelector();
  renderFailover();
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

// filteredNodes returns visible nodes in stored order.
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
  const nodes = sortedForDisplay(filteredNodes());
  const subs = subscriptionMap();
  const sorted = Boolean(nodeSortMode);
  const moveTitle = sorted ? ' title="按延迟显示时不能调整顺序，请先恢复保存的顺序"' : "";
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
      const failoverActiveBackup =
        failoverRuntime?.managing &&
        failoverRuntime.active_node_id &&
        failoverRuntime.active_node_id !== failoverRuntime.primary_node_id &&
        node.id === failoverRuntime.active_node_id;
      const selected =
        node.id === appState.selected_node
          ? '<span class="pill green">当前</span>'
          : failoverActiveBackup
            ? '<span class="pill yellow">当前(备用)</span>'
            : "";
      const checked = selectedNodes.has(node.id) ? " checked" : "";
      const handle = sorted
        ? `<span class="drag-handle disabled"${moveTitle}>⋮⋮</span>`
        : '<span class="drag-handle" title="按住拖动调整顺序" aria-hidden="true">⋮⋮</span>';
      const moveDisabled = sorted ? " disabled" : "";
      return `<tr data-node-id="${escapeHTML(node.id)}">
      <td class="drag-col">${handle}</td>
      <td><input class="node-check" type="checkbox" value="${escapeHTML(node.id)}"${checked} aria-label="选择 ${escapeHTML(node.name || "节点")}"></td>
      <td><div class="node-title">${escapeHTML(node.name || "未命名")} ${selected}</div><div class="node-server">${escapeHTML(node.id)}</div></td>
      <td><span class="pill">${escapeHTML(node.type || "-")}</span></td>
      <td><div>${escapeHTML(group)}</div><div class="node-server">${escapeHTML(source?.name || "手动节点")}</div></td>
      <td><div>${escapeHTML(node.server || "-")}</div><div class="node-server">端口 ${escapeHTML(node.port || "-")}</div></td>
      <td><button class="small-btn" data-action="toggle-node" data-id="${escapeHTML(node.id)}">${node.enabled ? "已启用" : "已停用"}</button></td>
      <td class="delay">${delay}</td>
      <td><div class="row-actions"><button class="small-btn" data-action="test-node" data-method="ping" data-id="${escapeHTML(node.id)}" title="测试 Ping 平均延迟；注意境外节点可能由上游路由器代答，建议优先用 TCP 或 URLTest">Ping</button><button class="small-btn" data-action="test-node" data-method="tcp" data-id="${escapeHTML(node.id)}">TCP</button><button class="small-btn" data-action="test-node" data-method="urltest" data-id="${escapeHTML(node.id)}">URLTest</button><button class="small-btn" data-action="edit-node" data-id="${escapeHTML(node.id)}">编辑</button><button class="small-btn" data-action="copy-node" data-id="${escapeHTML(node.id)}">复制</button><button class="small-btn" data-action="move-node" data-direction="-1" data-id="${escapeHTML(node.id)}"${moveDisabled}${moveTitle}>上移</button><button class="small-btn" data-action="move-node" data-direction="1" data-id="${escapeHTML(node.id)}"${moveDisabled}${moveTitle}>下移</button><button class="small-btn danger" data-action="delete-node" data-id="${escapeHTML(node.id)}">删除</button></div></td>
    </tr>`;
    })
    .join("");
  $("nodeEmpty").hidden = nodes.length > 0;
  $("nodeSortButton").textContent = {
    "": "按延迟排序",
    asc: "延迟：低→高",
    desc: "延迟：高→低",
  }[nodeSortMode];
  syncSelectAll();
}

function syncSelectAll() {
  const boxes = [...document.querySelectorAll(".node-check")];
  const all = $("selectAllNodes");
  const count = boxes.filter((box) => box.checked).length;
  all.checked = boxes.length > 0 && count === boxes.length;
  all.indeterminate = count > 0 && count < boxes.length;
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

// outboundChoices is the single source for outbound labels and options (F11).
function outboundChoices({ block = false, allNodes = false } = {}) {
  const options = [["direct", "直连"]];
  if (block) options.push(["block", "阻止"]);
  for (const group of appState.strategy_groups || [])
    options.push([group.id, `策略：${group.name}`]);
  for (const node of appState.nodes.filter((item) => allNodes || item.enabled))
    options.push([node.id, `节点：${node.name || "未命名"}`]);
  return options;
}

function outboundOptionList(includeSame = false) {
  return [
    includeSame ? ["same", "跟随 TCP"] : ["", "当前运行节点"],
    ...outboundChoices(),
  ];
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
          const current = runtime?.selected || group.selected || "";
          const pending = pendingStrategySelection.get(group.id);
          const selected =
            pending && (group.node_ids || []).includes(pending) ? pending : current;
          const currentName = names.get(current) || current || "-";
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

async function loadStrategyStatus(background = false) {
  if (!(appState.strategy_groups || []).length) return;
  try {
    const data = await request("/api/strategy/status", { background });
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
  $("forceProxyDomains").value = (appState.force_proxy_domains || []).join(
    "\n",
  );
  updateDNSFields();
  const outboundNames = new Map(
    outboundChoices({ block: true, allNodes: true }),
  );
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

function nodeLabelByID(id) {
  if (!id) return "-";
  const node = (appState.nodes || []).find((item) => item.id === id);
  return node ? `${node.name || "未命名"} [${node.type}]` : id;
}

function renderFailover() {
  const cfg = appState.failover || {};
  $("failoverEnabled").checked = Boolean(cfg.enabled);
  $("failoverAutoFailback").checked = cfg.auto_failback !== false;
  $("failoverInterval").value = cfg.check_interval_sec || 30;
  $("failoverFailureThreshold").value = cfg.failure_threshold || 3;
  $("failoverRecoveryThreshold").value = cfg.recovery_threshold || 2;
  $("failoverTestURL").value =
    cfg.test_url || "https://www.gstatic.com/generate_204";
  const existing = new Set((appState.nodes || []).map((n) => n.id));
  failoverDraftBackups = (cfg.backup_node_ids || []).filter((id) =>
    existing.has(id),
  );
  renderFailoverBackupList();
  renderFailoverStatus();
}

function renderFailoverBackupList() {
  const enabledNodes = (appState.nodes || []).filter((n) => n.enabled);
  const chosen = new Set(failoverDraftBackups);
  const addSelect = $("failoverBackupAdd");
  const candidates = enabledNodes.filter((n) => !chosen.has(n.id));
  addSelect.innerHTML = candidates.length
    ? candidates
        .map(
          (node) =>
            `<option value="${escapeHTML(node.id)}">${escapeHTML(node.name || "未命名")} [${escapeHTML(node.type)}]</option>`,
        )
        .join("")
    : '<option value="">无更多可选节点</option>';
  addSelect.disabled = candidates.length === 0;

  const list = $("failoverBackupList");
  if (!failoverDraftBackups.length) {
    list.innerHTML =
      '<div class="empty">尚未添加备用节点（启用故障转移前请至少添加 1 个）</div>';
    return;
  }
  const byID = new Map((appState.nodes || []).map((n) => [n.id, n]));
  list.innerHTML = failoverDraftBackups
    .map((id, index) => {
      const node = byID.get(id);
      const name = node ? node.name || "未命名" : id;
      const meta = node
        ? `${node.type}${node.enabled ? "" : " · 已停用"}`
        : "节点不存在";
      const upDisabled = index === 0 ? " disabled" : "";
      const downDisabled =
        index === failoverDraftBackups.length - 1 ? " disabled" : "";
      return `<div class="failover-backup-row" data-backup-index="${index}">
        <div class="failover-backup-info">
          <span class="pill">备用 ${index + 1}</span>
          <div>
            <div class="node-title">${escapeHTML(name)}</div>
            <div class="node-server">${escapeHTML(meta)}</div>
          </div>
        </div>
        <div class="row-actions">
          <button class="small-btn" type="button" data-action="move-failover-backup" data-id="${escapeHTML(id)}" data-direction="-1"${upDisabled}>上移</button>
          <button class="small-btn" type="button" data-action="move-failover-backup" data-id="${escapeHTML(id)}" data-direction="1"${downDisabled}>下移</button>
          <button class="small-btn danger" type="button" data-action="remove-failover-backup" data-id="${escapeHTML(id)}">移除</button>
        </div>
      </div>`;
    })
    .join("");
}

function renderFailoverStatus() {
  const st = failoverRuntime;
  const badge = $("failoverBadge");
  const summary = $("failoverSummary");
  const banner = $("failoverBanner");
  const failbackBtn = $("failoverFailbackBtn");
  const eventsWrap = $("failoverEventsWrap");
  const eventsList = $("failoverEvents");

  if (!st || !st.enabled) {
    badge.className = "pill";
    badge.textContent = "未启用";
    summary.textContent = "未启用自动故障转移";
    banner.hidden = true;
    banner.innerHTML = "";
    failbackBtn.hidden = true;
    eventsWrap.hidden = true;
    return;
  }

  const badgeMap = {
    healthy: ["green", "监控正常"],
    degraded: ["yellow", "主节点异常"],
    failed_over: ["yellow", "已切至备用"],
    all_down: ["red", "全部不可用"],
    inactive: ["", "未接管"],
    stopped: ["", "服务已停止"],
    disabled: ["", "未启用"],
  };
  const [color, label] = badgeMap[st.state] || ["", st.state || "未知"];
  badge.className = color ? `pill ${color}` : "pill";
  badge.textContent = label;

  const isFailedOver =
    st.managing &&
    st.active_node_id &&
    st.primary_node_id &&
    st.active_node_id !== st.primary_node_id;
  failbackBtn.hidden = !isFailedOver;

  if (!st.managing) {
    summary.textContent = st.inactive_reason || "当前未接管默认出站";
    banner.hidden = true;
    banner.innerHTML = "";
  } else {
    const parts = [
      `原主节点：${nodeLabelByID(st.primary_node_id)}`,
      `当前生效：${nodeLabelByID(st.active_node_id)}${st.last_active_delay_ms > 0 ? ` (${st.last_active_delay_ms}ms)` : ""}`,
    ];
    if (st.consecutive_failures > 0) {
      parts.push(
        `连续失败：${st.consecutive_failures}/${st.failure_threshold || 3}`,
      );
    }
    if (isFailedOver) {
      if (st.auto_failback) {
        parts.push(
          `主节点恢复探测：${st.primary_recovery_count || 0}/${st.recovery_threshold || 2}`,
        );
      } else {
        parts.push("自动切回：已关闭");
      }
    }
    if (st.last_check_at && !String(st.last_check_at).startsWith("0001-")) {
      parts.push(`最近检查：${formatDate(st.last_check_at)}`);
    }
    if (st.last_error) {
      parts.push(`最近错误：${st.last_error}`);
    }
    summary.textContent = parts.join(" · ");

    if (isFailedOver) {
      banner.hidden = false;
      banner.className = "failover-banner";
      banner.innerHTML = `<span><strong>故障转移生效中：</strong>原主节点「${escapeHTML(nodeLabelByID(st.primary_node_id))}」不可用，当前实际流量已热切至备用节点「${escapeHTML(nodeLabelByID(st.active_node_id))}」${st.auto_failback ? "（持续探活原主节点中）" : "（已关闭自动回切）"}</span><button class="small-btn" type="button" data-action="failover-failback">立即切回主节点</button>`;
    } else if (st.state === "all_down") {
      banner.hidden = false;
      banner.className = "failover-banner danger";
      banner.innerHTML = `<span><strong>故障转移告警：</strong>主节点及全部备用节点探测失败，当前停留在「${escapeHTML(nodeLabelByID(st.active_node_id))}」等待网络恢复。</span>`;
    } else {
      banner.hidden = true;
      banner.innerHTML = "";
    }
  }

  const events = Array.isArray(st.events) ? [...st.events].reverse() : [];
  if (events.length) {
    eventsWrap.hidden = false;
    eventsList.innerHTML = events
      .slice(0, 8)
      .map(
        (ev) =>
          `<li><span class="failover-event-time">${escapeHTML(formatDate(ev.time))}</span><span>${escapeHTML(ev.message)}</span></li>`,
      )
      .join("");
  } else {
    eventsWrap.hidden = true;
    eventsList.innerHTML = "";
  }
}

async function loadFailoverStatus(background = false) {
  try {
    failoverRuntime = await request("/api/failover/status", { background });
    renderFailoverStatus();
    if (activeViewID() === "nodes") renderNodes();
  } catch (error) {
    if (!background) toast(error.message, true);
  }
}
