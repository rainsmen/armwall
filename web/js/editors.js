// ArmWall web UI: node, subscription, strategy and ACL editors.

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

async function openNodeEditor(node = null) {
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

  if (node && (node.password === "******" || node.uuid === "******" || node.obfs_password === "******")) {
    try {
      const real = await request(`/api/node/get?id=${encodeURIComponent(node.id)}`);
      if (real && $("nodeId").value === node.id) {
        if (real.password) $("nodePassword").value = real.password;
        if (real.uuid) $("nodeUUID").value = real.uuid;
        if (real.obfs_password) $("nodeObfsPassword").value = real.obfs_password;
      }
    } catch (_) {}
  }
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
    id: id || undefined,
    name: $("subscriptionName").value.trim(),
    url: $("subscriptionURL").value.trim(),
    update_hours: Number($("subscriptionHours").value) || 6,
    enabled: $("subscriptionEnabled").checked,
  };
  if (id && existing?.last_updated) {
    payload.last_updated = existing.last_updated;
  }
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
