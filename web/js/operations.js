// ArmWall web UI: node and site tests, service control, logs, rules, backups and core upload.

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

async function batchTestNodes(method, button) {
  let ids = selectedNodeIDs();
  if (!ids.length) {
    ids = filteredNodes().map((n) => n.id);
  }
  if (!ids.length) {
    throw new Error("没有可测试的节点");
  }
  const old = button.textContent;
  button.disabled = true;
  button.textContent = `测试中 (${ids.length})...`;
  try {
    toast(`正在批量 ${method.toUpperCase()} 测试 ${ids.length} 个节点...`);
    const data = await request("/api/node/batch-test", {
      method: "POST",
      body: { ids, method },
      timeoutMs: 180000,
    });
    if (data && data.results) {
      let okCount = 0;
      for (const [id, res] of Object.entries(data.results)) {
        if (res.error || res.ms < 0) {
          nodeTests.set(id, { error: true, method, message: res.error });
        } else {
          okCount++;
          nodeTests.set(id, { ms: res.ms, method });
        }
      }
      renderNodes();
      toast(`批量 ${method.toUpperCase()} 完成：${okCount}/${ids.length} 成功`);
    }
  } catch (err) {
    toast(`批量测试失败: ${err.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = old;
  }
}

let delaySortAsc = true;
function sortNodesByDelay() {
  delaySortAsc = !delaySortAsc;
  appState.nodes.sort((a, b) => {
    const resA = nodeTests.get(a.id);
    const resB = nodeTests.get(b.id);
    const msA = resA && !resA.error && typeof resA.ms === "number" ? resA.ms : 999999;
    const msB = resB && !resB.error && typeof resB.ms === "number" ? resB.ms : 999999;
    return delaySortAsc ? msA - msB : msB - msA;
  });
  renderNodes();
  toast(delaySortAsc ? "已按延迟由低到高排序" : "已按延迟由高到低排序");
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
      await request("/api/service/status", {}, true)
    ).trim();
    $("serviceMetric").textContent = status || "未知";
    $("serviceOutput").textContent = status || "未知";
    if (notify) toast(`代理服务：${status}`);
  } catch (error) {
    $("serviceMetric").textContent = "异常";
    if (notify) toast(error.message, true);
  }
}

async function refreshLogs() {
  $("logOut").textContent = await request("/api/logs", {}, true);
}

function activeViewID() {
  return document.querySelector(".view.active")?.id || "";
}

function startAutoRefresh() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(async () => {
    if (document.hidden || refreshInProgress) return;
    refreshInProgress = true;
    try {
      const tasks = [refreshServiceStatus(false)];
      if ((appState.strategy_groups || []).length) tasks.push(loadStrategyStatus());
      if (activeViewID() === "logs") tasks.push(refreshLogs());
      await Promise.all(tasks);
    } catch (error) {
      toast(error.message || "后台刷新失败", true);
    } finally {
      refreshInProgress = false;
    }
  }, 15000);
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
    const adBlockEnabled = data.ad_block_enabled !== false;
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
          ${tag === "geosite-ads" ? `<label class="rule-auto"><input class="rule-ad-block" type="checkbox" ${adBlockEnabled ? "checked" : ""}>启用拦截</label>` : ""}
          <label class="rule-auto"><input class="rule-auto-update" type="checkbox" ${setting.auto_update ? "checked" : ""}>自动更新</label>
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
    { method: "POST", body: form, timeoutMs: 180000 },
    true,
  );
  $("coreVersion").textContent = output.trim() || "更新完成";
  toast(`${selectedCore} 已更新`);
}
