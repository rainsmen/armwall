// ArmWall web UI: dispatch for [data-action] buttons.

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
    else if (action === "batch-test") await batchTestNodes(method || "tcp", button);
    else if (action === "sort-nodes-delay") sortNodesByDelay();
    else if (action === "move-node") {
      const visibleIDs = filteredNodes().map((node) => node.id);
      const visibleFrom = visibleIDs.indexOf(id);
      const visibleTo = visibleFrom + Number(direction);
      if (visibleFrom < 0 || visibleTo < 0 || visibleTo >= visibleIDs.length)
        return;
      const ids = appState.nodes.map((node) => node.id);
      const from = ids.indexOf(id);
      const to = ids.indexOf(visibleIDs[visibleTo]);
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
        timeoutMs: 180000,
      });
      toast("订阅已更新");
      await loadState(false);
    } else if (action === "update-all-subscriptions") {
      button.disabled = true;
      await request("/api/subscription/update", { method: "POST", timeoutMs: 180000 });
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
      const adBlock = row.querySelector(".rule-ad-block");
      await request("/api/rules/settings", {
        method: "POST",
        body: {
          tag,
          backup: row.querySelector(".rule-backup").value.trim(),
          hours: Number(row.querySelector(".rule-hours").value),
          autoUpdate: row.querySelector(".rule-auto-update").checked,
          ...(adBlock ? { adBlockEnabled: adBlock.checked } : {}),
        },
      });
      toast("规则设置已保存");
      await renderRules();
    } else if (action === "update-rule") {
      button.disabled = true;
      await request("/api/rules/update", { method: "POST", body: { tag }, timeoutMs: 180000 });
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
          { method: "POST", body: { core: selectedCore, action: "latest" }, timeoutMs: 180000 },
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
    } else if (action === "refresh-logs") await refreshLogs();
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
    } else if (action === "reset-token") {
      token = "";
      sessionStorage.removeItem("armwallToken");
      localStorage.removeItem("armwallToken");
      toast("本地 Token 已清除");
    }
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
}
