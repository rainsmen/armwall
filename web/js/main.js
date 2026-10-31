// ArmWall web UI: navigation, event bindings and startup.

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
    if (button.dataset.view === "logs") void refreshLogs();
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
startAutoRefresh();
