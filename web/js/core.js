// ArmWall web UI: state, API request helper and formatting utilities.

const $ = (id) => document.getElementById(id);

let token = sessionStorage.armwallToken || localStorage.armwallToken || "";
let appState = { nodes: [], subscriptions: [] };
const nodeTests = new Map();
const strategyRuntime = new Map();
let selectedCore = "sing-box";
let toastTimer;
let refreshTimer;
let refreshInProgress = false;

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
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs || 30000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, { ...options, headers, signal: controller.signal });
    if (response.status === 401 && retry) {
      token = window.prompt("请输入 ArmWall 管理 Token") || "";
      if (token) {
        sessionStorage.armwallToken = token;
        localStorage.armwallToken = token;
      } else {
        sessionStorage.removeItem("armwallToken");
        localStorage.removeItem("armwallToken");
      }
      return request(path, options, text, false);
    }
    if (response.status === 429) {
      throw new Error("请求过于频繁，请稍候再试 (HTTP 429)");
    }
    if (!response.ok) {
      const message =
        (await response.text()).trim() || `请求失败 (${response.status})`;
      throw new Error(message);
    }
    if (text) return await response.text();
    const type = response.headers.get("content-type") || "";
    return type.includes("application/json") ? await response.json() : await response.text();
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("请求超时，请检查网络或稍后重试");
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
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
    pruneNodeTests();
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
