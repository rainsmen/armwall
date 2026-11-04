// ArmWall web UI: state, API request helper and formatting utilities.

const $ = (id) => document.getElementById(id);

let token = "";
try {
  token = sessionStorage.armwallToken || localStorage.armwallToken || "";
} catch (_) {}
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

// authBlocked is set when the server rejected the token and the user has not
// supplied a new one. Background polling stops until a user action succeeds,
// so a stale token neither re-opens the prompt every 15 seconds nor burns the
// server's authentication failure budget.
let authBlocked = false;
let tokenPrompt = null;

class AuthError extends Error {}

function setToken(value) {
  token = value || "";
  try {
    if (token) {
      sessionStorage.armwallToken = token;
      localStorage.armwallToken = token;
    } else {
      sessionStorage.removeItem("armwallToken");
      localStorage.removeItem("armwallToken");
    }
  } catch (_) {}
}

function markUnauthorized() {
  authBlocked = true;
  $("connectionText").textContent = "未授权";
  document.querySelector(".top-status").classList.remove("ready");
}

// promptToken shares one prompt between concurrent requests that hit 401.
function promptToken() {
  if (!tokenPrompt) {
    tokenPrompt = Promise.resolve().then(() => {
      const value = (window.prompt("请输入 ArmWall 管理 Token") || "").trim();
      setToken(value);
      return value;
    });
    tokenPrompt.finally(() => {
      setTimeout(() => {
        tokenPrompt = null;
      }, 0);
    });
  }
  return tokenPrompt;
}

// request sends an authenticated API call. options.background marks polling
// calls: they never open the token prompt.
async function request(path, options = {}, text = false, retry = true) {
  const { background = false, timeoutMs = 30000, ...fetchOptions } = options;
  const headers = new Headers(fetchOptions.headers || {});
  const sentToken = token;
  if (sentToken) headers.set("Authorization", `Bearer ${sentToken}`);
  if (
    fetchOptions.body &&
    typeof fetchOptions.body !== "string" &&
    !(fetchOptions.body instanceof FormData)
  ) {
    headers.set("Content-Type", "application/json");
    fetchOptions.body = JSON.stringify(fetchOptions.body);
  }
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(path, {
      ...fetchOptions,
      headers,
      signal: controller.signal,
    });
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("请求超时，请检查网络或稍后重试");
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
  if (response.status === 401) {
    if (background) {
      markUnauthorized();
      throw new AuthError("Token 无效，请重新输入");
    }
    if (retry) {
      // Another request may already have obtained a new token.
      const next = token !== sentToken ? token : await promptToken();
      if (next) return request(path, options, text, false);
    }
    markUnauthorized();
    throw new AuthError("未授权：Token 无效或未输入");
  }
  if (response.status === 429) {
    throw new Error("请求过于频繁，请稍候再试 (HTTP 429)");
  }
  if (!response.ok) {
    const message =
      (await response.text()).trim() || `请求失败 (${response.status})`;
    throw new Error(message);
  }
  authBlocked = false;
  if (text) return await response.text();
  const type = response.headers.get("content-type") || "";
  return type.includes("application/json")
    ? await response.json()
    : await response.text();
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
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

// guardForm runs submit for a form at most once at a time (F5).
async function guardForm(event, submit) {
  event.preventDefault();
  const form = event.target;
  if (form.dataset.busy === "1") return;
  form.dataset.busy = "1";
  const buttons = form.querySelectorAll('button[type="submit"]');
  buttons.forEach((button) => {
    button.disabled = true;
  });
  try {
    await submit();
  } finally {
    delete form.dataset.busy;
    buttons.forEach((button) => {
      button.disabled = false;
    });
  }
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
    pruneNodeSelection();
    renderState();
    $("connectionText").textContent = "已连接";
    document.querySelector(".top-status").classList.add("ready");
    await refreshServiceStatus(false);
  } catch (error) {
    if (!(error instanceof AuthError))
      $("connectionText").textContent = "连接失败";
    document.querySelector(".top-status").classList.remove("ready");
    if (showErrors || error instanceof AuthError) toast(error.message, true);
  }
}
