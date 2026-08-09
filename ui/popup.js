const originEl = document.querySelector("#origin");
const statusEl = document.querySelector("#status");
const statusTitleEl = document.querySelector("#statusTitle");
const statusTextEl = document.querySelector("#statusText");
const credentialCountEl = document.querySelector("#credentialCount");
const policyVersionEl = document.querySelector("#policyVersion");
const openOptionsButton = document.querySelector("#openOptions");
const protectSiteButton = document.querySelector("#protectSite");
let currentOrigin = "";
let currentState = null;

init().catch((error) => {
  statusTitleEl.textContent = "Error";
  statusTextEl.textContent = error.message || String(error);
});

openOptionsButton.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

protectSiteButton.addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("ui/options.html") });
});

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const origin = supportedOrigin(tab?.url);
  currentOrigin = origin;

  const state = await sendMessage({ type: "GET_STATE", origin: origin || undefined });
  currentState = state;
  applyI18n();
  originEl.textContent = origin || t("noActivePage");
  credentialCountEl.textContent = String(state.secretCount || state.credentialCount);
  policyVersionEl.textContent = `v${state.policy.version}`;

  if (state.currentService) {
    statusEl.classList.add("known");
    statusTitleEl.textContent = state.currentService.name;
    statusTextEl.textContent = t("protectedHere");
  }
}

function applyI18n() {
  document.documentElement.lang = lang();
  for (const node of document.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.dataset.i18n);
  }
}

function lang() {
  return currentState?.settings?.language === "pl" ? "pl" : "en";
}

function t(key) {
  return (MESSAGES[lang()] && MESSAGES[lang()][key]) || MESSAGES.en[key] || key;
}

const MESSAGES = {
  en: {
    checkingTab: "Checking tab...",
    statusText: "LeakFence only runs on supported AI chats.",
    secrets: "Secrets",
    policy: "Policy",
    addSecret: "Add secret",
    options: "Options",
    noActivePage: "No active web page",
    knownSurface: "This origin is listed as a known AI chat.",
    protectedHere: "Protection is active on this AI chat.",
    privacyLocal: "Local only",
    privacyNoTelemetry: "No data collected",
    privacyOpenSource: "Open source"
  },
  pl: {
    checkingTab: "Sprawdzanie karty...",
    statusText: "LeakFence dziala tylko na obslugiwanych czatach AI.",
    secrets: "Sekrety",
    policy: "Policy",
    addSecret: "Dodaj sekret",
    options: "Opcje",
    noActivePage: "Brak aktywnej strony web",
    knownSurface: "Ten origin jest na liscie znanych czatow AI.",
    protectedHere: "Ochrona jest aktywna na tym czacie AI.",
    privacyLocal: "Lokalnie",
    privacyNoTelemetry: "Nic nie zbieramy",
    privacyOpenSource: "Open source"
  }
};

function supportedOrigin(url) {
  if (!url) {
    return "";
  }
  const parsed = new URL(url);
  return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.origin : "";
}

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      if (!response?.ok) {
        reject(new Error(response?.error || "Unknown extension error."));
        return;
      }
      const { ok, ...payload } = response;
      resolve(payload);
    });
  });
}
