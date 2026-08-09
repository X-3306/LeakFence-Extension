const elements = {
  refresh: document.querySelector("#refresh"),
  guide: document.querySelector("#guide"),
  addForm: document.querySelector("#addForm"),
  label: document.querySelector("#label"),
  password: document.querySelector("#password"),
  addNote: document.querySelector("#addNote"),
  secrets: document.querySelector("#credentials"),
  secretCount: document.querySelector("#credentialCount"),
  clearOnBlock: document.querySelector("#clearOnBlock"),
  patternGuard: document.querySelector("#patternGuard"),
  redactOnBlock: document.querySelector("#redactOnBlock"),
  language: document.querySelector("#language"),
  policy: document.querySelector("#policy"),
  policyVersion: document.querySelector("#policyVersion"),
  audit: document.querySelector("#audit"),
  clearAudit: document.querySelector("#clearAudit")
};

let currentState = null;

elements.refresh.addEventListener("click", load);
elements.guide.addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("ui/guide.html") });
});
elements.addForm.addEventListener("submit", onAddSecret);
elements.clearAudit.addEventListener("click", async () => {
  await sendMessage({ type: "CLEAR_AUDIT" });
  await load();
});

for (const key of ["clearOnBlock", "patternGuard", "redactOnBlock"]) {
  elements[key].addEventListener("change", async () => {
    await sendMessage({ type: "UPDATE_SETTINGS", patch: { [key]: elements[key].checked } });
    await load();
  });
}

elements.language.addEventListener("change", async () => {
  await sendMessage({ type: "UPDATE_SETTINGS", patch: { language: elements.language.value } });
  await load();
});

load().catch(showError);

async function load() {
  currentState = await sendMessage({ type: "GET_STATE" });
  const audit = await sendMessage({ type: "GET_AUDIT" });
  renderState(currentState, audit.audit || []);
}

async function onAddSecret(event) {
  event.preventDefault();
  elements.addNote.textContent = "";

  try {
    await sendMessage({
      type: "REGISTER_SECRET",
      label: elements.label.value,
      authorizedOrigins: [],
      origin: "https://chatgpt.com",
      secret: elements.password.value
    });
    elements.password.value = "";
    elements.addForm.reset();
    elements.addNote.textContent = t("saved");
    await load();
  } catch (error) {
    elements.addNote.textContent = error.message || String(error);
  }
}

function renderState(state, audit) {
  currentState = state;
  const secrets = state.secrets || state.credentials || [];
  elements.secretCount.textContent = String(secrets.length);
  elements.policyVersion.textContent = `v${state.policy.version}`;
  elements.clearOnBlock.checked = Boolean(state.settings.clearOnBlock);
  elements.patternGuard.checked = Boolean(state.settings.patternGuard);
  elements.redactOnBlock.checked = Boolean(state.settings.redactOnBlock);
  elements.language.value = state.settings.language || "en";
  applyI18n();

  elements.secrets.replaceChildren(
    ...secrets.map((secret) => secretItem(secret)),
    secrets.length ? "" : emptyItem(t("noSecrets"))
  );

  elements.policy.replaceChildren(
    ...state.policy.services.map((service) => {
      const item = document.createElement("div");
      item.className = "item";
      const strong = document.createElement("strong");
      strong.textContent = service.name;
      const code = document.createElement("code");
      code.textContent = service.authorizedOrigins.join(", ");
      item.append(strong, code);
      return item;
    })
  );

  elements.audit.replaceChildren(
    ...audit.slice(0, 80).map((event) => {
      const item = document.createElement("div");
      item.className = "item";
      const title = document.createElement("strong");
      title.textContent = `${event.type} - ${event.decision || ""}`;
      const code = document.createElement("code");
      code.textContent = `${event.at} ${event.origin || ""} ${event.details || ""}`;
      item.append(title, code);
      return item;
    }),
    audit.length ? "" : emptyItem(t("auditEmpty"))
  );
}

function secretItem(secret) {
  const item = document.createElement("div");
  item.className = "item";

  const header = document.createElement("div");
  header.className = "itemHeader";
  const title = document.createElement("strong");
  title.textContent = secret.label;
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "secondary";
  remove.textContent = t("delete");
  remove.addEventListener("click", async () => {
    await sendMessage({ type: "DELETE_CREDENTIAL", credentialId: secret.id });
    await load();
  });
  header.append(title, remove);

  const note = document.createElement("code");
  note.textContent = t("blocksOnAi");
  item.append(header, note);
  return item;
}

function emptyItem(text) {
  const item = document.createElement("div");
  item.className = "item";
  item.textContent = text;
  return item;
}

function showError(error) {
  elements.addNote.textContent = error.message || String(error);
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
    tagline: "Stop secrets before they are pasted into AI chats. Fully local, no cloud scanning.",
    guide: "Guide",
    refresh: "Refresh",
    protectSecret: "Protect a secret from AI prompts",
    label: "Label",
    secretValue: "Secret value",
    saveFingerprint: "Save local fingerprint",
    protectedSecrets: "Protected secrets",
    privacyTitle: "Privacy posture",
    privacyBadge: "verifiable",
    privacyCardLocalTitle: "On-device checks",
    privacyCardLocalBody: "Prompt text is checked in the extension runtime. It is not sent to a server.",
    privacyCardStorageTitle: "Local fingerprints",
    privacyCardStorageBody: "Manually protected secrets are stored as local HMAC fingerprints, not plaintext.",
    privacyCardTelemetryTitle: "No data collected",
    privacyCardTelemetryBody: "No prompts, secrets, fingerprints, audit events, or usage analytics are collected.",
    privacyCardSourceTitle: "Open source",
    privacyCardSourceBody: "The code is public so anyone can verify the extension behavior.",
    settings: "Settings",
    clearPasswordFields: "Clear password fields after a block",
    patternGuard: "Detect common secret patterns locally",
    redactOnBlock: "Offer redacted paste when a leak is blocked",
    knownSurfaces: "AI chats covered",
    clear: "Clear",
    saved: "Fingerprint saved locally. LeakFence will block this secret in supported AI chats.",
    noSecrets: "No protected secrets yet.",
    auditEmpty: "Audit is empty.",
    delete: "Delete",
    blocksOnAi: "Blocked on supported AI chats"
  },
  pl: {
    tagline: "Zatrzymaj sekrety przed wklejeniem do czatow AI. Lokalnie, bez skanowania w chmurze.",
    guide: "Poradnik",
    refresh: "Odswiez",
    protectSecret: "Chron sekret przed promptami AI",
    label: "Nazwa",
    secretValue: "Wartosc sekretu",
    saveFingerprint: "Zapisz lokalny fingerprint",
    protectedSecrets: "Chronione sekrety",
    privacyTitle: "Prywatnosc",
    privacyBadge: "weryfikowalne",
    privacyCardLocalTitle: "Sprawdzanie na urzadzeniu",
    privacyCardLocalBody: "Tekst promptu jest sprawdzany w runtime rozszerzenia. Nie trafia na serwer.",
    privacyCardStorageTitle: "Lokalne fingerprinty",
    privacyCardStorageBody: "Recznie chronione sekrety sa zapisane jako lokalne fingerprinty HMAC, nie plaintext.",
    privacyCardTelemetryTitle: "Nic nie zbieramy",
    privacyCardTelemetryBody: "Prompty, sekrety, fingerprinty, audit i analityka uzycia nie sa zbierane.",
    privacyCardSourceTitle: "Open source",
    privacyCardSourceBody: "Kod jest publiczny, wiec kazdy moze zweryfikowac dzialanie rozszerzenia.",
    settings: "Ustawienia",
    clearPasswordFields: "Czysc pola hasla po blokadzie",
    patternGuard: "Wykrywaj lokalnie popularne wzorce sekretow",
    redactOnBlock: "Proponuj wklejenie po redakcji, gdy wyciek jest blokowany",
    knownSurfaces: "Obslugiwane czaty AI",
    clear: "Wyczysc",
    saved: "Fingerprint zapisany lokalnie. LeakFence zablokuje ten sekret w obslugiwanych czatach AI.",
    noSecrets: "Brak chronionych sekretow.",
    auditEmpty: "Audit jest pusty.",
    delete: "Usun",
    blocksOnAi: "Blokowane w obslugiwanych czatach AI"
  }
};

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
