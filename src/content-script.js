(() => {
  "use strict";

  const CHANNEL = "leakfence-local";
  const DATA_ALLOW_ONCE = "leakFenceAllowOnce";
  const state = {
    origin: getSupportedOrigin(),
    url: location.href,
    settings: {
      clearOnBlock: true,
      minPasswordLength: 6,
      patternGuard: true,
      redactOnBlock: true,
      language: "en"
    },
    lastSubmitter: null,
    activeDialog: null,
    extensionAvailable: true,
    locked: false,
    allowNextActivation: new WeakSet(),
    seenInputs: new WeakSet(),
    pendingChecks: new WeakMap()
  };

  init();

  async function init() {
    if (!state.origin) {
      return;
    }
    try {
      const publicState = await sendMessage({ type: "GET_STATE", origin: state.origin });
      state.settings = { ...state.settings, ...publicState.settings };
    } catch (error) {
      if (isExtensionContextError(error)) {
        markExtensionUnavailable();
        return;
      }
      console.warn("[LeakFence Local] Failed to initialize:", error);
    }

    watchDocument();
    scanMonitoredInputs(document);
  }

  function watchDocument() {
    document.addEventListener("submit", onSubmitCapture, true);
    document.addEventListener("click", onActivationCapture, true);
    document.addEventListener("input", onTextActivity, true);
    document.addEventListener("change", onTextActivity, true);
    document.addEventListener("blur", onTextActivity, true);
    document.addEventListener("paste", onPasteCapture, true);
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node instanceof Element || node instanceof DocumentFragment) {
            scanMonitoredInputs(node);
          }
        }
      }
    });

    const startObserver = () => {
      if (document.documentElement) {
        observer.observe(document.documentElement, { childList: true, subtree: true });
      }
    };

    if (document.documentElement) {
      startObserver();
    } else {
      document.addEventListener("DOMContentLoaded", startObserver, { once: true });
    }
  }

  function scanMonitoredInputs(root) {
    const inputs = [];
    if (isMonitoredEditable(root)) {
      inputs.push(root);
    }
    if (root.querySelectorAll) {
      inputs.push(...root.querySelectorAll("input, textarea, [contenteditable=''], [contenteditable='true']"));
      for (const element of root.querySelectorAll("*")) {
        if (element.shadowRoot) {
          scanMonitoredInputs(element.shadowRoot);
        }
      }
    }

    for (const input of inputs) {
      if (!state.seenInputs.has(input)) {
        state.seenInputs.add(input);
        input.addEventListener("input", onTextActivity, true);
        input.addEventListener("change", onTextActivity, true);
        input.addEventListener("blur", onTextActivity, true);
      }
    }
  }

  function onTextActivity(event) {
    if (!state.extensionAvailable) {
      return;
    }
    const input = event.target;
    if (!isMonitoredEditable(input)) {
      return;
    }
    queueTextCheck(input);
  }

  function onPasteCapture(event) {
    if (!state.extensionAvailable) {
      return;
    }
    const text = event.clipboardData?.getData("text/plain") || "";
    if (!text || text.trim().length < state.settings.minPasswordLength) {
      return;
    }

    const target = event.target;
    if (!isMonitoredEditable(target)) {
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();

    void sendMessage({
      type: "ASSESS_TEXT",
      text,
      origin: state.origin,
      url: state.url,
      source: "paste"
    })
      .then((result) => {
        if (result.decision === "BLOCK") {
          handleBlock(result, {
            form: closestFormOrDocument(target),
            sourceInput: target,
            assessedText: text,
            staleCheck: false,
            lockPage: false
          });
          return;
        }
        insertText(target, text);
      })
      .catch((error) => {
        if (isExtensionContextError(error)) {
          markExtensionUnavailable();
          insertText(target, text);
          return;
        }
        console.warn("[LeakFence Local] Paste check failed:", error);
        showDialog({
          title: t("checkFailedTitle"),
          body: t("checkFailedBody"),
          meta: error.message || String(error),
          actions: [
            { label: t("keepBlocked"), kind: "danger", onClick: closeDialog }
          ]
        });
      });
  }

  function queueTextCheck(input) {
    if (!state.extensionAvailable) {
      return;
    }
    const value = getEditableText(input);
    if (!isProbablySensitiveText(value)) {
      return;
    }

    clearTimeout(state.pendingChecks.get(input));
    const timer = setTimeout(async () => {
      try {
        const result = await sendMessage({
          type: "ASSESS_TEXT",
          text: value,
          origin: state.origin,
          url: state.url,
          source: "input"
        });
        if (result.decision === "BLOCK") {
          handleBlock(result, { form: closestFormOrDocument(input), sourceInput: input, assessedText: value, staleCheck: true });
        }
      } catch (error) {
        if (isExtensionContextError(error)) {
          markExtensionUnavailable();
          return;
        }
        console.warn("[LeakFence Local] Check failed:", error);
      }
    }, 180);
    state.pendingChecks.set(input, timer);
  }

  function onSubmitCapture(event) {
    if (!state.extensionAvailable) {
      return;
    }
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset[DATA_ALLOW_ONCE] === "1") {
      delete form.dataset[DATA_ALLOW_ONCE];
      return;
    }

    const secrets = collectTextValues(form);
    if (secrets.length === 0) {
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();
    void assessSubmit(form, secrets, event.submitter || state.lastSubmitter);
  }

  function onActivationCapture(event) {
    if (!state.extensionAvailable) {
      return;
    }
    const target = actionableElement(event.target);
    if (!target) {
      return;
    }
    if (state.allowNextActivation.has(target)) {
      state.allowNextActivation.delete(target);
      return;
    }
    if (isSubmitControl(target)) {
      state.lastSubmitter = target;
    }

    const form = target instanceof HTMLElement ? target.closest("form") : null;
    const root = form || document;
    const secrets = collectTextValues(root);
    if (secrets.length === 0) {
      return;
    }

    interceptActivation(event, target, root, secrets);
  }

  function interceptActivation(event, target, root, knownSecrets) {
    const secrets = knownSecrets || collectTextValues(root);
    if (secrets.length === 0) {
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();
    void assessSubmit(root, secrets, target);
  }

  async function assessSubmit(form, secrets, submitter) {
    try {
      const result = await sendMessage({
        type: "ASSESS_TEXT",
        text: secrets.join("\n"),
        origin: state.origin,
        url: state.url,
        source: "submit"
      });

      if (result.decision === "BLOCK") {
        handleBlock(result, { form, sourceInput: firstMonitoredInput(form), assessedText: secrets.join("\n"), staleCheck: true });
        return;
      }

      if (result.decision === "PROMPT_REGISTER") {
        showRegisterDialog(result, form, secrets[secrets.length - 1], submitter);
        return;
      }

      continueSubmission(form, submitter);
    } catch (error) {
      if (isExtensionContextError(error)) {
        markExtensionUnavailable();
        continueSubmission(form, submitter);
        return;
      }
      showDialog({
        title: t("checkFailedTitle"),
        body: t("checkFailedBody"),
        meta: error.message || String(error),
        actions: [
          { label: t("keepBlocked"), kind: "danger", onClick: closeDialog }
        ]
      });
    }
  }

  function handleBlock(result, context) {
    if (isStaleBlock(result, context)) {
      unlockPageOnce();
      return;
    }

    if (context.lockPage !== false) {
      state.locked = true;
      window.postMessage({
        channel: CHANNEL,
        type: "LOCK",
        reason: "Protected secret used on an unauthorized origin."
      }, "*");
    }

    if (state.settings.clearOnBlock) {
      clearSensitivePasswordInputs(context.form || document);
    }

    const labels = (result.unauthorized || [])
      .map((item) => item.matchPreview ? `${item.label} (${item.matchPreview})` : item.label)
      .join(", ");

    const actions = [
      { label: t("keepBlocked"), kind: "danger", onClick: closeDialog }
    ];

    if (state.settings.redactOnBlock && result.redactedText && context.sourceInput) {
      actions.push({
        label: t("pasteRedacted"),
        kind: "primary",
        onClick: () => {
          rememberRedactedText(context.sourceInput, result.redactedText);
          replaceEditableText(context.sourceInput, result.redactedText);
          unlockPageOnce();
          closeDialog();
        }
      });
    }

    if (state.settings.redactOnBlock && result.suggestedRedactions?.length) {
      actions.push({
        label: t("clearVisibleFields"),
        onClick: () => {
          clearMonitoredInputs(context.form || document);
          unlockPageOnce();
          closeDialog();
        }
      });
    }

    showDialog({
      title: t("blockedTitle"),
      body: t("blockedBody", { labels: labels || t("protectedSecret") }),
      meta: `${t("destination")}: ${currentAiName(result) || state.origin}\n${t("currentOrigin")}: ${state.origin}`,
      actions
    });
  }

  function currentAiName(result) {
    return result.service?.name || null;
  }

  function isStaleBlock(result, context = {}) {
    if (!context.sourceInput) {
      return false;
    }

    const currentText = getEditableText(context.sourceInput);
    if (result.redactedText && currentText === result.redactedText && currentText.includes("_REDACTED]")) {
      return true;
    }

    if (isRecentlyRedacted(context.sourceInput, currentText)) {
      return true;
    }

    if (!context.staleCheck || !context.assessedText) {
      return false;
    }

    return currentText && currentText !== context.assessedText && !currentText.includes(context.assessedText);
  }

  function showRegisterDialog(result, form, secret, submitter) {
    const service = result.service;
    showDialog({
      title: t("protectTitle"),
      body: t("protectBody", { service: service?.name || state.origin }),
      meta: `Origin: ${state.origin}`,
      actions: [
        {
          label: t("onlyThisTime"),
          onClick: () => {
            closeDialog();
            continueSubmission(form, submitter);
          }
        },
        {
          label: t("protectSecret"),
          kind: "primary",
          onClick: async () => {
            await sendMessage({
              type: "REGISTER_SECRET",
              secret,
              origin: state.origin,
              url: state.url,
              label: service?.name
            });
            closeDialog();
            continueSubmission(form, submitter);
          }
        }
      ]
    });
  }

  function continueSubmission(form, submitter) {
    if (!(form instanceof HTMLFormElement)) {
      replayActivation(submitter);
      return;
    }

    unlockPageOnce();
    form.dataset[DATA_ALLOW_ONCE] = "1";
    if (submitter && typeof form.requestSubmit === "function" && submitter.form === form) {
      form.requestSubmit(submitter);
    } else if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else {
      form.submit();
    }
  }

  function replayActivation(target) {
    unlockPageOnce();
    if (!(target instanceof HTMLElement)) {
      return;
    }
    state.allowNextActivation.add(target);
    target.click();
  }

  function unlockPageOnce() {
    state.locked = false;
    window.postMessage({ channel: CHANNEL, type: "UNLOCK_ONCE" }, "*");
  }

  function collectTextValues(root) {
    return allMonitoredInputs(root)
      .map(getEditableText)
      .filter(isProbablySensitiveText);
  }

  function firstMonitoredInput(root) {
    return allMonitoredInputs(root)[0] || null;
  }

  function clearSensitivePasswordInputs(root) {
    for (const input of allMonitoredInputs(root)) {
      if (input instanceof HTMLInputElement && input.type === "password") {
        input.value = "";
        input.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }
  }

  function clearMonitoredInputs(root) {
    for (const input of allMonitoredInputs(root)) {
      if (input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement) {
        input.value = "";
      } else {
        input.textContent = "";
      }
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }
  }

  function allMonitoredInputs(root) {
    const inputs = [];
    if (isMonitoredEditable(root)) {
      inputs.push(root);
    }
    if (root.querySelectorAll) {
      inputs.push(...[...root.querySelectorAll("input, textarea, [contenteditable=''], [contenteditable='true']")].filter(isMonitoredEditable));
    }
    return inputs;
  }

  function getEditableText(input) {
    if (input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement) {
      return input.value || "";
    }
    if (input instanceof HTMLElement && input.isContentEditable) {
      return input.innerText || input.textContent || "";
    }
    return "";
  }

  function insertText(target, text) {
    if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
      const start = target.selectionStart ?? target.value.length;
      const end = target.selectionEnd ?? target.value.length;
      target.value = `${target.value.slice(0, start)}${text}${target.value.slice(end)}`;
      const caret = start + text.length;
      target.setSelectionRange(caret, caret);
      target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertFromPaste", data: text }));
      return;
    }

    if (target instanceof HTMLElement && target.isContentEditable) {
      document.execCommand("insertText", false, text);
      target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertFromPaste", data: text }));
    }
  }

  function replaceEditableText(target, text) {
    if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
      target.value = text;
      target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: text }));
      return;
    }

    if (target instanceof HTMLElement && target.isContentEditable) {
      target.textContent = text;
      target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: text }));
    }
  }

  function rememberRedactedText(target, text) {
    if (!target || !text) {
      return;
    }
    state.pendingChecks.delete(target);
    state.redactedApprovals ??= new WeakMap();
    state.redactedApprovals.set(target, {
      text,
      expiresAt: Date.now() + 15000
    });
  }

  function isRecentlyRedacted(target, text) {
    const approval = state.redactedApprovals?.get(target);
    if (!approval) {
      return false;
    }
    if (Date.now() > approval.expiresAt) {
      state.redactedApprovals.delete(target);
      return false;
    }
    return text === approval.text;
  }

  function closestFormOrDocument(target) {
    if (target instanceof HTMLElement) {
      return target.closest("form") || document;
    }
    return document;
  }

  function isMonitoredEditable(value) {
    if (value instanceof HTMLTextAreaElement) {
      return true;
    }
    if (value instanceof HTMLElement && value.isContentEditable) {
      return true;
    }
    if (!(value instanceof HTMLInputElement)) {
      return false;
    }
    return ["password", "text", "search", "email", "url", "tel"].includes(value.type);
  }

  function isSubmitControl(target) {
    return (
      target instanceof HTMLButtonElement && (!target.type || target.type === "submit")
    ) || (
      target instanceof HTMLInputElement && (target.type === "submit" || target.type === "image")
    );
  }

  function actionableElement(target) {
    if (!(target instanceof Element)) {
      return null;
    }
    const element = target.closest("button, input[type='submit'], input[type='button'], input[type='image'], [role='button'], a[href]");
    if (!element) {
      return null;
    }
    return isSubmitControl(element) || looksLikeCredentialAction(element) ? element : null;
  }

  function looksLikeCredentialAction(element) {
    const text = [
      element.getAttribute("aria-label"),
      element.getAttribute("title"),
      element.getAttribute("value"),
      element.textContent
    ].filter(Boolean).join(" ").toLowerCase();

    return /\b(send|ask|prompt|chat|log\s*in|login|sign\s*in|signin|continue|next|submit|verify|authorize|zaloguj|dalej|kontynuuj|wyslij)\b/.test(text);
  }

  function isProbablySensitiveText(value) {
    return typeof value === "string" && value.length >= state.settings.minPasswordLength && value.length <= 50000;
  }

  function isProbablyPassword(value) {
    return isProbablySensitiveText(value);
  }

  function showDialog({ title, body, meta, actions }) {
    closeDialog();
    const backdrop = document.createElement("div");
    backdrop.className = "cg-backdrop";

    const dialog = document.createElement("section");
    dialog.className = "cg-dialog";
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");

    const bar = document.createElement("div");
    bar.className = "cg-dialog__bar";
    const mark = document.createElement("div");
    mark.className = "cg-dialog__mark";
    mark.textContent = "AI";
    const heading = document.createElement("h2");
    heading.className = "cg-dialog__title";
    heading.textContent = title;
    bar.append(mark, heading);

    const content = document.createElement("div");
    content.className = "cg-dialog__body";
    const paragraph = document.createElement("p");
    paragraph.textContent = body;
    const proof = document.createElement("p");
    proof.className = "cg-dialog__proof";
    proof.textContent = t("localProof");
    const metaBox = document.createElement("pre");
    metaBox.className = "cg-dialog__meta";
    metaBox.textContent = meta || "";
    content.append(paragraph, proof, metaBox);

    const footer = document.createElement("div");
    footer.className = "cg-dialog__actions";
    for (const action of actions) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `cg-button${action.kind ? ` cg-button--${action.kind}` : ""}`;
      button.textContent = action.label;
      button.addEventListener("click", () => {
        Promise.resolve(action.onClick()).catch((error) => {
          metaBox.textContent = error.message || String(error);
        });
      });
      footer.append(button);
    }

    dialog.append(bar, content, footer);
    backdrop.append(dialog);
    (document.documentElement || document.body).append(backdrop);
    state.activeDialog = backdrop;
  }

  function closeDialog() {
    if (state.activeDialog) {
      state.activeDialog.remove();
      state.activeDialog = null;
    }
  }

  function sendMessage(message) {
    return new Promise((resolve, reject) => {
      try {
        if (typeof chrome === "undefined" || !chrome.runtime?.id) {
          reject(new Error("Extension context invalidated."));
          return;
        }

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
      } catch (error) {
        reject(error);
      }
    });
  }

  function isExtensionContextError(error) {
    const message = String(error?.message || error || "").toLowerCase();
    return message.includes("extension context invalidated") ||
      message.includes("context invalidated") ||
      message.includes("receiving end does not exist") ||
      message.includes("extension context");
  }

  function markExtensionUnavailable() {
    state.extensionAvailable = false;
    unlockPageOnce();
    closeDialog();
  }

  function getSupportedOrigin() {
    if (location.protocol !== "https:" && location.protocol !== "http:") {
      return null;
    }
    return location.origin;
  }

  function t(key, vars = {}) {
    const lang = state.settings.language === "pl" ? "pl" : "en";
    const value = MESSAGES[lang][key] || MESSAGES.en[key] || key;
    return value.replace(/\{(\w+)\}/g, (_, name) => vars[name] ?? "");
  }

  const MESSAGES = {
    en: {
      checkFailedTitle: "LeakFence could not check this action",
      checkFailedBody: "The action was stopped for safety. Try again or check the extension status.",
      keepBlocked: "Keep blocked",
      clearVisibleFields: "Clear visible fields",
      pasteRedacted: "Paste redacted",
      addOrigin: "Add this origin",
      blockedTitle: "AI prompt blocked",
      blockedBody: "LeakFence found {labels} in text headed to an AI chat. Keep it blocked, or paste a redacted version.",
      protectedSecret: "a protected secret",
      currentOrigin: "Current origin",
      destination: "Destination",
      allowedOrigins: "Allowed origins",
      notAvailable: "not available",
      protectTitle: "Protect this secret?",
      protectBody: "LeakFence recognized a known surface: {service}. It will store a local fingerprint, not the secret.",
      onlyThisTime: "Only this time",
      protectSecret: "Protect secret",
      localProof: "Checked locally. No prompts, secrets, fingerprints, or audit events are collected."
    },
    pl: {
      checkFailedTitle: "LeakFence nie mogl sprawdzic tej akcji",
      checkFailedBody: "Akcja zostala zatrzymana dla bezpieczenstwa. Sprobuj ponownie albo sprawdz stan rozszerzenia.",
      keepBlocked: "Zostaw zablokowane",
      clearVisibleFields: "Wyczysc widoczne pola",
      pasteRedacted: "Wklej po redakcji",
      addOrigin: "Dodaj ten origin",
      blockedTitle: "Zablokowano prompt do AI",
      blockedBody: "LeakFence wykryl: {labels} w tekscie kierowanym do czatu AI. Zostaw blokade albo wklej wersje po redakcji.",
      protectedSecret: "chroniony sekret",
      currentOrigin: "Biezacy origin",
      destination: "Cel",
      allowedOrigins: "Dozwolone originy",
      notAvailable: "brak danych",
      protectTitle: "Chronic ten sekret?",
      protectBody: "LeakFence rozpoznal znane miejsce: {service}. Zapisze lokalny fingerprint, nie sekret.",
      onlyThisTime: "Tylko tym razem",
      protectSecret: "Chron sekret",
      localProof: "Sprawdzane lokalnie. Prompty, sekrety, fingerprinty i audit nie sa zbierane."
    }
  };
})();
