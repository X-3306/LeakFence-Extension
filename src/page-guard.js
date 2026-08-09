(() => {
  "use strict";

  const CHANNEL = "leakfence-local";
  let locked = false;
  let lockReason = "LeakFence Local blocked protected secret use on this origin.";

  window.addEventListener("message", (event) => {
    if (event.source !== window || event.data?.channel !== CHANNEL) {
      return;
    }
    if (event.data.type === "LOCK") {
      locked = true;
      lockReason = event.data.reason || lockReason;
    }
    if (event.data.type === "UNLOCK_ONCE") {
      locked = false;
    }
  });

  const blockedError = () => new DOMException(lockReason, "SecurityError");

  const originalFetch = window.fetch;
  if (typeof originalFetch === "function") {
    window.fetch = function credentialGuardFetch(...args) {
      if (locked) {
        return Promise.reject(blockedError());
      }
      return Reflect.apply(originalFetch, this, args);
    };
  }

  const originalSendBeacon = navigator.sendBeacon;
  if (typeof originalSendBeacon === "function") {
    navigator.sendBeacon = function credentialGuardSendBeacon(...args) {
      if (locked) {
        return false;
      }
      return Reflect.apply(originalSendBeacon, this, args);
    };
  }

  const originalWebSocket = window.WebSocket;
  if (typeof originalWebSocket === "function") {
    window.WebSocket = new Proxy(originalWebSocket, {
      construct(target, args) {
        if (locked) {
          throw blockedError();
        }
        return Reflect.construct(target, args);
      },
      apply(target, thisArg, args) {
        if (locked) {
          throw blockedError();
        }
        return Reflect.apply(target, thisArg, args);
      }
    });
  }

  const originalXhrOpen = XMLHttpRequest.prototype.open;
  const originalXhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function credentialGuardXhrOpen(...args) {
    this.__credentialGuardUrl = args[1];
    return Reflect.apply(originalXhrOpen, this, args);
  };
  XMLHttpRequest.prototype.send = function credentialGuardXhrSend(...args) {
    if (locked) {
      throw blockedError();
    }
    return Reflect.apply(originalXhrSend, this, args);
  };

  const originalSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function credentialGuardFormSubmit(...args) {
    if (locked) {
      throw blockedError();
    }
    return Reflect.apply(originalSubmit, this, args);
  };

  const originalRequestSubmit = HTMLFormElement.prototype.requestSubmit;
  if (typeof originalRequestSubmit === "function") {
    HTMLFormElement.prototype.requestSubmit = function credentialGuardRequestSubmit(...args) {
      if (locked) {
        throw blockedError();
      }
      return Reflect.apply(originalRequestSubmit, this, args);
    };
  }
})();
