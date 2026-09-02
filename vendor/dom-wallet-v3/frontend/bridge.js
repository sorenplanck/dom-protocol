import { invoke as tauriInvoke } from "@tauri-apps/api/core";

export const BridgeState = Object.freeze({
  INITIALIZING: "INITIALIZING",
  READY: "READY",
  FAILED: "FAILED",
});

export class NativeBridgeUnavailableError extends Error {
  constructor(cause) {
    super("Native desktop command bridge is unavailable.", { cause });
    this.name = "NativeBridgeUnavailableError";
    this.code = "NATIVE_BRIDGE_UNAVAILABLE";
  }
}

export function createNativeBridge(invokeImpl = tauriInvoke) {
  let state = BridgeState.INITIALIZING;
  let probe;

  const initialize = () => {
    if (state === BridgeState.READY) return Promise.resolve(probe);
    if (probe) return probe;

    state = BridgeState.INITIALIZING;
    probe = invokeImpl("native_bridge_status")
      .then((result) => {
        if (result?.bridge !== "ready" || typeof result?.app_version !== "string") {
          throw new Error("Invalid native bridge response.");
        }
        state = BridgeState.READY;
        return result;
      })
      .catch((error) => {
        state = BridgeState.FAILED;
        throw new NativeBridgeUnavailableError(error);
      });
    return probe;
  };

  return Object.freeze({
    get state() { return state; },
    initialize,
    async invoke(command, args = {}) {
      await initialize();
      return invokeImpl(command, args);
    },
  });
}

export const nativeBridge = createNativeBridge();
