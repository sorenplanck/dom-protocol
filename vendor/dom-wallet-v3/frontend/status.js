export function synchronizationPresentation(network, peers, synchronization) {
  const localHeight = Number.isSafeInteger(network?.canonical_height)
    ? network.canonical_height
    : 0;
  const peerHeight = Number.isSafeInteger(peers?.highest_known_peer_height)
    ? peers.highest_known_peer_height
    : null;
  const connectedPeers = Number.isSafeInteger(peers?.total_connected_peers)
    ? peers.total_connected_peers
    : 0;
  const lifecycle = network?.lifecycle;
  const progress = peerHeight != null && peerHeight > 0
    ? Math.min(100, Math.floor((localHeight * 100) / peerHeight))
    : 0;

  if (lifecycle === "FAILED" || lifecycle === "STALE" || lifecycle === "STOPPED"
    || lifecycle === "STARTING") {
    return {
      badgeState: lifecycle,
      message: network?.status_message ?? `Node state: ${lifecycle}`,
      localHeight,
      peerHeight,
      progress,
    };
  }
  if (connectedPeers === 0 || lifecycle === "WAITING_FOR_PEERS") {
    return {
      badgeState: "WAITING_FOR_PEERS",
      message: `Waiting for peers at local height ${localHeight}`,
      localHeight,
      peerHeight: null,
      progress: 0,
    };
  }
  if (peerHeight == null || lifecycle === "UNKNOWN_PEER_HEIGHT") {
    return {
      badgeState: "UNKNOWN_PEER_HEIGHT",
      message: `Connected; waiting for authoritative peer height at ${localHeight}`,
      localHeight,
      peerHeight: null,
      progress: 0,
    };
  }
  if (peerHeight > localHeight || lifecycle === "SYNCHRONIZING") {
    return {
      badgeState: "SYNCHRONIZING",
      message: `Synchronizing ${localHeight} / ${peerHeight} (${progress}%)`,
      localHeight,
      peerHeight,
      progress,
    };
  }
  if (localHeight === 0 && peerHeight === 0) {
    return {
      badgeState: "CONNECTED_AT_GENESIS",
      message: "Connected to canonical peers at genesis",
      localHeight,
      peerHeight,
      progress: 100,
    };
  }
  if (peerHeight === localHeight && synchronization?.synchronized) {
    return {
      badgeState: "READY",
      message: `Wallet synchronized at height ${synchronization.cursor_height}`,
      localHeight,
      peerHeight,
      progress: 100,
    };
  }
  if (synchronization?.last_error) {
    return {
      badgeState: "ATTENTION",
      message: synchronization.last_error,
      localHeight,
      peerHeight,
      progress,
    };
  }
  return {
    badgeState: "PREPARING",
    message: "Preparing wallet synchronization",
    localHeight,
    peerHeight,
    progress,
  };
}

export function restoreReadinessPresentation(node) {
  const localHeight = Number.isSafeInteger(node?.canonical_tip_height)
    ? node.canonical_tip_height
    : 0;
  const peerHeight = Number.isSafeInteger(node?.highest_known_peer_height)
    ? node.highest_known_peer_height
    : 0;
  const connectedPeers = Number.isSafeInteger(node?.connected_peers)
    ? node.connected_peers
    : 0;
  const progress = peerHeight > 0
    ? Math.min(100, Math.floor((localHeight * 100) / peerHeight))
    : 0;
  const synchronized = node?.network === "MAINNET"
    && node?.lifecycle === "READY"
    && node?.ready === true
    && connectedPeers > 0
    && peerHeight > 0
    && localHeight >= peerHeight;

  if (synchronized) {
    return {
      submitEnabled: true,
      badge: "READY",
      message: `Mainnet node synchronized at height ${localHeight}.`,
      localHeight,
      peerHeight,
      connectedPeers,
      progress: 100,
    };
  }
  if (connectedPeers === 0) {
    return {
      submitEnabled: true,
      badge: "DISCOVERING",
      message: `Discovering Mainnet peers at local height ${localHeight}.`,
      localHeight,
      peerHeight: null,
      connectedPeers,
      progress: 0,
    };
  }
  if (peerHeight > localHeight) {
    return {
      submitEnabled: true,
      badge: "SYNCHRONIZING",
      message: `Synchronizing ${localHeight} / ${peerHeight} (${progress}%).`,
      localHeight,
      peerHeight,
      connectedPeers,
      progress,
    };
  }
  return {
    submitEnabled: true,
    badge: "FINALIZING",
    message: `Validating Mainnet state at height ${localHeight}.`,
    localHeight,
    peerHeight: peerHeight || null,
    connectedPeers,
    progress,
  };
}

export function restoreScanPresentation(synchronization) {
  const active = synchronization?.seed_restore_in_progress === true;
  const cursorHeight = Number.isSafeInteger(synchronization?.cursor_height)
    ? synchronization.cursor_height
    : 0;
  const tipHeight = Number.isSafeInteger(synchronization?.tip_height)
    ? synchronization.tip_height
    : null;
  const reportedPercent = synchronization?.scan_progress_percent;
  const progress = Number.isSafeInteger(reportedPercent)
    ? Math.min(100, Math.max(0, reportedPercent))
    : tipHeight != null && tipHeight > 0
      ? Math.min(100, Math.floor((cursorHeight * 100) / tipHeight))
      : 0;
  const partial = synchronization?.partial_balance;
  const partialNoms = Number.isSafeInteger(partial)
    ? partial
    : Number.isSafeInteger(partial?.confirmed)
      ? partial.confirmed
      : Number.isSafeInteger(partial?.total)
        ? partial.total
        : null;
  if (!active) {
    return {
      active: false,
      message: null,
      progress,
      cursorHeight,
      tipHeight,
      partialBalanceText: null,
    };
  }
  return {
    active: true,
    message: tipHeight != null
      ? `Restored — scanning block ${cursorHeight} of ${tipHeight} (${progress}%)`
      : `Restored — scanning block ${cursorHeight}`,
    progress,
    cursorHeight,
    tipHeight,
    partialBalanceText: partialNoms == null
      ? "Partial balance: unavailable"
      : `Partial balance: ${formatDomFromNoms(partialNoms)}`,
  };
}

export function remoteTipAlertPresentation(synchronization) {
  const active = synchronization?.remote_tip_alert === true;
  return {
    active,
    message: active
      ? "Remote node alert: the reported chain tip regressed or is inconsistent. Verify your remote node before trusting balances."
      : null,
  };
}

export function chainSourceTlsWarning(baseUrl) {
  if (typeof baseUrl !== "string" || baseUrl.trim() === "") return false;
  let parsed;
  try {
    parsed = new URL(baseUrl.trim());
  } catch {
    return true;
  }
  if (parsed.protocol === "https:") return false;
  const host = parsed.hostname.toLowerCase();
  const isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
  return !isLocal;
}

export function chainSourcePresentation(value) {
  const source = value?.source === "REMOTE" ? "REMOTE" : "EMBEDDED";
  const baseUrl = typeof value?.base_url === "string" && value.base_url !== ""
    ? value.base_url
    : null;
  const tlsWarning = value?.tls_warning === true
    || (source === "REMOTE" && chainSourceTlsWarning(baseUrl ?? ""));
  return {
    source,
    baseUrl,
    hasBearerToken: value?.has_bearer_token === true,
    tlsWarning,
    message: source === "REMOTE"
      ? `Remote node (fast): ${baseUrl ?? "no URL configured"}`
      : "Local full node (default): the embedded node validates the entire chain.",
  };
}

export function liveStatusProjection(summary, node, network, peers, synchronization) {
  const nodeHeight = Number.isSafeInteger(node?.canonical_tip_height)
    ? node.canonical_tip_height
    : undefined;
  const networkHeight = Number.isSafeInteger(network?.canonical_height)
    ? network.canonical_height
    : undefined;
  const canonicalHeight = nodeHeight ?? networkHeight;
  const connectedPeers = Number.isSafeInteger(node?.connected_peers)
    ? node.connected_peers
    : Number.isSafeInteger(peers?.total_connected_peers)
      ? peers.total_connected_peers
      : undefined;
  const highestPeerHeight = Number.isSafeInteger(node?.highest_known_peer_height)
    ? node.highest_known_peer_height
    : Number.isSafeInteger(peers?.highest_known_peer_height)
      ? peers.highest_known_peer_height
      : undefined;
  const cursorHeight = synchronization?.cursor_height ?? summary?.cursor_height ?? null;

  const effectiveNetwork = canonicalHeight == null
    ? undefined
    : {
        canonical_height: canonicalHeight,
        lifecycle: node?.lifecycle,
        status_message: node?.status_message,
      };
  const effectivePeers = canonicalHeight == null
    ? undefined
    : {
        highest_known_peer_height: highestPeerHeight,
        total_connected_peers: connectedPeers,
      };
  const effectiveSynchronization = canonicalHeight == null
    ? undefined
    : synchronization ?? {
        cursor_height: cursorHeight,
        synchronized: false,
        last_error: null,
      };
  const synchronizationState = effectiveNetwork && effectivePeers && effectiveSynchronization
    ? synchronizationPresentation(
        effectiveNetwork,
        effectivePeers,
        effectiveSynchronization,
      )
    : undefined;

  return {
    badgeState: synchronizationState?.badgeState
      ?? (canonicalHeight == null ? "NODE UNAVAILABLE" : "PREPARING"),
    message: synchronizationState?.message
      ?? (canonicalHeight == null
        ? "Waiting for the embedded node"
        : "Waiting for wallet synchronization status"),
    synchronizationState,
    canonicalHeight,
    cursorHeight,
    connectedPeers,
    highestPeerHeight,
    chainId: node?.chain_id ?? network?.chain_id,
    genesisHash: node?.genesis_hash ?? network?.genesis_hash,
    dataDirectory: network?.data_directory,
    bootstrapPhase: node?.bootstrap_phase ?? peers?.bootstrap_phase,
  };
}

export function miningPresentation(mining, node) {
  const lifecycle = node?.lifecycle ?? "NOT_READY";
  const nodeReady = (lifecycle === "READY" || lifecycle === "CONNECTED_AT_GENESIS")
    && node?.ready === true;
  if (!nodeReady) {
    return {
      status: lifecycle === "SYNCHRONIZING" ? "SYNCHRONIZING" : "NODE NOT READY",
      canStart: false,
      warning: node?.status_message ?? "The node must be ready before mining can start.",
    };
  }
  return {
    status: mining.status,
    // WAITING_FOR_SYNCHRONIZATION means the worker is alive and will resume on
    // its own, so Start must stay disabled — the backend rejects it as
    // MINING_RUNNING anyway, and offering it would look like mining is off.
    canStart: mining.enabled === true
      && mining.running !== true
      && mining.status !== "WAITING_FOR_SYNCHRONIZATION",
    warning: mining.current_height === 0
      ? "Starting mining may produce the first post-genesis Mainnet block."
      : null,
  };
}

export function nodeStatusText(value) {
  const localHeight = value.canonical_tip_height ?? "—";
  const peerHeight = value.highest_known_peer_height ?? "—";
  const progress = value.synchronization_progress_percent == null
    ? "—"
    : `${value.synchronization_progress_percent}%`;
  return [
    value.status_message,
    `Lifecycle: ${value.lifecycle}`,
    `Network: ${value.network ?? "—"}`,
    `Local height: ${localHeight}`,
    `Highest peer height: ${peerHeight}`,
    `Synchronization: ${progress}`,
    `Connected peers: ${value.connected_peers}`,
    `Bootstrap: ${value.bootstrap_phase}`,
    `Canonical hash: ${value.canonical_tip_hash ?? "—"}`,
    `Error: ${value.error_code ?? "None"}`,
  ].join("\n");
}

export function formatDomFromNoms(value) {
  if (!Number.isSafeInteger(value) || value < 0) return "Unavailable";
  const noms = BigInt(value);
  const unit = 100_000_000n;
  const whole = noms / unit;
  const fraction = String(noms % unit).padStart(8, "0");
  return `${whole}.${fraction} DOM`;
}
