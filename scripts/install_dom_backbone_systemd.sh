#!/usr/bin/env bash
set -euo pipefail

UNIT_SOURCE="${UNIT_SOURCE:-deploy/dom-backbone.service}"
ENV_SOURCE="${ENV_SOURCE:-deploy/dom-backbone.env.example}"
DOC_SOURCE="${DOC_SOURCE:-docs/BACKBONE_SYSTEMD.md}"
UNIT_TARGET="${UNIT_TARGET:-/etc/systemd/system/dom-backbone.service}"
ENV_TARGET="${ENV_TARGET:-/etc/dom/backbone.env}"
DOC_TARGET="${DOC_TARGET:-/usr/local/share/doc/dom/BACKBONE_SYSTEMD.md}"
DATA_DIR="${DOM_BACKBONE_DATA_DIR:-/var/lib/dom-backbone}"
BIN_TARGET="${DOM_NODE_BIN:-/usr/local/bin/dom-node}"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "Missing required file: ${path}" >&2
    exit 1
  fi
}

install_dom_user() {
  if ! id -u dom >/dev/null 2>&1; then
    useradd --system --home-dir "${DATA_DIR}" --shell /usr/sbin/nologin dom
  fi
}

main() {
  require_root
  require_file "${UNIT_SOURCE}"
  require_file "${ENV_SOURCE}"
  require_file "${DOC_SOURCE}"

  if [[ ! -x "${BIN_TARGET}" ]]; then
    echo "Warning: ${BIN_TARGET} is not executable yet; install the release binary before start." >&2
  fi

  install_dom_user

  install -d -o dom -g dom -m 0750 "${DATA_DIR}"
  install -d -m 0755 /etc/dom
  install -d -m 0755 "$(dirname "${DOC_TARGET}")"

  install -m 0644 "${UNIT_SOURCE}" "${UNIT_TARGET}"
  install -m 0644 "${DOC_SOURCE}" "${DOC_TARGET}"

  if [[ -e "${ENV_TARGET}" ]]; then
    echo "Preserving existing ${ENV_TARGET}; compare it with ${ENV_SOURCE} manually."
  else
    install -m 0640 -o root -g dom "${ENV_SOURCE}" "${ENV_TARGET}"
    echo "Installed ${ENV_TARGET}. Review it before starting the service."
  fi

  systemctl daemon-reload
  systemctl enable dom-backbone.service

  cat <<'MSG'
Installed dom-backbone.service.

Next steps:
  1. Install/update /usr/local/bin/dom-node.
  2. Review /etc/dom/backbone.env.
  3. Open the configured P2P port in the host firewall.
  4. Start with: sudo systemctl start dom-backbone
  5. Check with: sudo systemctl status dom-backbone --no-pager
MSG
}

main "$@"
