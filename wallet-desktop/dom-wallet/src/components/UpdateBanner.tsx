import type { UpdateInfo } from "../lib/tauri";

interface Props {
  update: UpdateInfo | null;
  onDismiss: () => void;
}

/** Update banner. Mandatory (hard-fork) updates are red and not dismissible. */
export function UpdateBanner({ update, onDismiss }: Props) {
  if (!update || !update.newer) return null;

  const open = () => {
    // Open the release page in the OS browser. We never download/execute code
    // here — the user applies the signed installer themselves.
    window.open(update.html_url, "_blank");
  };

  if (update.mandatory) {
    return (
      <div className="banner mandatory">
        <span>⚠</span>
        <span className="grow">
          <strong>Critical update required.</strong> Version {update.latest} is
          a mandatory hard-fork release. Update before the deadline to stay on
          the network.
        </span>
        <button className="primary" onClick={open}>
          Update now
        </button>
      </div>
    );
  }

  return (
    <div className="banner update">
      <span className="grow">
        A new version is available: <strong>{update.latest}</strong> (you have{" "}
        {update.current}).
      </span>
      <button onClick={open}>View release</button>
      <button className="ghost" onClick={onDismiss}>
        Dismiss
      </button>
    </div>
  );
}
