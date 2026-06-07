import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { onLogLine } from "../lib/events";
import { logsSnapshot, logsExport, errMessage, type LogLine } from "../lib/tauri";
import { formatLogTime } from "../lib/format";

const LEVELS = ["All", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"] as const;
type LevelFilter = (typeof LEVELS)[number];

/** UI-side ring buffer cap (backend keeps up to 10k for export). */
const UI_MAX = 1000;

const levelClass = (lvl: string): string => {
  switch (lvl.toUpperCase()) {
    case "ERROR":
      return "error";
    case "WARN":
      return "warn";
    case "INFO":
      return "info";
    case "DEBUG":
      return "debug";
    default:
      return "trace";
  }
};

export function LogStream() {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [level, setLevel] = useState<LevelFilter>("All");
  const [targetFilter, setTargetFilter] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [paused, setPaused] = useState(false);
  const [notice, setNotice] = useState<string>("");

  const windowRef = useRef<HTMLDivElement>(null);
  // Hold incoming lines while paused, flush on resume.
  const pausedBuffer = useRef<LogLine[]>([]);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  // Initial history snapshot.
  useEffect(() => {
    logsSnapshot(UI_MAX)
      .then(setLines)
      .catch((e) => setNotice(errMessage(e)));
  }, []);

  // Live subscription.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    onLogLine((line) => {
      if (pausedRef.current) {
        pausedBuffer.current.push(line);
        return;
      }
      setLines((prev) => {
        const next = prev.length >= UI_MAX ? prev.slice(prev.length - UI_MAX + 1) : prev.slice();
        next.push(line);
        return next;
      });
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  // Auto-scroll to bottom when new lines arrive (unless user scrolled up).
  useEffect(() => {
    if (autoScroll && windowRef.current) {
      windowRef.current.scrollTop = windowRef.current.scrollHeight;
    }
  }, [lines, autoScroll]);

  // Detect manual scroll: disengage auto-scroll when leaving the bottom,
  // re-engage when scrolled back to the bottom.
  const onScroll = useCallback(() => {
    const el = windowRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    setAutoScroll(atBottom);
  }, []);

  const togglePause = () => {
    if (paused) {
      // Flush buffered lines on resume.
      setLines((prev) => {
        const merged = prev.concat(pausedBuffer.current);
        pausedBuffer.current = [];
        return merged.length > UI_MAX ? merged.slice(merged.length - UI_MAX) : merged;
      });
    }
    setPaused((p) => !p);
  };

  const clear = () => setLines([]);

  const doExport = async () => {
    try {
      const path = await save({
        title: "Export logs",
        defaultPath: `dom-node-logs-${Date.now()}.txt`,
        filters: [{ name: "Text", extensions: ["txt"] }],
      });
      if (!path) return;
      const n = await logsExport(path, 10_000);
      setNotice(`Exported ${n} lines.`);
    } catch (e) {
      setNotice(errMessage(e));
    }
  };

  const visible = useMemo(() => {
    return lines.filter((l) => {
      if (level !== "All" && l.level.toUpperCase() !== level) return false;
      if (targetFilter && !l.target.toLowerCase().includes(targetFilter.toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [lines, level, targetFilter]);

  return (
    <div>
      <div className="log-toolbar">
        <span className="muted" style={{ fontSize: 12 }}>
          Filter:
        </span>
        <select value={level} onChange={(e) => setLevel(e.target.value as LevelFilter)}>
          {LEVELS.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
        <input
          placeholder="target (e.g. dom_node)"
          value={targetFilter}
          onChange={(e) => setTargetFilter(e.target.value)}
        />
        <label className="toggle">
          <input
            type="checkbox"
            style={{ width: "auto" }}
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
          />
          Auto-scroll
        </label>
        <span style={{ flex: 1 }} />
        <button onClick={togglePause}>{paused ? "Resume stream" : "Pause stream"}</button>
        <button onClick={clear}>Clear</button>
        <button onClick={doExport}>Export</button>
      </div>

      {notice && (
        <div className="faint" style={{ fontSize: 12, marginBottom: 6 }}>
          {notice}
        </div>
      )}

      <div className="log-window" ref={windowRef} onScroll={onScroll}>
        {visible.length === 0 ? (
          <div className="faint">No log lines yet. Start the node to see live output.</div>
        ) : (
          visible.map((l, i) => (
            <div className={`log-line ${levelClass(l.level)}`} key={`${l.timestamp}-${i}`}>
              <span className="ts">{formatLogTime(l.timestamp)}</span>
              <span className="lvl">{l.level.toUpperCase()}</span>
              <span className="tgt">{l.target}</span>
              <span className="msg">{l.message}</span>
            </div>
          ))
        )}
      </div>
      {paused && (
        <div className="faint" style={{ fontSize: 12, marginTop: 6 }}>
          Stream paused — {pausedBuffer.current.length} line(s) buffered. Logging continues in the
          background.
        </div>
      )}
    </div>
  );
}
