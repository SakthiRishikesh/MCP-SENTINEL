import { useEffect, useRef, useState } from "react";
import { api, fetchFile, usePoll } from "../api.js";
import { Card, Empty, Pill } from "./ui.jsx";

const KIND_ICON = { decision: "⚖", sandbox: "⧉", approval: "✋", files: "🗂", event: "⚑" };

/** Step-by-step replay of everything Sentinel recorded for one workflow, plus signed exports. */
export function WorkflowReplay({ workflowId }) {
  const report = usePoll(() => api.get(`/v1/workflows/${encodeURIComponent(workflowId)}/report`), [workflowId], 10000);
  const [step, setStep] = useState(-1);
  const [playing, setPlaying] = useState(false);
  const timer = useRef(null);
  const items = report.data?.timeline || [];

  useEffect(() => {
    if (!playing) return undefined;
    timer.current = setInterval(() => {
      setStep((s) => {
        if (s + 1 >= items.length) {
          setPlaying(false);
          return s;
        }
        return s + 1;
      });
    }, 900);
    return () => clearInterval(timer.current);
  }, [playing, items.length]);

  const r = report.data;
  if (!r) return <Card title="Replay"><Empty>{report.error || "Loading…"}</Empty></Card>;
  const shown = step < 0 ? items : items.slice(0, step + 1);
  const s = r.summary;
  const file = (fmt) => fetchFile(`/v1/workflows/${encodeURIComponent(workflowId)}/report.${fmt}?download=1`,
    { filename: `incident-${workflowId.slice(0, 24)}.${fmt}` });
  return (
    <Card title="Replay & incident report"
      subtitle={`${s.calls} calls · ${s.blocked} blocked · ${s.escalated} sent to a person · ${s.receipts_verified}/${s.receipts_total} receipts verified`}
      actions={(
        <div className="row gap">
          <button className="btn btn-sm" onClick={() => { if (step >= items.length - 1 || step < 0) setStep(0); setPlaying(!playing); }}>{playing ? "Pause" : step >= 0 && step < items.length - 1 ? "Resume" : "▶ Replay"}</button>
          {step >= 0 && <button className="btn btn-sm" onClick={() => { setPlaying(false); setStep(-1); }}>Show all</button>}
          <button className="btn btn-sm" onClick={() => file("html")}>Export HTML</button>
          <button className="btn btn-sm" onClick={() => file("json")}>JSON</button>
        </div>
      )}>
      {items.length === 0 ? <Empty>Nothing recorded for this workflow.</Empty> : (
        <ol className="replay">
          {shown.map((t, i) => (
            <li key={`${t.ref}-${i}`} className={`replay-item sev-${t.severity} ${i === step ? "current" : ""}`}>
              <span className="replay-icon" aria-hidden="true">{KIND_ICON[t.kind] || "•"}</span>
              <div className="grow">
                <div className="row gap wrap">
                  <strong>{t.title}</strong>
                  {t.risk != null && <span className="chip">risk {t.risk}</span>}
                  {t.verified === false && <Pill value="REJECTED" title="receipt signature check failed" />}
                  <span className="muted small mono">{(t.at || "").slice(11, 19)}</span>
                </div>
                {t.detail && <div className="small muted">{t.detail}</div>}
                {(t.preview?.files || []).length > 0 && (
                  <ul className="small mono">{t.preview.files.slice(0, 5).map((f, j) => <li key={j}>{f.change}: {f.path}</li>)}</ul>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}
      <p className="muted small">The exported report re-verifies every receipt (SHA-256 chain + Ed25519) and is itself signed with Sentinel's receipt key, so it holds up as evidence after it leaves the dashboard.</p>
    </Card>
  );
}
