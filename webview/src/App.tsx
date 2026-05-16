import {
  VSCodeBadge,
  VSCodeDataGrid,
  VSCodeDataGridCell,
  VSCodeDataGridRow,
} from "@vscode/webview-ui-toolkit/react";
import { useCallback, useEffect, useState } from "react";
import "./App.css";
import { ITokenListItem, tokenListItems } from "./utilities/tokenListItems";
import { vscode } from "./utilities/vscode";

type Severity = "error" | "warning" | "info";

interface Finding {
  id: string;
  severity: Severity;
  message: string;
  docUrl?: string;
}

interface JwtPanelPayload {
  kind: "JWS" | "JWE" | "unknown";
  header: Record<string, unknown>;
  claims: Record<string, unknown> | null;
  findings: Finding[];
  isEncrypted: boolean;
}

const SEVERITY_STYLE: Record<Severity, { bg: string; fg: string; label: string }> = {
  error: { bg: "#5a1d1d", fg: "#ffb4b4", label: "ERROR" },
  warning: { bg: "#5a4a1d", fg: "#ffe39a", label: "WARN" },
  info: { bg: "#1d3a5a", fg: "#a8d4ff", label: "INFO" },
};

function FindingsBanner({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <section
      aria-label="Findings"
      style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 12 }}
    >
      {findings.map((f) => {
        const s = SEVERITY_STYLE[f.severity];
        return (
          <div
            key={f.id}
            style={{
              background: s.bg,
              color: s.fg,
              padding: "8px 12px",
              borderRadius: 4,
              fontSize: 13,
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <strong style={{ minWidth: 56 }}>{s.label}</strong>
            <span>{f.message}</span>
            {f.docUrl ? (
              <a href={f.docUrl} style={{ color: s.fg, marginLeft: "auto" }}>
                docs
              </a>
            ) : null}
          </div>
        );
      })}
    </section>
  );
}

function isJwtPanelPayload(value: unknown): value is JwtPanelPayload {
  return (
    typeof value === "object" &&
    value !== null &&
    "kind" in value &&
    "header" in value &&
    "findings" in value
  );
}

function App() {
  const [didInitialize, setDidInitialize] = useState<boolean>(false);
  const [payload, setPayload] = useState<JwtPanelPayload | undefined>();

  const onMessage = useCallback((event: MessageEvent) => {
    if (isJwtPanelPayload(event.data)) {
      setPayload(event.data);
    }
  }, []);

  useEffect(() => {
    window.addEventListener("message", onMessage);
    if (!didInitialize) {
      vscode.postMessage({ command: "onDidInitialize", text: undefined });
      setDidInitialize(true);
    }
    return () => window.removeEventListener("message", onMessage);
  }, [onMessage, didInitialize]);

  const claimRows: ITokenListItem[] = [];
  if (payload?.claims) {
    const rows = tokenListItems(JSON.stringify(payload.claims));
    for (const row of rows) {
      if (row.claimValue) {
        if (Array.isArray(row.claimValue)) {
          row.claimValue = row.claimValue.sort().map((c) => `🏷️ ${c}`).join("\n");
        } else {
          row.claimValue = `📦 ${row.claimValue}`;
        }
      }
      claimRows.push(row);
    }
  }

  return (
    <main>
      {payload ? <FindingsBanner findings={payload.findings} /> : null}

      {payload?.isEncrypted ? (
        <section
          style={{
            padding: 12,
            border: "1px solid #5a4a1d",
            borderRadius: 4,
            color: "#ffe39a",
            marginBottom: 12,
          }}
        >
          <strong>Encrypted payload (JWE)</strong> — claims cannot be displayed without a decryption key.
          Header below shows the encryption algorithms (<code>alg</code>, <code>enc</code>).
        </section>
      ) : null}

      {payload?.header ? (
        <section style={{ marginBottom: 16 }}>
          <h3 style={{ margin: "0 0 6px 0", fontSize: 13, opacity: 0.8 }}>JOSE Header</h3>
          <pre
            style={{
              background: "rgba(255,255,255,0.04)",
              padding: 8,
              borderRadius: 4,
              fontSize: 12,
              margin: 0,
            }}
          >
            {JSON.stringify(payload.header, null, 2)}
          </pre>
        </section>
      ) : null}

      {claimRows.length > 0 ? (
        <VSCodeDataGrid gridTemplateColumns="150px 650px" aria-label="Claims">
          <VSCodeDataGridRow rowType="sticky-header">
            <VSCodeDataGridCell cellType="columnheader" gridColumn="1">
              Claim
            </VSCodeDataGridCell>
            <VSCodeDataGridCell cellType="columnheader" gridColumn="2">
              Value
            </VSCodeDataGridCell>
            <VSCodeDataGridCell cellType="columnheader" gridColumn="3">
              Description
            </VSCodeDataGridCell>
          </VSCodeDataGridRow>
          {claimRows.map((claim) => (
            <VSCodeDataGridRow key={`row_${claim.claimName}`}>
              <VSCodeDataGridCell key={`claimName_${claim.claimName}`} gridColumn="1">
                <img
                  src={claim.claimIcon}
                  alt="logo"
                  style={{ height: 16, width: 16, marginRight: 8 }}
                />
                <VSCodeBadge>{claim.claimName}</VSCodeBadge>
              </VSCodeDataGridCell>
              <VSCodeDataGridCell
                style={{ whiteSpace: "pre-line" }}
                key={`claimValue_${claim.claimName}`}
                gridColumn="2"
              >
                {claim.claimValue}
              </VSCodeDataGridCell>
              <VSCodeDataGridCell
                key={`claimDescription_${claim.claimName}`}
                gridColumn="3"
              >
                {claim.claimDescription}
              </VSCodeDataGridCell>
            </VSCodeDataGridRow>
          ))}
        </VSCodeDataGrid>
      ) : null}
    </main>
  );
}

export default App;
