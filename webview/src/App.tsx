import {
  VSCodeBadge,
  VSCodeDataGrid,
  VSCodeDataGridCell,
  VSCodeDataGridRow,
} from "@vscode/webview-ui-toolkit/react";
import { useCallback, useEffect, useState } from "react";
import "./App.css";
import styles from "./App.module.css";
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

const SEVERITY_LABEL: Record<Severity, string> = {
  error: "ERROR",
  warning: "WARN",
  info: "INFO",
};

function FindingsBanner({ findings }: Readonly<{ findings: Finding[] }>) {
  if (findings.length === 0) return null;
  return (
    <section aria-label="Findings" className={styles.findingsBanner}>
      {findings.map((f) => (
        <div key={f.id} className={`${styles.finding} ${styles[f.severity]}`}>
          <strong className={styles.findingLabel}>{SEVERITY_LABEL[f.severity]}</strong>
          <span>{f.message}</span>
          {f.docUrl ? (
            <a href={f.docUrl} className={styles.findingDocLink}>
              docs
            </a>
          ) : null}
        </div>
      ))}
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
        <section className={styles.encryptedNotice}>
          <strong>Encrypted payload (JWE)</strong> — claims cannot be displayed without a decryption key.
          Header below shows the encryption algorithms (<code>alg</code>, <code>enc</code>).
        </section>
      ) : null}

      {payload?.header ? (
        <section className={styles.headerSection}>
          <h3 className={styles.headerTitle}>JOSE Header</h3>
          <pre className={styles.headerCode}>
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
                  className={styles.claimIcon}
                />
                <VSCodeBadge>{claim.claimName}</VSCodeBadge>
              </VSCodeDataGridCell>
              <VSCodeDataGridCell
                key={`claimValue_${claim.claimName}`}
                gridColumn="2"
              >
                <div className={styles.claimValueCell}>{claim.claimValue}</div>
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
