import { useMemo, useState } from "react";
import { PasswordInput } from "../components/PasswordInput";
import { SeedPhraseDisplay } from "../components/SeedPhraseDisplay";
import { SeedPhraseInput, isLikelyValidPhrase } from "../components/SeedPhraseInput";
import {
  walletCreate,
  walletRecover,
  walletUnlock,
  errMessage,
} from "../lib/tauri";
import logo from "../assets/logo.png";

type Step =
  | "welcome"
  | "create-password"
  | "create-show-seed"
  | "create-confirm-seed"
  | "recover";

interface Props {
  onReady: () => void;
}

/** Password strength: 0..4. Mirrors the backend's UX gate (≥12 chars + classes). */
function strength(pw: string): { score: number; label: string; color: string } {
  let score = 0;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  score += classes >= 3 ? 1 : 0;
  score += classes === 4 && pw.length >= 16 ? 1 : 0;
  const labels = ["Too weak", "Weak", "Fair", "Good", "Strong"];
  const colors = ["#a04030", "#a04030", "#c9a14a", "#5a8a4a", "#5a8a4a"];
  return { score, label: labels[score], color: colors[score] };
}

export function Onboarding({ onReady }: Props) {
  const [step, setStep] = useState<Step>("welcome");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [recoverPhrase, setRecoverPhrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Three random word indices the user must re-type to confirm backup.
  const [challenge, setChallenge] = useState<number[]>([]);
  const [answers, setAnswers] = useState<Record<number, string>>({});

  const pwStrength = useMemo(() => strength(password), [password]);
  const passwordsMatch = password.length > 0 && password === confirm;
  const strongEnough = pwStrength.score >= 2 && password.length >= 12;

  const resetErr = () => setError("");

  const doCreate = async () => {
    resetErr();
    setBusy(true);
    try {
      const { mnemonic: phrase } = await walletCreate(password);
      setMnemonic(phrase);
      // pick 3 distinct indices in [0,24)
      const idx = new Set<number>();
      while (idx.size < 3) idx.add(Math.floor(Math.random() * 24));
      setChallenge([...idx].sort((a, b) => a - b));
      setStep("create-show-seed");
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const words = mnemonic.trim().split(/\s+/);
  const challengeOk = challenge.every(
    (i) => (answers[i] ?? "").trim().toLowerCase() === words[i],
  );

  const finishCreate = async () => {
    resetErr();
    setBusy(true);
    try {
      // Unlock to bring the wallet into an open+unlocked state for the app.
      await walletUnlock(password);
      // Scrub the mnemonic from memory now that the user confirmed it.
      setMnemonic("");
      setAnswers({});
      onReady();
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const doRecover = async () => {
    resetErr();
    if (!isLikelyValidPhrase(recoverPhrase)) {
      setError("Enter all 24 words of your recovery phrase.");
      return;
    }
    if (!passwordsMatch) {
      setError("Passwords do not match.");
      return;
    }
    if (!strongEnough) {
      setError("Choose a stronger password (12+ characters).");
      return;
    }
    setBusy(true);
    try {
      await walletRecover(password, recoverPhrase);
      await walletUnlock(password);
      setRecoverPhrase("");
      onReady();
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="center-screen">
      <div className="panel reveal">
        <img className="logo" src={logo} alt="DOM" />

        {step === "welcome" && (
          <>
            <h1 style={{ textAlign: "center", marginBottom: 4 }}>DOM Wallet</h1>
            <p className="muted" style={{ textAlign: "center", marginBottom: 24 }}>
              Mine and hold DOM with a full node built in.
            </p>
            <div className="col">
              <button className="primary" onClick={() => setStep("create-password")}>
                Create new wallet
              </button>
              <button onClick={() => setStep("recover")}>Recover from seed phrase</button>
            </div>
          </>
        )}

        {step === "create-password" && (
          <>
            <h2 style={{ marginBottom: 16 }}>Set a password</h2>
            <div className="col">
              <PasswordInput
                label="Password"
                value={password}
                onChange={setPassword}
                autoFocus
                placeholder="At least 12 characters"
              />
              {password.length > 0 && (
                <div>
                  <div className="strength">
                    <span
                      style={{
                        width: `${(pwStrength.score / 4) * 100}%`,
                        background: pwStrength.color,
                      }}
                    />
                  </div>
                  <span className="faint" style={{ fontSize: 12 }}>
                    {pwStrength.label}
                  </span>
                </div>
              )}
              <PasswordInput
                label="Confirm password"
                value={confirm}
                onChange={setConfirm}
                placeholder="Re-enter password"
              />
              {confirm.length > 0 && !passwordsMatch && (
                <span className="error-text">Passwords do not match.</span>
              )}
            </div>
            {error && <p className="error-text" style={{ marginTop: 12 }}>{error}</p>}
            <div className="row" style={{ marginTop: 20 }}>
              <button className="ghost" onClick={() => setStep("welcome")}>
                Back
              </button>
              <span style={{ flex: 1 }} />
              <button
                className="primary"
                disabled={busy || !passwordsMatch || !strongEnough}
                onClick={doCreate}
              >
                {busy ? "Creating…" : "Continue"}
              </button>
            </div>
          </>
        )}

        {step === "create-show-seed" && (
          <>
            <h2>Your recovery phrase</h2>
            <div className="warn-box">
              Write these 24 words down on paper and store them safely. They are the{" "}
              <strong>only</strong> way to recover your DOM if you lose access. Never share them,
              and never store them digitally.
            </div>
            <SeedPhraseDisplay phrase={mnemonic} />
            <div className="row" style={{ marginTop: 16 }}>
              <span style={{ flex: 1 }} />
              <button className="primary" onClick={() => setStep("create-confirm-seed")}>
                I&apos;ve written it down
              </button>
            </div>
          </>
        )}

        {step === "create-confirm-seed" && (
          <>
            <h2>Confirm your backup</h2>
            <p className="muted" style={{ marginBottom: 14 }}>
              Type the requested words to confirm you saved your phrase.
            </p>
            <div className="col">
              {challenge.map((i) => (
                <div key={i}>
                  <label>Word #{i + 1}</label>
                  <input
                    value={answers[i] ?? ""}
                    onChange={(e) => setAnswers((a) => ({ ...a, [i]: e.target.value }))}
                    style={{ fontFamily: "var(--font-mono)" }}
                  />
                </div>
              ))}
            </div>
            {error && <p className="error-text" style={{ marginTop: 12 }}>{error}</p>}
            <div className="row" style={{ marginTop: 20 }}>
              <button className="ghost" onClick={() => setStep("create-show-seed")}>
                Back
              </button>
              <span style={{ flex: 1 }} />
              <button className="primary" disabled={busy || !challengeOk} onClick={finishCreate}>
                {busy ? "Finishing…" : "Confirm & open wallet"}
              </button>
            </div>
          </>
        )}

        {step === "recover" && (
          <>
            <h2 style={{ marginBottom: 16 }}>Recover wallet</h2>
            <div className="col">
              <SeedPhraseInput value={recoverPhrase} onChange={setRecoverPhrase} />
              <PasswordInput
                label="New password"
                value={password}
                onChange={setPassword}
                placeholder="At least 12 characters"
              />
              <PasswordInput
                label="Confirm password"
                value={confirm}
                onChange={setConfirm}
              />
            </div>
            {error && <p className="error-text" style={{ marginTop: 12 }}>{error}</p>}
            <div className="row" style={{ marginTop: 20 }}>
              <button className="ghost" onClick={() => setStep("welcome")}>
                Back
              </button>
              <span style={{ flex: 1 }} />
              <button className="primary" disabled={busy} onClick={doRecover}>
                {busy ? "Recovering…" : "Recover wallet"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
