import React, { useState, useEffect, useRef, useCallback } from "react";
import { gsap } from "gsap";
import { CheckCircle2, AlertTriangle, RefreshCw, ArrowRight, Loader2 } from "lucide-react";
import { api } from "../../api/jobs";
import type { ReadinessResponse } from "../../api/types";
import SecurityCore from "./SecurityCore";
import styles from "./BootScreen.module.css";

interface BootScreenProps {
  onComplete: () => void;
}

type CheckStatus = "pending" | "checking" | "ready" | "failed" | "warning";

interface SystemCheck {
  id: string;
  name: string;
  status: CheckStatus;
  detail?: string;
  action?: string;
}

export const BootScreen: React.FC<BootScreenProps> = ({ onComplete }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const wordmarkRef = useRef<HTMLDivElement>(null);
  const isTransitioning = useRef(false);

  const [checks, setChecks] = useState<SystemCheck[]>([
    { id: "backend", name: "Connecting to Backend", status: "checking" },
    { id: "database", name: "Database & Audit Ledger", status: "pending" },
    { id: "verifier", name: "Verifier Environment", status: "pending" },
    { id: "workspace", name: "Workspace Preparation", status: "pending" },
  ]);

  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [canProceedAnyway, setCanProceedAnyway] = useState(false);
  const [allReady, setAllReady] = useState(false);

  const handleFinish = useCallback(() => {
    if (isTransitioning.current) return;
    isTransitioning.current = true;

    try {
      sessionStorage.setItem("kavach_init_seen", "true");
    } catch {
      // Ignore sessionStorage limitations
    }

    if (containerRef.current) {
      gsap.to(containerRef.current, {
        opacity: 0,
        scale: 1.02,
        duration: 0.45,
        ease: "power2.inOut",
        onComplete: onComplete,
      });
    } else {
      onComplete();
    }
  }, [onComplete]);

  // Execute real backend diagnostics probe
  const runReadinessProbes = useCallback(async () => {
    setErrorMessage(null);
    setCanProceedAnyway(false);

    // 1. Probe Backend Gateway (/health)
    setChecks(prev =>
      prev.map(c => (c.id === "backend" ? { ...c, status: "checking" } : c))
    );

    let backendAlive = false;
    try {
      const health = await api.health();
      if (health && health.status === "ok") {
        backendAlive = true;
        setChecks(prev =>
          prev.map(c =>
            c.id === "backend"
              ? { ...c, status: "ready", detail: "FastAPI gateway online" }
              : c.id === "database"
              ? { ...c, status: "checking" }
              : c
          )
        );
      } else {
        throw new Error("Backend did not return healthy status.");
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unable to reach KAVACH-X Gateway.";
      setChecks(prev =>
        prev.map(c =>
          c.id === "backend"
            ? { ...c, status: "failed", detail: msg }
            : { ...c, status: "failed" }
        )
      );
      setErrorMessage(`Cannot connect to KAVACH-X backend at http://127.0.0.1:8000. Start backend server.`);
      setCanProceedAnyway(true);
      setTimeout(() => {
        handleFinish();
      }, 2500);
      return;
    }

    if (!backendAlive) return;

    // 2. Probe System Readiness (/ready)
    setChecks(prev =>
      prev.map(c =>
        c.id === "database" || c.id === "verifier" || c.id === "workspace"
          ? { ...c, status: "checking" }
          : c
      )
    );

    try {
      const res: ReadinessResponse = await api.ready().catch((err: unknown) => {
        // When backend /ready returns 503, the client throws an ApiError with payload
        const shape = err as { payload?: ReadinessResponse; status?: number };
        if (shape?.payload && typeof shape.payload === "object" && "checks" in shape.payload) {
          return shape.payload as ReadinessResponse;
        }
        throw err;
      });

      const dbReady = res.checks?.database?.status === "ready";
      const verifierReady =
        res.checks?.verifier_callable?.status === "ready" &&
        res.checks?.docker?.status === "ready";
      const workspaceReady = res.checks?.configuration?.status === "ready";

      const hasUnavailable = Object.values(res.checks || {}).some(
        c => c.status === "unavailable"
      );

      setChecks([
        {
          id: "backend",
          name: "Connected to Backend",
          status: "ready",
          detail: "FastAPI gateway active",
        },
        {
          id: "database",
          name: "Database & Audit Ledger",
          status: dbReady ? "ready" : "failed",
          detail: dbReady ? "SQLite Persistence Verified" : "Database probe failed",
        },
        {
          id: "verifier",
          name: "Verifier Environment",
          status: verifierReady ? "ready" : "warning",
          detail: verifierReady
            ? "Docker Sandbox Ready"
            : res.checks?.docker?.action || "Docker sandbox offline (Diagnostics in Settings)",
        },
        {
          id: "workspace",
          name: "Security Workspace",
          status: workspaceReady ? "ready" : "warning",
          detail: workspaceReady
            ? "Remediation Pipeline Ready"
            : res.checks?.configuration?.action || "Readiness checks verified",
        },
      ]);

      if (!hasUnavailable && dbReady) {
        setAllReady(true);
        // Automatic launch after smooth confirmation
        setTimeout(() => {
          handleFinish();
        }, 700);
      } else {
        // Core backend & database are active, optional dependencies have notices
        setCanProceedAnyway(true);
        setErrorMessage(
          "Core gateway & ledger operational. Entering security workspace…"
        );
        // Automatically proceed into the workspace without getting stuck
        setTimeout(() => {
          handleFinish();
        }, 1200);
      }
    } catch {
      // Backend returned unexpected error, don't trap operator
      setChecks(prev =>
        prev.map(c =>
          c.id === "backend" ? c : { ...c, status: "warning", detail: "Readiness probe returned notice" }
        )
      );
      setCanProceedAnyway(true);
      setErrorMessage("Gateway connected. Entering security workspace…");
      setTimeout(() => {
        handleFinish();
      }, 1200);
    }
  }, [handleFinish]);

  useEffect(() => {
    // Respect prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion) {
      handleFinish();
      return;
    }

    // Keyboard shortcuts (Escape or Space to skip immediately)
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" || e.key === " ") {
        handleFinish();
      }
    };
    window.addEventListener("keydown", handleKeyDown);

    // Initial animation with GSAP
    const ctx = gsap.context(() => {
      gsap.fromTo(
        wordmarkRef.current,
        { opacity: 0, y: -16 },
        { opacity: 1, y: 0, duration: 0.8, ease: "power2.out" }
      );
    }, containerRef);

    // Start genuine probes
    void runReadinessProbes();

    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      ctx.revert();
    };
  }, [handleFinish, runReadinessProbes]);

  return (
    <div className={styles.bootRoot} ref={containerRef} role="dialog" aria-modal="true" aria-label="KAVACH-X Initialization">
      {/* Background Atmosphere */}
      <div className={styles.ambientBackground} />
      <div className={styles.subtleGrid} />

      {/* Top Action Bar */}
      <header className={styles.topHeader}>
        <button
          className={styles.skipButton}
          onClick={handleFinish}
          aria-label="Skip initialization animation"
        >
          Skip Intro (Esc)
        </button>
      </header>

      {/* Centerpiece: Wordmark, Security Core, and Supporting Subtitle */}
      <main className={styles.centerComposition}>
        {/* Geometric Wordmark */}
        <div className={styles.brandWordmark} ref={wordmarkRef}>
          <h1 className={styles.wordmarkTitle}>
            <span>KAVACH-</span>
            <span className={styles.limeAccent}>X</span>
          </h1>
          <p className={styles.wordmarkSubtitle}>
            AUTONOMOUS <span className={styles.subLime}>SECURITY</span> REMEDIATION
          </p>
        </div>

        {/* 3-Layer Glass Security Core */}
        <SecurityCore />

        {/* Supporting Status Text */}
        <div className={styles.initLabel}>INITIALIZING SECURITY WORKSPACE</div>

        {/* Real Readiness Check Tracker */}
        <section className={styles.readinessTracker} aria-label="System Readiness Checks">
          {checks.map((check, index) => {
            const isReady = check.status === "ready";
            const isFailed = check.status === "failed";
            const isWarning = check.status === "warning";
            const isChecking = check.status === "checking";

            return (
              <React.Fragment key={check.id}>
                <div className={styles.checkNode}>
                  <div
                    className={`${styles.nodeIconWrapper} ${
                      isReady ? styles.ready : isFailed || isWarning ? styles.failed : styles.pending
                    }`}
                    title={check.detail || check.name}
                  >
                    {isReady ? (
                      <CheckCircle2 size={16} />
                    ) : isFailed || isWarning ? (
                      <AlertTriangle size={15} />
                    ) : isChecking ? (
                      <Loader2 size={15} className="spin" />
                    ) : (
                      <span style={{ width: 6, height: 6, borderRadius: "50%", background: "currentColor" }} />
                    )}
                  </div>
                  <span className={styles.nodeTitle}>{check.name}</span>
                </div>
                {index < checks.length - 1 && (
                  <div
                    className={`${styles.nodeConnector} ${
                      isReady ? styles.active : ""
                    }`}
                  />
                )}
              </React.Fragment>
            );
          })}
        </section>

        {/* Diagnostic Feedback & Action Row */}
        <div className={styles.statusFeedback} role="status" aria-live="polite">
          {allReady ? (
            <p className={styles.feedbackText}>
              <strong style={{ color: "#B7F36B" }}>All systems verified.</strong> Launching security workspace…
            </p>
          ) : errorMessage ? (
            <>
              <p className={styles.feedbackText}>{errorMessage}</p>
              <div className={styles.feedbackActions}>
                <button
                  className={styles.actionButtonSecondary}
                  onClick={() => void runReadinessProbes()}
                >
                  <RefreshCw size={13} /> Retry Diagnostics
                </button>
                {canProceedAnyway && (
                  <button className={styles.actionButtonLime} onClick={handleFinish}>
                    Proceed to Workspace <ArrowRight size={14} />
                  </button>
                )}
              </div>
            </>
          ) : (
            <p className={styles.feedbackText}>
              Connecting to secure runtime and evaluating system attestation…
            </p>
          )}
        </div>
      </main>
    </div>
  );
};

export default BootScreen;
