import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, ShieldCheck, Terminal, Cpu, Database, ChevronRight, Activity, Play } from "lucide-react";
import { gsap } from "gsap";
import DataCrystal from "../components/DataCrystal";
import { useAuth } from "../components/OperatorSession";
import { api } from "../api/jobs";

export default function LaunchBay() {
  const navigate = useNavigate();
  const { session, requireAuth, openModal } = useAuth();
  const rootRef = useRef<HTMLDivElement>(null);
  const [stats, setStats] = useState<{ jobsCount: number; verifiedCount: number; status: string }>({
    jobsCount: 0,
    verifiedCount: 0,
    status: "STANDBY",
  });
  const [isLaunching, setIsLaunching] = useState(false);

  useEffect(() => {
    let active = true;
    api.jobs(50, 0)
      .then(jobs => {
        if (!active) return;
        const verified = jobs.filter(j => j.status === "VERIFIED").length;
        setStats({
          jobsCount: jobs.length,
          verifiedCount: verified,
          status: "ONLINE",
        });
      })
      .catch(() => {
        if (active) setStats(s => ({ ...s, status: "READY" }));
      });
    return () => {
      active = false;
    };
  }, []);

  // GSAP Entrance Choreography
  useEffect(() => {
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion || !rootRef.current) return;

    const ctx = gsap.context(() => {
      const tl = gsap.timeline({ defaults: { ease: "power3.out" } });
      tl.from(".launch-header", { y: -25, opacity: 0, duration: 0.6 })
        .from(".hero-eyebrow", { y: 15, opacity: 0, duration: 0.4 }, "-=0.3")
        .from(".hero-headline", { y: 20, opacity: 0, duration: 0.5 }, "-=0.25")
        .from(".hero-copy", { y: 15, opacity: 0, duration: 0.4 }, "-=0.2")
        .from(".hero-actions", { y: 10, opacity: 0, duration: 0.4 }, "-=0.2")
        .from(".hero-metrics-strip", { y: 20, opacity: 0, duration: 0.4 }, "-=0.2")
        .from(".briefing-card", { y: 25, opacity: 0, stagger: 0.1, duration: 0.5 }, "-=0.25");
    }, rootRef);

    return () => ctx.revert();
  }, []);

  const handleLaunchMission = () => {
    setIsLaunching(true);
    setTimeout(() => {
      requireAuth(() => navigate("/mission"));
      setIsLaunching(false);
    }, 450);
  };

  const handleOpenConsole = () => {
    requireAuth(() => navigate("/dashboard"));
  };

  const handleReboot = () => {
    window.dispatchEvent(new CustomEvent("kavach:reboot"));
  };

  return (
    <div className={`launch-bay-root ${isLaunching ? "launch-sequence-active" : ""}`} ref={rootRef}>
      {/* Background Spatial Atmosphere & Terrain Grid */}
      <div className="spatial-stars" aria-hidden="true" />
      <div className="spatial-nebula" aria-hidden="true" />
      <div className="spatial-horizon-grid" aria-hidden="true" />

      {/* Top Editorial Navigation */}
      <header className="launch-header">
        <div className="launch-brand">
          <div className="launch-brand-mark">
            <ShieldCheck size={20} />
          </div>
          <div className="launch-brand-text">
            <span className="brand-title">KAVACH-X</span>
            <span className="brand-subtitle">EDITORIAL SCI-FI SECURITY</span>
          </div>
        </div>

        <div className="launch-telemetry mono">
          <span className="telemetry-item">
            <span className="telemetry-dot" />
            <span>SYS_CORE: {stats.status}</span>
          </span>
          <span className="telemetry-divider">/</span>
          <span className="telemetry-item">
            <span>ISOLATION: DOCKER_LAB</span>
          </span>
          <span className="telemetry-divider">/</span>
          <span className="telemetry-item">
            <span>HASH: SHA-256 CANONICAL</span>
          </span>
        </div>

        <div className="launch-header-actions">
          <button
            className="button button-ghost-sm mono"
            onClick={handleReboot}
            title="Replay initialization sequence"
            style={{ fontSize: "11px", gap: "6px" }}
          >
            <Play size={12} className="text-lime" />
            <span>INIT SEQ</span>
          </button>

          {session ? (
            <div className="launch-operator-pill">
              <span className="operator-indicator" />
              <span className="mono operator-email">{session.user.email}</span>
              <button
                className="button button-ghost-sm"
                onClick={handleOpenConsole}
                title="Enter Security Console"
              >
                Console <ChevronRight size={14} />
              </button>
            </div>
          ) : (
            <button className="button button-outline-lime" onClick={() => openModal("login")}>
              Operator Sign In
            </button>
          )}
        </div>
      </header>

      {/* Main Hero Spatial Composition */}
      <main className="launch-hero-section">
        <div className="launch-hero-content">
          <div className="hero-eyebrow">
            <span className="eyebrow-accent mono">MISSION DIRECTIVE 01</span>
            <span className="eyebrow-line" />
            <span className="mono text-muted">BOLA & ZERO-TRUST AUTONOMY</span>
          </div>

          <h1 className="hero-headline">
            Find the Vulnerability.
            <br />
            <span className="headline-lime-serif">Prove the Fix.</span>
          </h1>

          <p className="hero-copy">
            AI-assisted security remediation with explicit human approval, independent verification,
            and evidence you can inspect.
          </p>

          <div className="hero-actions">
            <button
              className="button button-lime button-large launch-primary-btn"
              onClick={handleLaunchMission}
              id="launch-mission-cta"
            >
              <Terminal size={18} />
              <span>Launch Security Mission</span>
              <ArrowRight size={18} />
            </button>

            <button
              className="button button-orbit button-large launch-secondary-btn"
              onClick={handleOpenConsole}
              id="open-console-cta"
            >
              <Cpu size={18} />
              <span>Open Security Console</span>
            </button>
          </div>

          {/* Quick Real-Time Metrics Strip */}
          <div className="hero-metrics-strip">
            <div className="hero-metric-cell">
              <span className="metric-label mono">IDENTIFIED JOBS</span>
              <strong className="metric-val mono">{stats.jobsCount || "—"}</strong>
              <small className="metric-sub">Active repository cases</small>
            </div>
            <div className="metric-cell-divider" />
            <div className="hero-metric-cell">
              <span className="metric-label mono">VERIFIED PROOFS</span>
              <strong className="metric-val lime mono">{stats.verifiedCount || "—"}</strong>
              <small className="metric-sub">Tested against protected suite</small>
            </div>
            <div className="metric-cell-divider" />
            <div className="hero-metric-cell">
              <span className="metric-label mono">ATTESTATION</span>
              <strong className="metric-val mono text-coral">STRICT HASH</strong>
              <small className="metric-sub">Tamper-proof approval binding</small>
            </div>
          </div>
        </div>

        {/* Floating Geometric Data Crystal Showcase */}
        <div className="launch-hero-visual">
          <DataCrystal />
        </div>
      </main>

      {/* Three Mission Pillars Briefing Cards */}
      <section className="launch-briefing-grid">
        <div className="briefing-card" onClick={() => requireAuth(() => navigate("/findings"))}>
          <div className="briefing-card-top">
            <span className="briefing-num mono">01 // DISCOVER</span>
            <Activity size={18} className="briefing-icon" />
          </div>
          <h3 className="briefing-title">Autonomous Intake</h3>
          <p className="briefing-desc">
            Deep AST scanning & BOLA defect identification. Ingests raw repository archives into bounded,
            auditable finding cases.
          </p>
          <div className="briefing-link mono">
            EXPLORE FINDINGS <ArrowRight size={14} />
          </div>
        </div>

        <div className="briefing-card" onClick={() => requireAuth(() => navigate("/investigation"))}>
          <div className="briefing-card-top">
            <span className="briefing-num mono">02 // REMEDIATE</span>
            <Cpu size={18} className="briefing-icon text-amber" />
          </div>
          <h3 className="briefing-title">AI Patch Generation</h3>
          <p className="briefing-desc">
            Qwen 2.5 Coder generates minimal, context-bounded candidate diffs tied to canonical SHA-256
            patch hashes requiring operator authorization.
          </p>
          <div className="briefing-link mono">
            REVIEW WORKSPACE <ArrowRight size={14} />
          </div>
        </div>

        <div className="briefing-card" onClick={() => requireAuth(() => navigate("/verification"))}>
          <div className="briefing-card-top">
            <span className="briefing-num mono">03 // VERIFY</span>
            <Database size={18} className="briefing-icon text-lime" />
          </div>
          <h3 className="briefing-title">Adversarial Lab</h3>
          <p className="briefing-desc">
            Isolated Docker containers execute 8 protected test suites. Only independent verification
            outcomes establish proof of remediation.
          </p>
          <div className="briefing-link mono">
            INSPECT ATTESTATIONS <ArrowRight size={14} />
          </div>
        </div>
      </section>

      {/* Launch Bay Footer */}
      <footer className="launch-footer">
        <div className="footer-left mono">
          <span>KAVACH-X SECURITY LAB</span>
          <span className="footer-sep">·</span>
          <span>BEYONDSIGHT</span>
          <span className="footer-sep">·</span>
          <span>NEATHACK 2026</span>
        </div>
        <div className="footer-right mono">
          <span className="status-live-dot" />
          <span>INDEPENDENT VERIFICATION ENGINE AUTHORIZED</span>
        </div>
      </footer>
    </div>
  );
}
