import { Bell, Search, Menu, Sparkles, LogOut, Shield, Compass } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "./OperatorSession";

const titles: Record<string, string> = {
  "/": "Launch Bay",
  "/mission": "Mission Control — Three Worlds",
  "/dashboard": "Command Center",
  "/overview": "Command Center",
  "/projects": "Target Repositories",
  "/findings": "Vulnerability Findings",
  "/investigation": "Unified Security Case",
  "/verification": "Adversarial Verification",
  "/activity": "Agent Audit Ledger",
  "/evidence": "Cryptographic Evidence",
  "/settings": "Readiness Diagnostics",
};

export default function Header({ onMenu }: { onMenu: () => void }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { session, logout } = useAuth();

  const title =
    titles[location.pathname] ||
    (location.pathname.startsWith("/jobs/") ? "Security Case Investigation" : "KAVACH-X");

  return (
    <header className="topbar">
      <button className="menu-trigger" onClick={onMenu} aria-label="Toggle navigation">
        <span className="menu-glyph">
          <Menu size={18} />
        </span>
        <span className="menu-word mono">FIELD GUIDE</span>
      </button>

      <div className="breadcrumbs mono">
        <span className="text-muted">KAVACH-X</span>
        <span className="crumb-slash">/</span>
        <strong>{title}</strong>
      </div>

      <div className="header-search">
        <Search size={16} className="search-icon" />
        <input
          aria-label="Search findings"
          placeholder="Search CVEs, findings, jobs, target files…"
          onKeyDown={e => {
            if (e.key === "Enter" && e.currentTarget.value.trim()) {
              navigate(`/findings?search=${encodeURIComponent(e.currentTarget.value.trim())}`);
            }
          }}
        />
        <span className="search-spark">
          <Sparkles size={13} />
        </span>
      </div>

      <div className="topbar-actions">
        <button
          className="icon-button"
          aria-label="Replay initialization sequence"
          title="Replay initialization sequence (BootScreen)"
          onClick={() => window.dispatchEvent(new CustomEvent("kavach:reboot"))}
        >
          <Compass size={16} />
        </button>

        <button
          className="icon-button"
          aria-label="Recent activity"
          title="Agent activity ledger"
          onClick={() => navigate("/activity")}
        >
          <Bell size={16} />
        </button>

        {session ? (
          <div className="operator-header-profile">
            <div className="operator-chip">
              <Shield size={13} className="text-lime" />
              <span className="operator-name mono">{session.user.email.split("@")[0]}</span>
            </div>
            <button
              className="icon-button disconnect-btn"
              aria-label="Log out"
              title="Terminate operator session"
              onClick={() => void logout()}
            >
              <LogOut size={15} />
            </button>
          </div>
        ) : (
          <button className="button button-lime-sm" onClick={() => navigate("/")}>
            Connect
          </button>
        )}
      </div>
    </header>
  );
}