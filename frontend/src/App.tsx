import { useEffect, useState } from "react";
import { Route, Routes, useParams, useLocation } from "react-router-dom";
import { AlertCircle, X } from "lucide-react";
import Sidebar from "./components/Sidebar";
import Header from "./components/Header";
import BootScreen from "./components/BootScreen/BootScreen";
import LaunchBay from "./pages/LaunchBay";
import MissionControl from "./pages/MissionControl";
import Dashboard from "./pages/Dashboard";
import Projects from "./pages/Projects";
import Findings from "./pages/Findings";
import Investigation from "./pages/Investigation";
import Evidence from "./pages/Evidence";
import Verification from "./pages/Verification";
import Settings from "./pages/Settings";
import ActivityPage from "./pages/Activity";
import PatchLab from "./pages/PatchLab";

function JobRoute() {
  const { jobId } = useParams();
  return <Investigation key={jobId} />;
}

export default function App() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [showBoot, setShowBoot] = useState(() => !sessionStorage.getItem("kavach_init_seen"));
  const location = useLocation();

  // Listen for reboot trigger event
  useEffect(() => {
    const handleReboot = () => setShowBoot(true);
    window.addEventListener("kavach:reboot", handleReboot);
    return () => window.removeEventListener("kavach:reboot", handleReboot);
  }, []);

  // Close mobile drawer on route change
  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  if (showBoot) {
    return <BootScreen onComplete={() => setShowBoot(false)} />;
  }

  const isLaunchBay = location.pathname === "/";

  if (isLaunchBay) {
    return <LaunchBay />;
  }

  return (
    <div className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
      <div
        className={`sidebar-overlay ${mobileOpen ? "visible" : ""}`}
        onClick={() => setMobileOpen(false)}
        aria-hidden="true"
      />
      <div className={`app-sidebar ${mobileOpen ? "mobile-open" : ""}`}>
        <button
          className="mobile-close icon-button"
          onClick={() => setMobileOpen(false)}
          aria-label="Close navigation"
        >
          <X size={17} />
        </button>
        <Sidebar />
      </div>
      <main className="main-area">
        <Header
          onMenu={() => {
            if (window.innerWidth <= 950) setMobileOpen(v => !v);
            else setSidebarCollapsed(v => !v);
          }}
        />
        <Routes>
          <Route path="/mission" element={<MissionControl />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/overview" element={<Dashboard />} />
          <Route path="/projects" element={<Projects />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/investigation" element={<Investigation />} />
          <Route path="/jobs/:jobId" element={<JobRoute />} />
          <Route path="/verification" element={<Verification />} />
          <Route path="/lab" element={<PatchLab />} />
          <Route path="/activity" element={<ActivityPage />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="/settings" element={<Settings />} />
          <Route
            path="*"
            element={
              <div className="page">
                <div className="error-state">
                  <AlertCircle size={24} className="text-coral" />
                  <h2>Sector Not Found</h2>
                  <p>This coordinate is not part of the active KAVACH-X mission grid.</p>
                  <a className="button button-lime" href="/dashboard">
                    Return to Command Center
                  </a>
                </div>
              </div>
            }
          />
        </Routes>
        <footer className="app-footer">
          <span className="mono">KAVACH-X // TEAM BEYONDSIGHT</span>
          <span className="mono text-muted">
            AUTONOMOUS REMEDIATION · ADVERSARIAL VERIFICATION · CANONICAL CRYPTOGRAPHIC ATTESTATION
          </span>
        </footer>
      </main>
    </div>
  );
}
