import { NavLink } from "react-router-dom";
import {
  Activity,
  FileSearch,
  LayoutDashboard,
  ShieldCheck,
  ScrollText,
  Crosshair,
  FolderOpen,
  Settings,
  Radar,
  Compass,
  GitCompare,
  type LucideIcon,
} from "lucide-react";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
  badge?: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    title: "MISSION",
    items: [
      { to: "/", label: "Launch Bay", icon: Compass, end: true },
      { to: "/mission", label: "Mission Control", icon: Radar },
      { to: "/dashboard", label: "Command Center", icon: LayoutDashboard },
    ],
  },
  {
    title: "OPERATIONS",
    items: [
      { to: "/projects", label: "Projects", icon: FolderOpen },
      { to: "/findings", label: "Findings", icon: FileSearch, badge: "Live" },
      { to: "/investigation", label: "Investigation", icon: Crosshair },
      { to: "/verification", label: "Verification", icon: ShieldCheck },
      { to: "/lab", label: "Patch Lab", icon: GitCompare, badge: "New" },
    ],
  },
  {
    title: "INTELLIGENCE",
    items: [
      { to: "/activity", label: "Agent activity", icon: Activity },
      { to: "/evidence", label: "Evidence reports", icon: ScrollText },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <ShieldCheck size={22} />
        </div>
        <div>
          <div className="brand-name">
            KAVACH<span className="brand-accent">-X</span>
          </div>
          <div className="brand-sub">EDITORIAL SCI-FI SECURITY</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navSections.map(section => (
          <div key={section.title} className="sidebar-section">
            <div className="workspace-label mono">{section.title}</div>
            <div className="sidebar-group">
              {section.items.map(({ to, label, icon: Icon, end, badge }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
                >
                  <Icon size={16} />
                  <span>{label}</span>
                  {badge && <span className="nav-count mono">{badge}</span>}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="sidebar-bottom">
        <div className="environment">
          <span className="pulse-dot" />
          <div>
            <strong>Docker Lab Connected</strong>
            <small className="mono">BOLA-REQUIRED-TESTS-V1</small>
          </div>
        </div>
        <div className="sidebar-foot mono">KAVACH-X // BEYONDSIGHT 2026</div>
      </div>
    </aside>
  );
}