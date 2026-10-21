import type { LucideIcon } from "lucide-react";

export type StatTone = "cyan" | "green" | "amber" | "red" | "lime" | "coral" | "teal";

export default function StatCard({
  label,
  value,
  detail,
  icon: Icon,
  tone = "teal",
}: {
  label: string;
  value: number | string;
  detail: string;
  icon: LucideIcon;
  tone?: StatTone;
}) {
  return (
    <article className="stat-card">
      <div className={`stat-icon ${tone}`}>
        <Icon size={18} />
      </div>
      <div className="stat-label">{label}</div>
      <div className="stat-value mono">{value}</div>
      <div className="stat-detail">{detail}</div>
    </article>
  );
}