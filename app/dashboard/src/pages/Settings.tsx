// Settings — one section, three tabs: General, Security, Backup & Restore.
// Each tab is a real route, so a link survives a reload and can be shared
// (and a restore can send the operator straight to the tab it happened on).
import { Outlet, NavLink } from "react-router-dom";
import { DatabaseBackup, Settings as SettingsIcon, ShieldCheck } from "lucide-react";
import { useT } from "../lib/i18n";

const TABS = [
  { to: ".", label: "settings.general", icon: SettingsIcon, end: true },
  { to: "security", label: "settings.security", icon: ShieldCheck, end: false },
  { to: "backup", label: "settings.backup", icon: DatabaseBackup, end: false },
] as const;

export default function Settings() {
  const t = useT();
  return (
    <div className="space-y-4 animate-fade-up">
      <h1 className="flex items-center gap-2 text-lg font-bold tracking-tight">
        <SettingsIcon size={18} className="text-brand" />{t("nav.settings")}
      </h1>

      <nav
        aria-label={t("nav.settings")}
        className="flex flex-wrap gap-1 rounded-xl border border-line bg-surface-2 p-1"
      >
        {TABS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-[13px] transition-colors ${
                isActive
                  ? "bg-brand-soft text-brand font-medium"
                  : "text-content-2 hover:bg-surface hover:text-content"
              }`}
          >
            <Icon size={15} />
            {t(label as never)}
          </NavLink>
        ))}
      </nav>

      <Outlet />
    </div>
  );
}
