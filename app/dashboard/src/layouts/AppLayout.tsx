// App shell — single sidebar (the ONE panel), topbar with omnibox entry,
// theme/locale toggles, mobile drawer, keyboard shortcuts.
import { clsx } from "clsx";
import {
  Activity, Award, Boxes, ChevronLeft, Cpu, FileTerminal, Globe,
  HardDrive, LayoutDashboard, LayoutTemplate, LifeBuoy, LogOut, Menu, Moon, Network,
  Radio, Route, Search, ServerCog, Settings, ShieldCheck, Sun, TerminalSquare,
  Users, Waypoints, Wifi,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { CommandPalette, useCommands } from "../components/CommandPalette";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { Toaster, toast } from "../components/feedback";
import { auth, getToken } from "../lib/api";
import { useT } from "../lib/i18n";
import { applyUiState, useUI } from "../stores/ui";

const NAV = [
  { section: "nav.section.operate", items: [
    { to: "/", icon: LayoutDashboard, key: "nav.overview", end: true },
    { to: "/subscriptions", icon: Radio, key: "nav.subscriptions" },
    { to: "/nodes", icon: HardDrive, key: "nav.nodes" },
  ]},
  { section: "nav.section.management", items: [
    { to: "/users", icon: Users, key: "nav.users" },
    { to: "/admins", icon: ShieldCheck, key: "nav.admins" },
    { to: "/templates", icon: LayoutTemplate, key: "nav.templates" },
  ]},
  { section: "nav.section.network", items: [
    { to: "/cores", icon: Cpu, key: "nav.cores" },
    { to: "/inbounds", icon: Waypoints, key: "nav.inbounds" },
    { to: "/outbounds", icon: Network, key: "nav.outbounds" },
    { to: "/routing", icon: Route, key: "nav.routing" },
    { to: "/hosts", icon: ServerCog, key: "nav.hosts" },
    { to: "/certificates", icon: ShieldCheck, key: "nav.certificates" },
    { to: "/dns", icon: Globe, key: "nav.dns" },
  ]},
  { section: "nav.section.observe", items: [
    { to: "/sessions", icon: Activity, key: "nav.sessions" },
    { to: "/devices", icon: Wifi, key: "nav.devices" },
    { to: "/logs", icon: FileTerminal, key: "nav.logs" },
  ]},
  { section: "nav.section.system", items: [
    { to: "/support", icon: LifeBuoy, key: "nav.support" },
    { to: "/settings", icon: Settings, key: "nav.settings" },
    { to: "/advanced", icon: TerminalSquare, key: "nav.advanced" },
  ]},
] as const;

export default function AppLayout() {
  const t = useT();
  const navigate = useNavigate();
  const location = useLocation();
  const { theme, locale, sidebarCollapsed, setTheme, setLocale, toggleSidebar, advancedMode } = useUI();
  const [palette, setPalette] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);

  const commands = useCommands(useMemo(() => [
    { id: "action-theme", title: `Toggle theme (${theme === "dark" ? "light" : "dark"})`, section: "Actions",
      run: () => { const next = theme === "dark" ? "light" : "dark"; setTheme(next); applyUiState(next, locale); } },
    { id: "action-locale", title: `Switch language (${locale === "fa" ? "English" : "فارسی"})`, section: "Actions",
      run: () => { const next = locale === "fa" ? "en" : "fa"; setLocale(next); applyUiState(theme, next); } },
  ], [theme, locale, setTheme, setLocale]));

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((v) => !v); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  useEffect(() => { setMobileNav(false); }, [location.pathname]);

  // Auth guard — navigate() is a state update and must NEVER run during
  // render (React throws / can loop). Redirect goes in an effect; while the
  // redirect is pending we render nothing (never a partial shell).
  const token = getToken();
  useEffect(() => {
    if (!token) navigate("/login", { replace: true });
  }, [token, navigate]);
  if (!token) return null;

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className={clsx("flex h-16 items-center gap-3 border-b border-border px-4", sidebarCollapsed && "justify-center px-2")}>
        <img src="./statics/zagros.svg" alt="Zagros" className="h-9 w-9 shrink-0 rounded-xl" />
        {!sidebarCollapsed && (
          <div className="min-w-0">
            <p className="truncate text-[15px] font-bold tracking-tight">Zagros</p>
            <p className="truncate text-[10.5px] text-content-3">{t("app.tagline")}</p>
          </div>
        )}
      </div>
      <nav aria-label="Primary" className="flex-1 space-y-4 overflow-y-auto p-2.5">
        {NAV.map((group) => (
          <div key={group.section}>
            {!sidebarCollapsed && (
              <p className="px-2.5 pb-1.5 pt-1 text-[10px] font-semibold uppercase tracking-wider text-content-3">
                {t(group.section as Parameters<typeof t>[0])}
              </p>
            )}
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                if (item.key === "nav.advanced" && !advancedMode) return null;
                const Icon = item.icon;
                return (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      end={"end" in item && item.end}
                      title={t(item.key as Parameters<typeof t>[0])}
                      className={({ isActive }) => clsx(
                        "group flex items-center gap-2.5 rounded-xl px-2.5 py-2 text-[13px] font-medium transition-all",
                        sidebarCollapsed && "justify-center",
                        isActive
                          ? "bg-brand-soft text-brand"
                          : "text-content-2 hover:bg-surface-2 hover:text-content",
                      )}
                    >
                      <Icon size={17} className="shrink-0" />
                      {!sidebarCollapsed && <span className="truncate">{t(item.key as Parameters<typeof t>[0])}</span>}
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className="border-t border-border p-2.5">
        <button
          onClick={toggleSidebar}
          className="hidden w-full items-center gap-2 rounded-xl px-2.5 py-2 text-xs text-content-3 hover:bg-surface-2 hover:text-content lg:flex"
        >
          <ChevronLeft size={15} className={clsx("transition-transform", sidebarCollapsed && "rotate-180 [dir=rtl]&:-rotate-180")} />
          {!sidebarCollapsed && t("shell.collapse")}
        </button>
      </div>
    </div>
  );

  return (
    <div className="flex h-dvh overflow-hidden bg-surface text-content">
      {/* desktop sidebar */}
      <aside className={clsx(
        "hidden shrink-0 border-e border-border bg-surface-1 transition-[width] lg:block",
        sidebarCollapsed ? "w-[68px]" : "w-60",
      )}>
        {sidebar}
      </aside>

      {/* mobile drawer */}
      {mobileNav && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/55" onClick={() => setMobileNav(false)} />
          <aside className="absolute inset-y-0 start-0 w-64 border-e border-border bg-surface-1 shadow-pop">
            {sidebar}
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        {/* topbar */}
        <header className="glass z-20 flex h-16 shrink-0 items-center gap-3 border-b border-border px-4">
          <button className="rounded-lg p-2 text-content-2 hover:bg-surface-2 lg:hidden" onClick={() => setMobileNav(true)} aria-label="Menu">
            <Menu size={18} />
          </button>
          <button
            onClick={() => setPalette(true)}
            className="flex h-9 w-full max-w-sm items-center gap-2.5 rounded-xl border border-border bg-surface-1 px-3 text-content-3 transition-colors hover:border-border-strong hover:text-content-2"
          >
            <Search size={15} />
            <span className="flex-1 text-start text-[13px]">{t("shell.search")}</span>
            <span className="kbd">⌘K</span>
          </button>
          <div className="ms-auto flex items-center gap-1.5">
            <button
              onClick={() => { const next = locale === "fa" ? "en" : "fa"; setLocale(next); applyUiState(theme, next); }}
              className="grid h-9 w-9 place-items-center rounded-xl text-content-2 hover:bg-surface-2"
              title={t("shell.language")} aria-label={t("shell.language")}
            >
              <span className="text-xs font-bold">{locale === "fa" ? "EN" : "فا"}</span>
            </button>
            <button
              onClick={() => { const next = theme === "dark" ? "light" : "dark"; setTheme(next); applyUiState(next, locale); }}
              className="grid h-9 w-9 place-items-center rounded-xl text-content-2 hover:bg-surface-2"
              title={t("shell.theme")} aria-label={t("shell.theme")}
            >
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
            </button>
            <span className="mx-1 h-5 w-px bg-border" />
            <button
              onClick={() => {
                auth.logout();
                toast.info(t("shell.signout"));
                navigate("/login", { replace: true });
              }}
              className="flex items-center gap-2 rounded-xl px-3 py-2 text-[13px] text-content-2 hover:bg-surface-2"
            >
              <LogOut size={15} />
              <span className="hidden sm:inline">{t("shell.signout")}</span>
            </button>
          </div>
        </header>

        {/* page body — page-level ErrorBoundary: if ONE page crashes, the
            shell/sidebar stay alive and other pages keep working.
            The key resets the boundary on every navigation. */}
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1400px] p-4 sm:p-6">
            <ErrorBoundary scope={`page:${location.pathname}`} key={location.pathname}>
              <Outlet />
            </ErrorBoundary>
          </div>
        </main>
      </div>

      <CommandPalette open={palette} onClose={() => setPalette(false)} commands={commands} />
      <Toaster />
    </div>
  );
}
