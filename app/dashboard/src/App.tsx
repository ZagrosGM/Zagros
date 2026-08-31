import { lazy, Suspense } from "react";
import { HashRouter, Route, Routes } from "react-router-dom";
import AppLayout from "./layouts/AppLayout";
import Login from "./pages/Login";
import { Skeleton } from "./components/ui";

// Every page is lazy-loaded — the shell boots fast, pages stream in.
const Overview = lazy(() => import("./pages/Overview"));
const Users = lazy(() => import("./pages/Users"));
const Admins = lazy(() => import("./pages/Admins"));
const Templates = lazy(() => import("./pages/Templates"));
const Subscriptions = lazy(() => import("./pages/Subscriptions"));
const Nodes = lazy(() => import("./pages/Nodes"));
const Cores = lazy(() => import("./pages/Cores"));
const Support = lazy(() => import("./pages/Support"));
const Routing = lazy(() => import("./pages/Routing"));
const Outbounds = lazy(() => import("./pages/Outbounds"));
const Inbounds = lazy(() => import("./pages/Inbounds"));
const Hosts = lazy(() => import("./pages/Hosts"));
const Dns = lazy(() => import("./pages/Dns"));
const Certificates = lazy(() => import("./pages/Certificates"));
const Sessions = lazy(() => import("./pages/Sessions"));
const Devices = lazy(() => import("./pages/Devices"));
const Logs = lazy(() => import("./pages/Logs"));
const Settings = lazy(() => import("./pages/Settings"));
const SettingsGeneral = lazy(() => import("./pages/SettingsGeneral"));
const SettingsSecurity = lazy(() => import("./pages/SettingsSecurity"));
const SettingsBackup = lazy(() => import("./pages/SettingsBackup"));
const Advanced = lazy(() => import("./pages/Advanced"));

function PageFallback() {
  return (
    <div className="space-y-4 animate-fade-up">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="h-64 w-full" />
    </div>
  );
}

// HashRouter: the panel is served as static files under DASHBOARD_PATH with
// a 404→index fallback; hash routing keeps deep links working on every
// deployment shape (no server rewrite contract required).
export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<AppLayout />}>
          <Route index element={<Suspense fallback={<PageFallback />}><Overview /></Suspense>} />
          <Route path="users" element={<Suspense fallback={<PageFallback />}><Users /></Suspense>} />
          <Route path="admins" element={<Suspense fallback={<PageFallback />}><Admins /></Suspense>} />
          <Route path="templates" element={<Suspense fallback={<PageFallback />}><Templates /></Suspense>} />
          <Route path="subscriptions" element={<Suspense fallback={<PageFallback />}><Subscriptions /></Suspense>} />
          <Route path="nodes" element={<Suspense fallback={<PageFallback />}><Nodes /></Suspense>} />
          <Route path="cores" element={<Suspense fallback={<PageFallback />}><Cores /></Suspense>} />
          <Route path="routing" element={<Suspense fallback={<PageFallback />}><Routing /></Suspense>} />
          <Route path="outbounds" element={<Suspense fallback={<PageFallback />}><Outbounds /></Suspense>} />
          <Route path="inbounds" element={<Suspense fallback={<PageFallback />}><Inbounds /></Suspense>} />
          <Route path="hosts" element={<Suspense fallback={<PageFallback />}><Hosts /></Suspense>} />
          <Route path="dns" element={<Suspense fallback={<PageFallback />}><Dns /></Suspense>} />
          <Route path="certificates" element={<Suspense fallback={<PageFallback />}><Certificates /></Suspense>} />
          <Route path="sessions" element={<Suspense fallback={<PageFallback />}><Sessions /></Suspense>} />
          <Route path="devices" element={<Suspense fallback={<PageFallback />}><Devices /></Suspense>} />
          <Route path="logs" element={<Suspense fallback={<PageFallback />}><Logs /></Suspense>} />
          <Route path="support" element={<Suspense fallback={<PageFallback />}><Support /></Suspense>} />
          {/* Settings is a section with three linkable tabs */}
          <Route path="settings" element={<Suspense fallback={<PageFallback />}><Settings /></Suspense>}>
            <Route index element={<Suspense fallback={<PageFallback />}><SettingsGeneral /></Suspense>} />
            <Route path="security" element={<Suspense fallback={<PageFallback />}><SettingsSecurity /></Suspense>} />
            <Route path="backup" element={<Suspense fallback={<PageFallback />}><SettingsBackup /></Suspense>} />
          </Route>
          <Route path="advanced" element={<Suspense fallback={<PageFallback />}><Advanced /></Suspense>} />
          <Route path="*" element={<Suspense fallback={<PageFallback />}><Overview /></Suspense>} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
