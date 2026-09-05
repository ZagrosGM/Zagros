// Settings → Security — the operator's own credentials, live sessions, and the
// admin token lifetime.
//
// Deliberate choices:
//  * Changing a password requires the current one: a stolen session must not be
//    enough to lock the real owner out.
//  * Sessions listed here are *client* sessions. Admin sign-in is a stateless
//    JWT, so there is nothing server-side to revoke for an admin — saying
//    otherwise would be a lie dressed up as a feature.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, LogOut, Save, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { toast } from "../components/feedback";
import { Badge, Button, Card, CardHeader, Field, Input, Skeleton, Switch } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT } from "../lib/i18n";

interface SecurityOverview {
  admin: { username: string };
  token: {
    expire_minutes: number;
    override_minutes: number | null;
    effective_minutes: number;
    source: "database" | "environment";
    env_var: string;
  };
  ip_limit: {
    ban_duration_minutes: number;
    review_interval_seconds: number;
  };
  sessions: Array<{
    token_hash: string;
    user_id: number;
    username: string;
    created_at: string | null;
    expires_at: string | null;
    revoked: boolean;
    user_agent: string | null;
  }>;
}

function formatWhen(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export default function SettingsSecurity() {
  const t = useT();
  const qc = useQueryClient();

  const overview = useQuery({
    queryKey: ["zagros", "security"],
    queryFn: () => api.get<SecurityOverview>("/zagros/security"),
    retry: false,
  });

  const [current, setCurrent] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [lifetime, setLifetime] = useState<string>("");
  const [overrideEnabled, setOverrideEnabled] = useState(false);
  const [banMinutes, setBanMinutes] = useState("");
  const [reviewSeconds, setReviewSeconds] = useState("");

  const state = overview.data;
  if (state && lifetime === "" && state.token.override_minutes !== null) {
    setLifetime(String(state.token.override_minutes));
    setOverrideEnabled(true);
  }
  if (state && banMinutes === "") setBanMinutes(String(state.ip_limit.ban_duration_minutes));
  if (state && reviewSeconds === "") setReviewSeconds(String(state.ip_limit.review_interval_seconds));

  const changeCredentials = useMutation({
    mutationFn: () =>
      api.post<{ username: string; username_changed: boolean; password_changed: boolean; note: string }>(
        "/zagros/security/credentials",
        {
          current_password: current,
          ...(username.trim() ? { username: username.trim() } : {}),
          ...(password ? { password } : {}),
        },
      ),
    onSuccess: (data) => {
      toast.ok(
        [data.username_changed && "username updated", data.password_changed && "password updated"]
          .filter(Boolean)
          .join(" · ") || t("common.saved"),
      );
      setCurrent(""); setUsername(""); setPassword(""); setConfirm("");
      void qc.invalidateQueries({ queryKey: ["zagros", "security"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const saveLifetime = useMutation({
    mutationFn: () =>
      api.put("/zagros/security/token-lifetime", {
        expire_minutes: overrideEnabled ? Number(lifetime) : null,
      }),
    onSuccess: () => {
      toast.ok(t("common.saved"));
      void qc.invalidateQueries({ queryKey: ["zagros", "security"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const saveIpLimits = useMutation({
    mutationFn: () => api.put("/zagros/security/ip-limit", {
      ban_duration_minutes: Number(banMinutes),
      review_interval_seconds: Number(reviewSeconds),
    }),
    onSuccess: () => {
      toast.ok(t("common.saved"));
      void qc.invalidateQueries({ queryKey: ["zagros", "security"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const revoke = useMutation({
    mutationFn: (tokenHash: string) => api.delete(`/zagros/security/sessions/${encodeURIComponent(tokenHash)}`),
    onSuccess: () => {
      toast.ok(t("common.saved"));
      void qc.invalidateQueries({ queryKey: ["zagros", "security"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const mismatch = password.length > 0 && password !== confirm;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader
          title={<span className="inline-flex items-center gap-2"><KeyRound size={16} className="text-brand" />{t("settings.security.credentials")}</span>}
          subtitle={`signed in as ${state?.admin.username ?? "…"}`}
        />
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("current password")} hint={t("required to change anything")}>
            <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />
          </Field>
          <Field label={t("new username")} hint={t("leave empty to keep it")}>
            <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder={state?.admin.username} dir="ltr" autoComplete="username" />
          </Field>
          <Field label={t("new password")} hint={t("leave empty to keep it")}>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
          </Field>
          <Field label={t("repeat new password")} hint={mismatch ? "passwords do not match" : undefined}>
            <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
          </Field>
          <div className="sm:col-span-2">
            <Button
              onClick={() => changeCredentials.mutate()}
              loading={changeCredentials.isPending}
              disabled={!current || mismatch || (!username.trim() && !password)}
            >
              <Save size={14} />{t("save changes")}</Button>
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader
          title={<span className="inline-flex items-center gap-2"><ShieldCheck size={16} className="text-brand" />{t("settings.security.token")}</span>}
          subtitle={`env: ${state?.token.env_var ?? "JWT_ACCESS_TOKEN_EXPIRE_MINUTES"}`}
        />
        {overview.isLoading ? <Skeleton className="h-32" /> : (
          <div className="space-y-3">
            <div className="flex items-center gap-2.5">
              <Switch checked={overrideEnabled} onChange={setOverrideEnabled} label={t("override the environment value")} />
              <span className="text-sm text-content-2">{t("override from the panel")}</span>
            </div>
            <Field label={t("minutes (0 = never expires)")} hint={overrideEnabled ? undefined : "environment value applies"}>
              <Input
                type="number"
                min={0}
                value={overrideEnabled ? lifetime : String(state?.token.expire_minutes ?? "")}
                onChange={(e) => setLifetime(e.target.value)}
                disabled={!overrideEnabled}
                dir="ltr"
              />
            </Field>
            <p className="text-[11.5px] text-content-3">
              effective: <b className="text-content-2">{state?.token.effective_minutes ?? "—"} min</b>{" "}
              <Badge tone={state?.token.source === "database" ? "brand" : "muted"}>{state?.token.source}</Badge>
            </p>
            <Button variant="secondary" onClick={() => saveLifetime.mutate()} loading={saveLifetime.isPending}>
              <Save size={14} />{t("save token lifetime")}</Button>
          </div>
        )}
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader
          title={t("settings.security.ipLimit")}
          subtitle={t("settings.security.ipLimitSubtitle")}
        />
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("settings.security.banMinutes")} hint={t("settings.security.banMinutesHint")}>
            <Input type="number" min={1} max={10080} value={banMinutes}
              onChange={(e) => setBanMinutes(e.target.value)} dir="ltr" />
          </Field>
          <Field label={t("settings.security.reviewSeconds")} hint={t("settings.security.reviewSecondsHint")}>
            <Input type="number" min={5} max={300} value={reviewSeconds}
              onChange={(e) => setReviewSeconds(e.target.value)} dir="ltr" />
          </Field>
          <div className="sm:col-span-2">
            <Button variant="secondary" onClick={() => saveIpLimits.mutate()}
              loading={saveIpLimits.isPending}
              disabled={!banMinutes || !reviewSeconds}>
              <Save size={14} />{t("common.save")}
            </Button>
          </div>
        </div>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader title={t("settings.security.sessions")} subtitle={t("client sessions — revoking one ends it immediately")} />
        {overview.isLoading ? <Skeleton className="h-40" /> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12.5px]">
              <thead className="text-[10.5px] uppercase tracking-wide text-content-3">
                <tr>
                  <th className="py-2 pr-3">{t("user")}</th>
                  <th className="py-2 pr-3">created</th>
                  <th className="py-2 pr-3">{t("last seen")}</th>
                  <th className="py-2 pr-3">user agent</th>
                  <th className="py-2 pr-3" />
                </tr>
              </thead>
              <tbody>
                {(state?.sessions ?? []).map((session) => (
                  <tr key={session.token_hash} className="border-t border-line/60">
                    <td className="py-2 pr-3 text-content">{session.username}</td>
                    <td className="py-2 pr-3 text-content-2">{formatWhen(session.created_at)}</td>
                    <td className="py-2 pr-3 text-content-2">{formatWhen(session.expires_at)}</td>
                    <td className="max-w-[22rem] truncate py-2 pr-3 text-content-3" dir="ltr">{session.user_agent || "—"}</td>
                    <td className="py-2 pr-3 text-right">
                      <Button size="sm" variant="ghost" onClick={() => revoke.mutate(session.token_hash)} loading={revoke.isPending}>
                        <LogOut size={13} />revoke
                      </Button>
                    </td>
                  </tr>
                ))}
                {(state?.sessions ?? []).length === 0 && (
                  <tr><td colSpan={5} className="py-6 text-center text-content-3">no sessions</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
