// Login — legacy JWT (POST /api/admin/token), same contract as Marzban.
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Loader2, Mountain } from "lucide-react";
import { ApiError, auth } from "../lib/api";
import { useT } from "../lib/i18n";
import { Button, Input } from "../components/ui";

export default function Login() {
  const t = useT();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      await auth.login(username, password);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("login.failed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-dvh place-items-center bg-surface p-4">
      <motion.div
        initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }}
        transition={{ type: "spring", stiffness: 200, damping: 22 }}
        className="card w-full max-w-sm p-8"
      >
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <img src="./zagros.svg" alt="" className="h-14 w-14 rounded-2xl shadow-pop" />
          <div>
            <h1 className="text-lg font-bold tracking-tight">{t("login.title")}</h1>
            <p className="mt-1 text-xs text-content-3">{t("login.subtitle")}</p>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-4" autoComplete="off">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-content-2" htmlFor="u">{t("login.username")}</label>
            <Input id="u" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus required />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-content-2" htmlFor="p">{t("login.password")}</label>
            <Input id="p" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          {error && (
            <p role="alert" className="rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">
              {error}
            </p>
          )}
          <Button type="submit" disabled={busy} className="w-full" size="md">
            {busy ? <Loader2 size={15} className="animate-spin" /> : <Mountain size={15} />}
            {t("login.submit")}
          </Button>
        </form>
      </motion.div>
    </div>
  );
}
