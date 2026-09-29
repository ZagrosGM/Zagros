// f-panel-5: client mirror of the backend permission matrix
// (app/admin_permissions.py). Backend enforcement is the source of truth —
// this hook only hides what the admin cannot do anyway.
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

export const PERM_SECTIONS = [
  "overview", "users", "templates", "subscriptions", "applications",
  "nodes", "cores", "routing", "outbounds", "inbounds", "hosts", "dns",
  "certificates", "monitoring", "statistics", "support", "settings",
  "advanced",
] as const;

export type PermSection = (typeof PERM_SECTIONS)[number];
export type PermLevel = "hidden" | "view" | "edit";

const RANK: Record<PermLevel, number> = { hidden: 0, view: 1, edit: 2 };

export interface PermDoc {
  sections?: Record<string, string>;
  inbounds?: string[] | null;
}

export function useAdminPerms() {
  const q = useQuery({
    queryKey: ["admin", "me"],
    queryFn: () => api.get<{ is_sudo: boolean; permissions: PermDoc | null }>("/admin"),
    staleTime: 30_000,
    retry: false,
  });
  const isSudo = Boolean(q.data?.is_sudo);
  const raw = q.data?.permissions ?? null;
  const level = (section: string): PermLevel =>
    isSudo ? "edit" : ((((raw?.sections ?? {})[section]) as PermLevel) || "edit");
  const can = (section: string, need: "view" | "edit") =>
    RANK[level(section)] >= RANK[need];
  const allowedInbounds = (): string[] | null =>
    isSudo ? null : (raw?.inbounds ?? null);
  return { isSudo, loaded: Boolean(q.data), isLoading: q.isLoading, can, level, allowedInbounds };
}
