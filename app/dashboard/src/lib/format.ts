// Formatting helpers — locale-aware digits (fa), bytes, dates, durations.
import { useUI } from "../stores/ui";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";

dayjs.extend(relativeTime);

const FA_DIGITS = "۰۱۲۳۴۵۶۷۸۹";
export const faDigits = (s: string) => s.replace(/\d/g, (d) => FA_DIGITS[+d]);

export function useDigits() {
  const locale = useUI((s) => s.locale);
  return (s: string) => (locale === "fa" ? faDigits(s) : s);
}

export function formatBytes(bytes: number | null | undefined, digits = digitsEn): string {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return "—";
  if (bytes === 0) return digits("0 B");
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(Math.abs(bytes)) / Math.log(1024)));
  const v = bytes / 1024 ** i;
  const str = `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
  return digits(str);
}

export function formatSpeed(bps: number | null | undefined, digits = digitsEn): string {
  if (bps === null || bps === undefined) return "—";
  return `${formatBytes(bps, (s) => s)}/s` && formatBytes(bps, digits) + "/s";
}

const digitsEn = (s: string) => s;

export function formatNumber(n: number | null | undefined, digits = digitsEn): string {
  if (n === null || n === undefined) return "—";
  return digits(new Intl.NumberFormat("en-US").format(n));
}

export function formatDate(ts: number | string | null | undefined, digits = digitsEn): string {
  if (!ts) return "—";
  const d = typeof ts === "number" ? dayjs.unix(ts) : dayjs(ts);
  return digits(d.isValid() ? d.format("YYYY-MM-DD HH:mm") : "—");
}

export function formatRelative(ts: number | string | null | undefined, digits = digitsEn): string {
  if (!ts) return "—";
  const d = typeof ts === "number" ? dayjs.unix(ts) : dayjs(ts);
  return d.isValid() ? digits(d.fromNow()) : "—";
}

export function formatDuration(seconds: number | null | undefined, digits = digitsEn): string {
  if (seconds === null || seconds === undefined) return "—";
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return digits(`${d}d ${h}h`);
  if (h > 0) return digits(`${h}h ${m}m`);
  if (m > 0) return digits(`${m}m ${s % 60}s`);
  return digits(`${s}s`);
}

export function usagePercent(user: { used_traffic: number; data_limit: number | null }): number {
  if (!user.data_limit || user.data_limit <= 0) return 0;
  return Math.min(100, (user.used_traffic / user.data_limit) * 100);
}
