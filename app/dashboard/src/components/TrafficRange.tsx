import { Field, Input, Select } from "./ui";
import { useT } from "../lib/i18n";

export type TrafficPeriod = "hour" | "day" | "week" | "month" | "custom";
export interface TrafficRangeValue { period: TrafficPeriod; start: string; end: string }

export function trafficRangeQuery(value: TrafficRangeValue): string {
  const params = new URLSearchParams({ range: value.period });
  if (value.period === "custom" && value.start && value.end) {
    params.set("start", new Date(value.start).toISOString());
    params.set("end", new Date(value.end).toISOString());
  }
  return params.toString();
}

export function TrafficRange({ value, onChange }: {
  value: TrafficRangeValue; onChange: (value: TrafficRangeValue) => void;
}) {
  const t = useT();
  return (
    <div className="flex flex-wrap items-end gap-2">
      <Field label={t("statistics.range")}>
        <Select value={value.period} onChange={(event) => onChange({ ...value, period: event.target.value as TrafficPeriod })} className="w-32">
          <option value="hour">{t("statistics.hour")}</option>
          <option value="day">{t("statistics.day")}</option>
          <option value="week">{t("statistics.week")}</option>
          <option value="month">{t("statistics.month")}</option>
          <option value="custom">{t("statistics.custom")}</option>
        </Select>
      </Field>
      {value.period === "custom" && (
        <>
          <Field label={t("statistics.from")}>
            <Input type="datetime-local" value={value.start}
              onChange={(event) => onChange({ ...value, start: event.target.value })} className="w-[12.5rem]" />
          </Field>
          <Field label={t("statistics.to")}>
            <Input type="datetime-local" value={value.end}
              onChange={(event) => onChange({ ...value, end: event.target.value })} className="w-[12.5rem]" />
          </Field>
        </>
      )}
    </div>
  );
}
