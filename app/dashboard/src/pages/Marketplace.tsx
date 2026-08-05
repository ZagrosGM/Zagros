// Marketplace — honest Roadmap page: the extension model is designed but no
// packages ship yet. Nothing here pretends to work.
import { Store } from "lucide-react";
import { Badge, Card, CardHeader, EmptyState } from "../components/ui";
import { useT } from "../lib/i18n";

const ROADMAP = [
  { title: "Core plugin marketplace", body: "Install community cores and drivers from versioned, signed packages — the same capability model the built-in cores already use." },
  { title: "Theme & template packs", body: "Subscription portal templates and panel themes as installable packages." },
  { title: "Automation hooks", body: "Event webhooks and small serverless transforms for provisioning flows." },
];

export default function Marketplace() {
  const t = useT();
  return (
    <div className="space-y-4 animate-fade-up">
      <h1 className="flex items-center gap-2 text-lg font-bold tracking-tight">
        <Store size={18} className="text-brand" />{t("nav.marketplace")}
        <Badge tone="info">{t("common.roadmap")}</Badge>
      </h1>
      <Card>
        <EmptyState
          title="The marketplace ships with the plugin SDK"
          hint="This page is intentionally honest: there are no packages to install today. Below is the real roadmap for this surface — tracked as product work, not hidden behind fake buttons."
        />
      </Card>
      <div className="grid gap-3 md:grid-cols-3">
        {ROADMAP.map((r) => (
          <Card key={r.title}>
            <CardHeader title={<span className="flex items-center justify-between gap-2">{r.title}<Badge tone="muted">planned</Badge></span>} />
            <p className="text-[12px] leading-5 text-content-2">{r.body}</p>
          </Card>
        ))}
      </div>
    </div>
  );
}
