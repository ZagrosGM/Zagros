// Support — user-facing Bug Report & Feature Request submission.
import { useMutation } from "@tanstack/react-query";
import {
  Bug, CheckCircle2, FileText, LifeBuoy, Lightbulb, Paperclip, Send, ShieldAlert, X,
} from "lucide-react";
import { useState } from "react";
import { toast } from "../components/feedback";
import { Button, Card, Field, Input, Textarea, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT } from "../lib/i18n";

export default function Support() {
  const t = useT();

  // Ticket Form State
  const [ticketType, setTicketType] = useState<"bug" | "feature">("bug");
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [attachment, setAttachment] = useState<File | null>(null);
  const [successTicketId, setSuccessTicketId] = useState<string | null>(null);

  // Submit Mutation
  const submitTicket = useMutation({
    mutationFn: async () => {
      const fd = new FormData();
      fd.append("ticket_type", ticketType);
      fd.append("subject", subject);
      fd.append("message", message);
      if (attachment) {
        fd.append("attachment", attachment);
      }
      return api.post<{ ok: boolean; ticket_id: string; detail: string }>("/zagros/support/ticket", fd);
    },
    onSuccess: (data) => {
      setSuccessTicketId(data.ticket_id);
      toast.ok(`Ticket ${data.ticket_id} submitted successfully`);
      setSubject("");
      setMessage("");
      setAttachment(null);
    },
    onError: (e) => {
      toast.error(e instanceof ApiError ? e.message : "Support service is temporarily unavailable.");
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.size > 10 * 1024 * 1024) {
        toast.error("Attachment size exceeds 10MB limit");
        return;
      }
      setAttachment(file);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6 animate-fade-up">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-bold tracking-tight">
          <LifeBuoy size={22} className="text-brand" /> {t("nav.support")}
        </h1>
        <p className="mt-1 text-xs text-content-3">{t("Submit bug reports or feature requests directly to support.")}</p>
      </div>

      {successTicketId && (
        <Card className="p-4 border-ok/40 bg-ok-soft/30 flex items-start gap-3">
          <CheckCircle2 size={20} className="text-ok shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <h3 className="text-sm font-semibold text-content">{t("Ticket Submitted Successfully")}</h3>
            <p className="text-xs text-content-2 mt-1">{t("Your ticket ID is")}<code className="font-mono font-bold text-ok">{successTicketId}</code>.
              Our support team has been notified.
            </p>
          </div>
          <button onClick={() => setSuccessTicketId(null)} className="text-content-3 hover:text-content">
            <X size={16} />
          </button>
        </Card>
      )}

      <Card className="p-6 space-y-5">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-content-3 mb-2">{t("Select Request Type *")}</label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setTicketType("bug")}
              className={cn(
                "flex items-center gap-3 rounded-xl border p-3.5 text-start transition-colors",
                ticketType === "bug"
                  ? "border-brand bg-brand-soft/50 text-brand"
                  : "border-border hover:border-border-strong text-content-2",
              )}
            >
              <Bug size={20} className={ticketType === "bug" ? "text-brand" : "text-content-3"} />
              <div>
                <span className="block text-sm font-medium">{t("Bug Report")}</span>
                <span className="text-[11px] text-content-3">{t("Report an issue or unexpected error")}</span>
              </div>
            </button>

            <button
              type="button"
              onClick={() => setTicketType("feature")}
              className={cn(
                "flex items-center gap-3 rounded-xl border p-3.5 text-start transition-colors",
                ticketType === "feature"
                  ? "border-brand bg-brand-soft/50 text-brand"
                  : "border-border hover:border-border-strong text-content-2",
              )}
            >
              <Lightbulb size={20} className={ticketType === "feature" ? "text-brand" : "text-content-3"} />
              <div>
                <span className="block text-sm font-medium">{t("Feature Request")}</span>
                <span className="text-[11px] text-content-3">{t("Suggest an improvement or new feature")}</span>
              </div>
            </button>
          </div>
        </div>

        <Field label={t("Subject")} required hint={t("Brief summary of your request")}>
          <Input
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder={ticketType === "bug" ? t("e.g., Connection fails on WireGuard inbound") : t("e.g., Add Dark Mode toggle for client portal")}
          />
        </Field>

        <Field label={t("Message")} required hint={t("Provide detailed explanation and steps if applicable")}>
          <Textarea
            rows={6}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder={ticketType === "bug" ? t("Describe what happened, what was expected, and error messages if any...") : t("Describe the feature and how it would help...")}
          />
        </Field>

        <Field label={t("Attachments (Optional)")} hint={t("Images, log files, or documents (max 10MB)")}>
          <div className="flex items-center gap-3">
            <label className="cursor-pointer inline-flex items-center gap-2 rounded-xl border border-border bg-surface-2 px-3.5 py-2 text-xs font-medium text-content-2 transition-colors hover:bg-surface-3 hover:text-content">
              <Paperclip size={15} />
              <span>{attachment ? t("Change File") : t("Choose File")}</span>
              <input
                type="file"
                className="hidden"
                onChange={handleFileChange}
                accept="image/*,.pdf,.txt,.log,.doc,.docx,.xls,.xlsx,.zip,.rar"
              />
            </label>
            {attachment ? (
              <div className="flex items-center gap-2 rounded-xl bg-surface-2 px-3 py-1.5 text-xs">
                <FileText size={14} className="text-brand" />
                <span className="truncate max-w-[200px] font-medium">{attachment.name}</span>
                <span className="text-content-3">({(attachment.size / 1024).toFixed(0)} KB)</span>
                <button
                  type="button"
                  onClick={() => setAttachment(null)}
                  className="ms-1 text-content-3 hover:text-danger"
                >
                  <X size={14} />
                </button>
              </div>
            ) : (
              <span className="text-xs text-content-3">{t("No file selected")}</span>
            )}
          </div>
        </Field>

        <div className="pt-2 flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-[11px] text-content-3">
            <ShieldAlert size={14} className="text-ok" />
            <span>{t("Only your submitted ticket details are sent. No user lists or secrets are shared.")}</span>
          </div>

          <Button
            onClick={() => submitTicket.mutate()}
            loading={submitTicket.isPending}
            disabled={!subject.trim() || !message.trim()}
            className="min-w-[140px]"
          >
            <Send size={15} />{t("Submit Ticket")}</Button>
        </div>
      </Card>
    </div>
  );
}
