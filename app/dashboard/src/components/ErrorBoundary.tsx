// ErrorBoundary — structural guarantee: a render error can NEVER white-screen
// the panel. Used globally (main.tsx) and per-page (AppLayout <Outlet/>) so a
// crashing page leaves the shell, sidebar and other pages fully alive.
import { Component, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { RotateCcw, ShieldAlert } from "lucide-react";
import { useT } from "../lib/i18n";
import { Button } from "./ui";

interface Props {
  children: ReactNode;
  /** scope label for logs (e.g. "page", "app") */
  scope?: string;
}

interface State { error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: { componentStack?: string }) {
    // Real diagnostics land in the browser console instead of a white screen.
    console.error(`[zagros] ErrorBoundary (${this.props.scope ?? "app"}) caught:`, error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return <BoundaryFallback scope={this.props.scope ?? "app"} error={this.state.error}
      reset={() => this.setState({ error: null })} />;
  }
}

function BoundaryFallback({ error, reset, scope }: { error: Error; reset: () => void; scope: string }) {
  const t = useT();
  return (
    <div className="grid min-h-[50vh] place-items-center p-6">
      <div className="card w-full max-w-md p-8 text-center">
        <div className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-2xl bg-danger-soft text-danger">
          <ShieldAlert size={24} />
        </div>
        <h2 className="text-base font-bold">{t("error.title")}</h2>
        <p className="mt-1.5 text-[13px] text-content-2">{t("error.body")}</p>
        <details className="mt-4 rounded-xl border border-border bg-surface-1 p-3 text-start">
          <summary className="cursor-pointer text-xs font-medium text-content-3">{t("error.detail")}</summary>
          <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap text-[11px] leading-relaxed text-content-3" dir="ltr">
            {scope}: {error.name}: {error.message}
          </pre>
        </details>
        <div className="mt-5 flex items-center justify-center gap-2">
          <Button size="sm" onClick={() => { reset(); location.reload(); }}>
            <RotateCcw size={14} /> {t("error.reload")}
          </Button>
          <Link to="/" onClick={reset}>
            <Button size="sm" variant="ghost">{t("error.home")}</Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
