import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Dispatch, FormEvent, ReactNode, SetStateAction } from "react";
import {
  ChevronRight,
  Copy,
  Gauge,
  Info,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  RefreshCw,
} from "lucide-react";
import { ApiClient, ApiError } from "./api";
import type { EventMessage, NodeDetails, NodeHealth, NodeRecord, ServiceState, StatusResponse } from "./types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

const providerLoginStates: Partial<Record<ServiceState, true>> = { signed_out: true, expired: true };

type Route = "/" | "/signin";
type SessionState = "checking" | "setup" | "access_login" | "available";

interface AppProps {
  api?: ApiClient;
}

interface StatusDetail {
  label: string;
  message: string;
  tone: "ready" | "working" | "warning" | "danger" | "neutral";
}

const stateDetails: Record<ServiceState, StatusDetail> = {
  signed_out: { label: "Signed out", message: "Connect an account to load nodes.", tone: "neutral" },
  authenticating: { label: "Authenticating", message: "Connecting your account.", tone: "working" },
  syncing: { label: "Syncing", message: "Updating nodes.", tone: "working" },
  ready: { label: "Ready", message: "Service is ready.", tone: "ready" },
  degraded: { label: "Needs attention", message: "Saved nodes are still available.", tone: "warning" },
  expired: { label: "Expired", message: "Connect your account again.", tone: "danger" },
  error: { label: "Service error", message: "Service status could not be completed.", tone: "danger" },
};

const groupNameCollator = new Intl.Collator(["zh-CN-u-co-pinyin", "en"], { numeric: true, sensitivity: "base" });
const namedGroupPriorities = new Map<string, number>([
  ["优选直连线路", 1],
  ["音乐/视频APP专线", 2],
]);

function groupPriority(group: string): number {
  const namedPriority = namedGroupPriorities.get(group);
  if (namedPriority !== undefined) return namedPriority;
  return /➩\s*中国(?:大陆)?$/u.test(group) ? 3 : 0;
}

function compareGroupNames(left: string, right: string): number {
  return groupPriority(left) - groupPriority(right) || groupNameCollator.compare(left, right);
}

function routeFromLocation(): Route {
  return window.location.pathname === "/signin" ? "/signin" : "/";
}

function replaceRoute(route: Route): void {
  if (window.location.pathname !== route) window.history.replaceState(null, "", route);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function isSessionProblem(error: unknown): boolean {
  return error instanceof ApiError && (error.problem.status === 401 || error.problem.status === 403);
}

function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.problem.code === "rate_limited") return "Too many attempts. Wait a moment and try again.";
    if (error.problem.code === "invalid_access_token") return "That access token was not accepted.";
    if (error.problem.code === "login_rejected") return "The provider rejected that email or password.";
    return error.problem.detail || error.problem.title;
  }
  return "The local service did not complete that request.";
}

function formatTime(value?: string): string {
  if (!value) return "—";
  const time = new Date(value);
  return Number.isNaN(time.getTime()) ? "—" : time.toLocaleString();
}

function formatLatency(value?: number): string {
  return typeof value === "number" ? `${value} ms` : "—";
}

function healthLabel(health: NodeHealth): string {
  return health.slice(0, 1).toUpperCase() + health.slice(1);
}

export function App({ api: providedApi }: AppProps) {
  const apiRef = useRef<ApiClient>(providedApi ?? new ApiClient());
  const api = apiRef.current;
  const [route, setRoute] = useState<Route>(routeFromLocation);
  const [session, setSession] = useState<SessionState>("checking");
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [nodes, setNodes] = useState<NodeRecord[]>([]);
  const [subscriptionURL, setSubscriptionURL] = useState("");
  const [loadError, setLoadError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const sessionRevision = useRef(0);
  const reloadWork = useRef({ scheduled: false, running: false, queued: false, revision: 0 });
  const nextSSEFailureReloadAt = useRef(0);
  const accountLogoutInFlight = useRef(false);

  const clearProviderData = useCallback(() => {
    setStatus(null);
    setNodes([]);
    setSubscriptionURL("");
    setRefreshing(false);
  }, []);

  const clearConsoleData = useCallback(() => {
    clearProviderData();
    setLoadError("");
  }, [clearProviderData]);

  const loseAccessSession = useCallback(() => {
    sessionRevision.current += 1;
    reloadWork.current.queued = false;
    api.clearSession();
    clearConsoleData();
    setSession("access_login");
    replaceRoute("/");
  }, [api, clearConsoleData]);

  const loadAuthenticatedData = useCallback(async (): Promise<StatusResponse | null> => {
    if (accountLogoutInFlight.current) return null;
    const revision = sessionRevision.current;
    try {
      const nextStatus = await api.status();
      if (revision !== sessionRevision.current) return null;

      if (providerLoginStates[nextStatus.state]) {
        setStatus(nextStatus);
        setNodes([]);
        setSubscriptionURL("");
        setLoadError("");
        return nextStatus;
      }

      const [nextNodes, nextSubscription] = await Promise.all([
        api.nodes(),
        api.subscriptionURL(),
      ]);
      if (revision !== sessionRevision.current) return null;

      setStatus(nextStatus);
      setNodes(nextNodes.nodes);
      setSubscriptionURL(nextSubscription.url);
      setLoadError("");
      return nextStatus;
    } catch (error) {
      if (revision !== sessionRevision.current) return null;
      if (isSessionProblem(error)) {
        loseAccessSession();
        return null;
      }
      setLoadError(describeError(error));
      return null;
    }
  }, [api, loseAccessSession]);

  const queueAuthenticatedReload = useCallback(() => {
    if (accountLogoutInFlight.current) return;
    const work = reloadWork.current;
    work.queued = true;
    work.revision = sessionRevision.current;
    if (work.scheduled || work.running) return;

    work.scheduled = true;
    queueMicrotask(async () => {
      work.scheduled = false;
      while (work.queued && work.revision === sessionRevision.current) {
        work.queued = false;
        work.running = true;
        const revision = work.revision;
        await loadAuthenticatedData();
        work.running = false;
        if (revision !== sessionRevision.current) {
          work.queued = false;
          return;
        }
      }
    });
  }, [loadAuthenticatedData]);

  useEffect(() => {
    const updateRoute = () => setRoute(routeFromLocation());
    window.addEventListener("popstate", updateRoute);
    return () => window.removeEventListener("popstate", updateRoute);
  }, []);

  useEffect(() => {
    if (window.location.pathname !== route) replaceRoute(route);
  }, [route]);

  useEffect(() => {
    if (session !== "available" && route !== "/") replaceRoute("/");
  }, [route, session]);

  useEffect(() => {
    if (session !== "available") return;
    const needsProviderLogin = !status || Boolean(providerLoginStates[status.state]);
    if (needsProviderLogin && route !== "/signin") replaceRoute("/signin");
    if (!needsProviderLogin && route === "/signin") replaceRoute("/");
  }, [route, session, status]);

  useEffect(() => {
    let active = true;
    api.accessStatus()
      .then((access) => {
        if (!active) return;
        if (!access.initialized) {
          setSession("setup");
          return;
        }
        if (!access.authenticated) {
          setSession("access_login");
          return;
        }
        sessionRevision.current += 1;
        setSession("available");
        queueAuthenticatedReload();
      })
      .catch((error: unknown) => {
        if (!active) return;
        setLoadError(describeError(error));
        setSession("access_login");
      });
    return () => { active = false; };
  }, [api, queueAuthenticatedReload]);

  useEffect(() => {
    if (session !== "available") return;
    let active = true;
    const closeEvents = api.events(
      (event: EventMessage) => {
        if (!active) return;
        if (event.type === "probe") {
          setNodes((previous) => previous.map((node) => node.id === event.nodeId ? {
            ...node,
            health: event.health,
            tcpLatencyMs: event.tcpLatencyMs,
          } : node));
          return;
        }
        queueAuthenticatedReload();
      },
      () => {
        if (!active) return;
        const now = Date.now();
        if (now < nextSSEFailureReloadAt.current) return;
        nextSSEFailureReloadAt.current = now + 1000;
        queueAuthenticatedReload();
      },
    );
    return () => {
      active = false;
      closeEvents();
    };
  }, [api, queueAuthenticatedReload, session]);

  const completeAccess = useCallback(() => {
    sessionRevision.current += 1;
    accountLogoutInFlight.current = false;
    setLoadError("");
    setSession("available");
    replaceRoute("/");
    queueAuthenticatedReload();
  }, [queueAuthenticatedReload]);

  const setupAccess = async (token: string): Promise<void> => {
    await api.setupAccess(token);
    completeAccess();
  };

  const loginAccess = async (token: string): Promise<void> => {
    await api.loginAccess(token);
    completeAccess();
  };

  const loginAccount = async (account: string, password: string): Promise<void> => {
    accountLogoutInFlight.current = false;
    const revision = sessionRevision.current;
    await api.login(account, password);
    if (revision !== sessionRevision.current) return;
    await loadAuthenticatedData();
    if (revision === sessionRevision.current) replaceRoute("/");
  };

  const signOutAccount = async (): Promise<void> => {
    accountLogoutInFlight.current = true;
    const revision = ++sessionRevision.current;
    reloadWork.current.queued = false;
    clearConsoleData();
    setSession("access_login");
    replaceRoute("/");

    let operationError: unknown;
    try {
      await api.logoutAccount();
    } catch (error) {
      operationError = error;
    }
    try {
      await api.lockConsole();
    } catch (error) {
      if (!operationError) operationError = error;
    } finally {
      api.clearSession();
      accountLogoutInFlight.current = false;
    }
    if (revision === sessionRevision.current && operationError && !isSessionProblem(operationError)) {
      setLoadError(describeError(operationError));
    }
  };

  const lockConsole = async (): Promise<void> => {
    accountLogoutInFlight.current = false;
    const revision = ++sessionRevision.current;
    reloadWork.current.queued = false;
    clearConsoleData();
    setSession("access_login");
    replaceRoute("/");
    try {
      await api.lockConsole();
    } catch (error) {
      if (revision === sessionRevision.current && !isSessionProblem(error)) setLoadError(describeError(error));
    } finally {
      api.clearSession();
    }
  };

  const refreshAll = async (): Promise<void> => {
    const revision = sessionRevision.current;
    setRefreshing(true);
    setLoadError("");
    try {
      await api.refresh();
      if (revision === sessionRevision.current) await loadAuthenticatedData();
    } catch (error) {
      if (revision !== sessionRevision.current) return;
      if (isSessionProblem(error)) {
        loseAccessSession();
        return;
      }
      setLoadError(describeError(error));
    } finally {
      if (revision === sessionRevision.current) setRefreshing(false);
    }
  };

  const getSessionRevision = useCallback(() => sessionRevision.current, []);

  let content;
  if (session === "checking") {
    content = <LoadingCard />;
  } else if (session === "setup") {
    content = <AccessTokenCard mode="setup" onSubmit={setupAccess} error={loadError} />;
  } else if (session === "access_login") {
    content = <AccessTokenCard mode="login" onSubmit={loginAccess} error={loadError} />;
  } else if (!status || route === "/signin" || providerLoginStates[status.state]) {
    content = <ProviderLoginCard onSubmit={loginAccount} error={loadError} />;
  } else {
    content = (
      <StatusConsole
        api={api}
        getSessionRevision={getSessionRevision}
        loadError={loadError}
        nodes={nodes}
        onAccessLost={loseAccessSession}
        onLockConsole={lockConsole}
        onNodesChange={setNodes}
        onRefreshAll={refreshAll}
        onSignOutAccount={signOutAccount}
        refreshing={refreshing}
        status={status}
        subscriptionURL={subscriptionURL}
      />
    );
  }

  return <TooltipProvider delayDuration={150}>{content}</TooltipProvider>;
}

function AuthCardShell({ children }: { children: ReactNode }) {
  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-10 text-foreground">
      <div className="boot w-full max-w-md">
        <div className="mb-5 flex items-end justify-between gap-4 px-1">
          <div>
            <p className="glow font-sans text-lg font-bold uppercase tracking-[0.34em] text-primary">Kfadapter</p>
            <p className="mt-1 text-[0.625rem] uppercase tracking-[0.24em] text-muted-foreground">Local control plane</p>
          </div>
          <div aria-hidden="true" className="mb-1.5 flex items-center gap-1.5">
            <span className="led led--ok" />
            <span className="led led--warn led--pulse" />
            <span className="led" />
          </div>
        </div>
        <Card className="panel w-full">
          {children}
          <CardFooter className="justify-between border-t border-dashed border-border/70 pt-4 text-[0.625rem] uppercase tracking-[0.22em] text-muted-foreground [&.border-t]:pt-4">
            <span>Console access</span>
            <span aria-hidden="true">▪ ▪ ▪</span>
          </CardFooter>
        </Card>
      </div>
    </main>
  );
}

function LoadingCard() {
  return (
    <AuthCardShell>
      <CardHeader>
        <h1 className="flex items-center gap-2.5 font-sans text-lg font-semibold uppercase tracking-[0.05em]"><LoaderCircle className="size-5 animate-spin text-primary" />Opening kfadapter</h1>
        <CardDescription>Checking console access.</CardDescription>
      </CardHeader>
    </AuthCardShell>
  );
}

function AccessTokenCard({
  mode,
  onSubmit,
  error,
}: {
  mode: "setup" | "login";
  onSubmit: (token: string) => Promise<void>;
  error: string;
}) {
  const [token, setToken] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState("");
  const isSetup = mode === "setup";

  const clearFields = () => {
    setToken("");
    setConfirmation("");
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const submittedToken = token.trim();
    const submittedConfirmation = confirmation.trim();
    clearFields();

    const tokenBytes = new TextEncoder().encode(submittedToken).byteLength;
    if (tokenBytes < 16 || tokenBytes > 128) {
      setLocalError("That access token is too short or too long.");
      return;
    }
    if (isSetup && submittedToken !== submittedConfirmation) {
      setLocalError("The access tokens do not match.");
      return;
    }

    setSubmitting(true);
    setLocalError("");
    try {
      await onSubmit(submittedToken);
    } catch (requestError) {
      setLocalError(describeError(requestError));
    } finally {
      clearFields();
      setSubmitting(false);
    }
  };

  return (
    <AuthCardShell>
      <CardHeader>
        <h1 className="font-sans text-xl font-semibold uppercase tracking-[0.05em]">{isSetup ? "Create console access" : "Unlock console"}</h1>
        <CardDescription>{isSetup ? "Set an access token for this console." : "Enter your access token to continue."}</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4" noValidate onSubmit={submit}>
          <FormError message={localError || error} />
          <Field label="Access token" name="access-token">
            <Input
              autoComplete="off"
              id="access-token"
              name="access-token"
              onChange={(event) => setToken(event.currentTarget.value)}
              type="password"
              value={token}
            />
          </Field>
          {isSetup ? (
            <Field label="Confirm access token" name="access-token-confirmation">
              <Input
                autoComplete="off"
                id="access-token-confirmation"
                name="access-token-confirmation"
                onChange={(event) => setConfirmation(event.currentTarget.value)}
                type="password"
                value={confirmation}
              />
            </Field>
          ) : null}
          <Button className="mt-2 w-full" disabled={submitting} type="submit">
            {submitting ? <><LoaderCircle className="size-4 animate-spin" />Checking</> : isSetup ? "Create access" : "Continue"}
          </Button>
        </form>
      </CardContent>
    </AuthCardShell>
  );
}

function ProviderLoginCard({
  onSubmit,
  error,
}: {
  onSubmit: (account: string, password: string) => Promise<void>;
  error: string;
}) {
  const [account, setAccount] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState("");

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const email = account.trim();
    const submittedPassword = password;
    setPassword("");
    if (!email || !submittedPassword) {
      setLocalError("Enter your email and password.");
      return;
    }

    setSubmitting(true);
    setLocalError("");
    try {
      await onSubmit(email, submittedPassword);
      setAccount("");
    } catch (requestError) {
      setLocalError(describeError(requestError));
    } finally {
      setPassword("");
      setSubmitting(false);
    }
  };

  return (
    <AuthCardShell>
      <CardHeader>
        <h1 className="font-sans text-xl font-semibold uppercase tracking-[0.05em]">Connect account</h1>
        <CardDescription>Sign in to load your nodes.</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4" noValidate onSubmit={submit}>
          <FormError message={localError || error} />
          <Field label="Email" name="account">
            <Input
              autoComplete="off"
              id="account"
              inputMode="email"
              name="account"
              onChange={(event) => setAccount(event.currentTarget.value)}
              type="email"
              value={account}
            />
          </Field>
          <Field label="Password" name="password">
            <Input
              autoComplete="off"
              id="password"
              name="password"
              onChange={(event) => setPassword(event.currentTarget.value)}
              type="password"
              value={password}
            />
          </Field>
          <Button className="mt-2 w-full" disabled={submitting} type="submit">
            {submitting ? <><LoaderCircle className="size-4 animate-spin" />Signing in</> : "Sign in"}
          </Button>
        </form>
      </CardContent>
    </AuthCardShell>
  );
}

function Field({ label, name, children }: { label: string; name: string; children: ReactNode }) {
  return (
    <label className="grid gap-2" htmlFor={name}>
      <span className="text-[0.65rem] font-semibold uppercase tracking-[0.2em] text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}

function FormError({ message }: { message: string }) {
  return message ? (
    <p className="flex items-start gap-2.5 rounded-sm border border-destructive/35 bg-destructive/10 px-3 py-2.5 text-[0.8125rem] leading-5 text-destructive" role="alert">
      <span aria-hidden="true" className="led led--err led--pulse mt-1.5" />
      <span className="min-w-0">{message}</span>
    </p>
  ) : null;
}

function StatusConsole({
  api,
  getSessionRevision,
  loadError,
  nodes,
  onAccessLost,
  onLockConsole,
  onNodesChange,
  onRefreshAll,
  onSignOutAccount,
  refreshing,
  status,
  subscriptionURL,
}: {
  api: ApiClient;
  getSessionRevision: () => number;
  loadError: string;
  nodes: NodeRecord[];
  onAccessLost: () => void;
  onLockConsole: () => Promise<void>;
  onNodesChange: Dispatch<SetStateAction<NodeRecord[]>>;
  onRefreshAll: () => Promise<void>;
  onSignOutAccount: () => Promise<void>;
  refreshing: boolean;
  status: StatusResponse;
  subscriptionURL: string;
}) {
  const detail = stateDetails[status.state];
  const [copyMessage, setCopyMessage] = useState("");

  const copySubscription = async () => {
    if (!subscriptionURL) return;
    try {
      if (!navigator.clipboard?.writeText) throw new Error();
      await navigator.clipboard.writeText(subscriptionURL);
      setCopyMessage("Link copied.");
    } catch {
      setCopyMessage("Copy is unavailable.");
    }
  };

  return (
    <main className="min-h-screen bg-background px-4 py-6 text-foreground sm:px-6 lg:px-10">
      <div className="boot mx-auto grid w-full max-w-6xl gap-6">
        <header className="border-b border-dashed border-border pb-5">
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            <p className="glow font-sans text-sm font-bold uppercase tracking-[0.34em] text-primary">Kfadapter</p>
            <p className="hidden text-[0.625rem] uppercase tracking-[0.24em] text-muted-foreground sm:block">Local control plane · v{status.version}</p>
          </div>
          <div className="mt-4 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
            <div>
              <div className="flex flex-nowrap items-center gap-2 sm:gap-3">
                <h1 className="whitespace-nowrap font-sans text-xl font-semibold uppercase tracking-[0.04em] sm:text-2xl">Service status</h1>
                <StatusBadge detail={detail} />
              </div>
              {status.state === "ready" ? null : <p className="mt-2 text-sm text-muted-foreground">{detail.message}</p>}
            </div>
            <div className="flex flex-nowrap items-center gap-1 sm:gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button aria-label="Refresh account and node list" disabled={refreshing} onClick={() => void onRefreshAll()} size="icon-sm" variant="outline">
                    <RefreshCw className={refreshing ? "size-4 animate-spin" : "size-4"} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Refresh account and node list</TooltipContent>
              </Tooltip>
              <Button aria-label="Sign out account" onClick={() => void onSignOutAccount()} size="sm" variant="outline">
                <LogOut className="size-4" />
                <span aria-hidden="true" className="sm:hidden">Sign out</span>
                <span aria-hidden="true" className="hidden sm:inline">Sign out account</span>
              </Button>
              <Button aria-label="Lock console" onClick={() => void onLockConsole()} size="sm" variant="outline">
                <LockKeyhole className="size-4" />
                <span aria-hidden="true" className="sm:hidden">Lock</span>
                <span aria-hidden="true" className="hidden sm:inline">Lock console</span>
              </Button>
            </div>
          </div>
        </header>

        {loadError ? <FormError message={loadError} /> : null}

        <section className="grid gap-4 md:grid-cols-[1.4fr_1fr]">
          <Card className="panel">
            <CardHeader>
              <CardTitle>Service</CardTitle>
              <CardDescription>Current local activity.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-5 sm:grid-cols-2">
              <Metric label="Account" value={status.account?.display || "Connected"} />
              <Metric label="Available nodes" value={`${status.nodes.eligible} / ${status.nodes.total}`} />
            </CardContent>
            <CardFooter className="gap-2 text-xs text-muted-foreground">
              <span aria-hidden="true" className={`led ${refreshing ? "led--warn led--pulse" : "led--ok"}`} />
              Updated {formatTime(status.controlPlane.lastRefreshAt)}
            </CardFooter>
          </Card>

          <Card className="panel">
            <CardHeader>
              <CardTitle>Subscription link</CardTitle>
              <CardDescription>Generation {status.subscription.generation}</CardDescription>
              <CardAction>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button aria-label="Copy subscription link" disabled={!subscriptionURL} onClick={() => void copySubscription()} size="icon" variant="ghost">
                      <Copy className="size-4" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Copy link</TooltipContent>
                </Tooltip>
              </CardAction>
            </CardHeader>
            <CardContent>
              <code className="readout block break-all rounded-sm border border-border/70 px-3 py-2.5 text-xs leading-5 text-primary/90">
                {subscriptionURL || "Loading link…"}
              </code>
              <p aria-live="polite" className="mt-2 min-h-5 text-xs text-muted-foreground" role="status">{copyMessage}</p>
            </CardContent>
          </Card>
        </section>

        <NodeList
          api={api}
          getSessionRevision={getSessionRevision}
          nodes={nodes}
          onAccessLost={onAccessLost}
          onNodesChange={onNodesChange}
        />
      </div>
    </main>
  );
}

function StatusBadge({ detail }: { detail: StatusDetail }) {
  const tone = {
    ready: { badge: "border-led-ok/35 bg-led-ok/10 text-led-ok", led: "led--ok" },
    working: { badge: "border-led-warn/35 bg-led-warn/10 text-led-warn", led: "led--warn led--pulse" },
    warning: { badge: "border-led-warn/35 bg-led-warn/10 text-led-warn", led: "led--warn" },
    danger: { badge: "border-destructive/35 bg-destructive/10 text-destructive", led: "led--err" },
    neutral: { badge: "border-border bg-muted text-muted-foreground", led: "" },
  }[detail.tone];
  return (
    <Badge className={`h-8 gap-2 px-2.5 ${tone.badge}`} variant="outline">
      <span aria-hidden="true" className={`led ${tone.led}`} />
      {detail.label}
    </Badge>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-l border-primary/40 pl-3">
      <p className="text-[0.65rem] font-semibold uppercase tracking-[0.2em] text-muted-foreground">{label}</p>
      <p className="mt-1.5 break-words font-sans text-2xl font-semibold leading-tight tabular-nums">{value}</p>
    </div>
  );
}

function NodeList({
  api,
  getSessionRevision,
  nodes,
  onAccessLost,
  onNodesChange,
}: {
  api: ApiClient;
  getSessionRevision: () => number;
  nodes: NodeRecord[];
  onAccessLost: () => void;
  onNodesChange: Dispatch<SetStateAction<NodeRecord[]>>;
}) {
  const [activeProbe, setActiveProbe] = useState<string | null>(null);
  const [probingAll, setProbingAll] = useState(false);
  const active = useRef(true);

  useEffect(() => () => { active.current = false; }, []);

  const markProbeFailed = (nodeId: string) => {
    onNodesChange((previous) => previous.map((current) => current.id === nodeId ? {
      ...current,
      health: "unhealthy",
      tcpLatencyMs: undefined,
    } : current));
  };

  const probe = async (node: NodeRecord) => {
    const revision = getSessionRevision();
    setActiveProbe(node.id);
    try {
      const result = await api.probeNode(node.id);
      if (!active.current || revision !== getSessionRevision()) return;
      onNodesChange((previous) => previous.map((current) => current.id === node.id ? {
        ...current,
        health: result.health,
        tcpLatencyMs: result.tcpLatencyMs,
      } : current));
    } catch (requestError) {
      if (!active.current || revision !== getSessionRevision()) return;
      if (isSessionProblem(requestError)) {
        onAccessLost();
        return;
      }
      markProbeFailed(node.id);
    } finally {
      if (active.current && revision === getSessionRevision()) setActiveProbe(null);
    }
  };

  const groupedNodes = useMemo(() => {
    const groups = new Map<string, NodeRecord[]>();
    for (const node of nodes) {
      const group = node.group.trim() || "Ungrouped";
      const members = groups.get(group);
      if (members) members.push(node);
      else groups.set(group, [node]);
    }
    return [...groups.entries()]
      .sort(([left], [right]) => compareGroupNames(left, right))
      .map(([group, members]) => [group, members.sort((left, right) => groupNameCollator.compare(left.name, right.name))] as const);
  }, [nodes]);

  const probeAll = async () => {
    if (nodes.length === 0) return;
    const revision = getSessionRevision();
    setProbingAll(true);
    try {
      for (const [, members] of groupedNodes) {
        for (const node of members) {
          if (!active.current || revision !== getSessionRevision()) return;
          try {
            const result = await api.probeNode(node.id);
            if (!active.current || revision !== getSessionRevision()) return;
            onNodesChange((previous) => previous.map((current) => current.id === node.id ? {
              ...current,
              health: result.health,
              tcpLatencyMs: result.tcpLatencyMs,
            } : current));
          } catch (requestError) {
            if (!active.current || revision !== getSessionRevision()) return;
            if (isSessionProblem(requestError)) {
              onAccessLost();
              return;
            }
            markProbeFailed(node.id);
          }
        }
      }
    } finally {
      if (active.current && revision === getSessionRevision()) setProbingAll(false);
    }
  };


  return (
    <Card className="panel min-w-0">
      <CardHeader>
        <CardTitle>Nodes</CardTitle>
        <CardDescription>{nodes.length} available</CardDescription>
        <CardAction>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button aria-label="Probe all nodes" disabled={probingAll || activeProbe !== null || nodes.length === 0} onClick={() => void probeAll()} size="icon" variant="ghost">
                <Gauge className={probingAll ? "size-4 animate-pulse" : "size-4"} />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Probe all latency</TooltipContent>
          </Tooltip>
        </CardAction>
      </CardHeader>
      <CardContent className="min-w-0">
        <div aria-label="Nodes by group" className="grid gap-2.5" role="tree">
          {groupedNodes.map(([group, members], groupIndex) => (
            <details aria-label={`${group} group`} className="node-group overflow-hidden rounded-sm border border-border bg-background/40" key={group} role="treeitem">
              <summary className="flex cursor-pointer list-none items-center gap-2.5 px-3 py-2.5 text-sm font-medium transition-colors hover:bg-primary/5 [&::-webkit-details-marker]:hidden">
                <ChevronRight aria-hidden="true" className="node-group__chevron size-4 text-muted-foreground" />
                <span aria-hidden="true" className="font-sans text-xs font-semibold tabular-nums text-primary/80">{String(groupIndex + 1).padStart(2, "0")}</span>
                <span className="min-w-0 flex-1 truncate">{group}</span>
                <Badge variant="secondary">{members.length}</Badge>
              </summary>
              <div className="node-group__content" role="group">
                <div className="node-group__content-inner divide-y divide-border border-t border-border">
                {members.map((node) => (
                  <article aria-label={node.name} className="grid gap-3 p-3 transition-colors hover:bg-primary/[0.04] sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-center" key={node.id} role="treeitem">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{node.name}</p>
                      <p className="mt-0.5 text-[0.65rem] uppercase tracking-[0.18em] text-muted-foreground">{node.provider}</p>
                    </div>
                    <LatencyReadout node={node} />
                    <div className="flex justify-end gap-1">
                      <NodeDetailsPopover api={api} getSessionRevision={getSessionRevision} node={node} onAccessLost={onAccessLost} />
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button aria-label={`Probe ${node.name}`} disabled={probingAll || activeProbe !== null} onClick={() => void probe(node)} size="icon" variant="ghost">
                            <Gauge className={activeProbe === node.id ? "size-4 animate-pulse" : "size-4"} />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Probe latency</TooltipContent>
                      </Tooltip>
                    </div>
                  </article>
                ))}
                </div>
              </div>
            </details>
          ))}
        </div>
        {groupedNodes.length === 0 ? <p className="px-1 py-8 text-sm text-muted-foreground">No nodes available.</p> : null}
      </CardContent>
    </Card>
  );
}

function LatencyReadout({ node }: { node: NodeRecord }) {
  const timedOut = node.health === "unhealthy" && typeof node.tcpLatencyMs !== "number";
  const text = timedOut ? "Timeout" : formatLatency(node.tcpLatencyMs);
  const tone: Record<NodeHealth, string> = {
    healthy: "text-led-ok",
    degraded: "text-led-warn",
    unhealthy: "text-led-err",
    unknown: "text-muted-foreground",
  };
  return (
    <span
      aria-label={`Latency ${text}, ${healthLabel(node.health)}`}
      className={`text-xs font-medium tabular-nums sm:text-right ${tone[node.health]}`}
    >
      {text}
    </span>
  );
}

function NodeDetailsPopover({
  api,
  getSessionRevision,
  node,
  onAccessLost,
}: {
  api: ApiClient;
  getSessionRevision: () => number;
  node: NodeRecord;
  onAccessLost: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [details, setDetails] = useState<NodeDetails | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const requestId = useRef(0);

  useEffect(() => () => { requestId.current += 1; }, []);

  const onOpenChange = (nextOpen: boolean) => {
    requestId.current += 1;
    const currentRequest = requestId.current;
    setOpen(nextOpen);
    setDetails(null);
    setError("");
    setLoading(nextOpen);
    if (!nextOpen) return;

    const revision = getSessionRevision();
    api.nodeDetails(node.id)
      .then((response) => {
        if (currentRequest !== requestId.current || revision !== getSessionRevision()) return;
        setDetails(response);
      })
      .catch((requestError: unknown) => {
        if (currentRequest !== requestId.current || revision !== getSessionRevision()) return;
        if (isSessionProblem(requestError)) {
          onAccessLost();
          return;
        }
        setError(describeError(requestError));
      })
      .finally(() => {
        if (currentRequest === requestId.current && revision === getSessionRevision()) setLoading(false);
      });
  };

  return (
    <Popover onOpenChange={onOpenChange} open={open}>
      <Tooltip>
        <TooltipTrigger asChild>
          <PopoverTrigger asChild>
            <Button aria-label={`Details for ${node.name}`} size="icon" variant="ghost">
              <Info className="size-4" />
            </Button>
          </PopoverTrigger>
        </TooltipTrigger>
        <TooltipContent>Details</TooltipContent>
      </Tooltip>
      <PopoverContent align="end" className="panel w-[min(25rem,calc(100vw-2rem))] p-0">
        <div className="flex flex-col gap-4 py-4">
          <div className="grid gap-1 px-4">
            <h2 className="font-sans text-sm font-semibold uppercase tracking-[0.1em]">{node.name}</h2>
            <p className="text-xs text-muted-foreground">{node.group} · {node.provider}</p>
          </div>
          <div className="px-4">
            {loading ? <p className="flex items-center gap-2 text-sm text-muted-foreground"><LoaderCircle className="size-4 animate-spin" />Loading details</p> : null}
            {error ? <FormError message={error} /> : null}
            {details ? <NodeDetailsView details={details} /> : null}
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function NodeDetailsView({ details }: { details: NodeDetails }) {
  return (
    <dl className="grid gap-2.5 text-sm">
      <DetailRow label="Upstream" value={`${details.upstreamHost}:${details.upstreamPort}`} />
      <DetailRow label="Local SOCKS" value={details.socksAddress} />
      <DetailRow label="SOCKS username" value={details.socksUsername} />
      <DetailRow label="SOCKS password" value={details.socksPassword} />
      <div className="grid grid-cols-3 gap-3 border-t border-dashed border-border pt-3">
        <DetailRow label="Health" value={healthLabel(details.health)} />
        <DetailRow label="Latency" value={formatLatency(details.tcpLatencyMs)} />
        <DetailRow label="Generation" value={String(details.generation)} />
      </div>
    </dl>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[0.625rem] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all font-mono text-xs text-primary/90">{value}</dd>
    </div>
  );
}
