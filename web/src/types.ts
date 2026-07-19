export type ServiceState =
  | "signed_out"
  | "authenticating"
  | "syncing"
  | "ready"
  | "degraded"
  | "expired"
  | "error";

export type NodeHealth = "healthy" | "degraded" | "unhealthy" | "unknown";

export interface AccountSummary {
  display: string;
  isVip: boolean;
  vipEndsAt?: string;
}

export interface StatusResponse {
  state: ServiceState;
  version: string;
  deployment: {
    mode: "container" | string;
    startedAt?: string;
  };
  account?: AccountSummary;
  controlPlane: {
    lastRefreshAt?: string;
    nextRefreshAt?: string;
  };
  dataPlane: {
    socksAddress: string;
    udpMode: "disabled_unverified" | string;
  };
  nodes: {
    total: number;
    eligible: number;
    healthy: number;
  };
  subscription: {
    active: boolean;
    generation: number;
    nodeCount: number;
    lastFetchedAt?: string;
    lastFetchedGeneration?: number;
    reloadRecommended: boolean;
  };
}

export interface NodeRecord {
  id: string;
  name: string;
  group: string;
  provider: string;
  health: NodeHealth;
  tcpLatencyMs?: number;
  udpHealth: "unavailable" | "healthy" | "unhealthy" | string;
  eligible: boolean;
  compatibilityError?: string;
}

export interface NodeDetails {
  id: string;
  name: string;
  group: string;
  provider: string;
  upstreamHost: string;
  upstreamPort: number;
  socksAddress: string;
  socksUsername: string;
  socksPassword: string;
  health: NodeHealth;
  tcpLatencyMs?: number;
  generation: number;
}

export interface NodesResponse {
  nodes: NodeRecord[];
}

export interface SubscriptionMetadata {
  active: boolean;
  generation: number;
  nodeCount: number;
  lastFetchedAt?: string;
  lastFetchedGeneration?: number;
  reloadRecommended: boolean;
}

export interface SubscriptionURLResponse {
  url: string;
  generation: number;
}


export interface AccessStatusResponse {
  initialized: boolean;
  authenticated: boolean;
  csrfToken?: string;
  expiresAt?: string;
}

export interface AccessSessionResponse {
  csrfToken?: string;
  expiresAt?: string;
}

export interface LoginResponse {
  account?: AccountSummary;
  status?: StatusResponse;
}

export interface ProbeResult {
  nodeId: string;
  health: NodeHealth;
  tcpLatencyMs?: number;
  probedAt: string;
}

export type EventMessage =
  | { type: "state"; state: ServiceState; generation?: number }
  | { type: "refresh"; state: ServiceState; generation?: number; complete: boolean }
  | { type: "probe"; nodeId: string; health: NodeHealth; tcpLatencyMs?: number; probedAt: string };
