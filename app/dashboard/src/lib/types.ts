// Shared API types — legacy admin API (/api/*) + Zagros admin API (/api/zagros/*).

export interface Token { access_token: string; token_type: string }

export interface Admin { username: string; is_sudo: boolean }

// governance fields ride the same /admin(s) models.
export interface AdminUser {
  username: string;
  is_sudo: boolean;
  telegram_id?: number | null;
  discord_webhook?: string | null;
  users_usage?: number | null;
  created_at?: string | null;
  max_users?: number | null;
  expire_at?: string | null;
  traffic_alloc_limit?: number | null;
  traffic_consume_limit?: number | null;
  /** aggregates attached by the list endpoint */
  users_count?: number | null;
  users_lifetime_usage?: number | null;
  users_allocated_traffic?: number | null;
}

export type UserStatus = "active" | "disabled" | "limited" | "expired" | "on_hold";

export interface User {
  username: string;
  status: UserStatus;
  used_traffic: number;
  data_limit: number | null;
  lifetime_used_traffic?: number;
  expire: number | null;
  /** epoch seconds — on-hold users */
  on_hold_expire_duration?: number | null;
  data_limit_reset_strategy?: string;
  note?: string | null;
  sub_url?: string;
  /** the field the legacy API actually sends — a RELATIVE /sub/... path */
  subscription_url?: string;
  /** global device limit (all cores combined); null/0 = unlimited */
  ip_limit?: number | null;
  device_limit?: number | null;
  /** aggregate across every core/connection; 0 = unlimited */
  download_limit_mbps: number;
  upload_limit_mbps: number;
  sub_updated_at?: string | null;
  sub_last_user_agent?: string | null;
  online_at?: string | null;
  created_at: string;
  /** legacy API returns the admin object on some deployments, the username on others */
  admin?: string | { username?: string } | null;
  telegram_id?: number | null;
  app_username?: string | null;
  proxies?: Record<string, Record<string, unknown>>;
  inbounds?: Record<string, string[]>;
  excluded_inbounds?: Record<string, string[]>;
  /** multi-core grants: core_id → inbound tags */
  core_access?: Record<string, string[]> | null;
}

export interface UsersResponse { users: User[]; total: number }

/** A remote Zagros node (multi-core agent). Pairing: pending → connected. */
export interface Node {
  id: number;
  name: string;
  address: string;
  port: number;          // HTTPS control plane (signed commands)
  api_port: number;      // read-only bootstrap/info port
  usage_coefficient: number;
  add_as_new_host: boolean;
  status: string;        // pending | connected | error
  agent_type: string;    // zagros_native
  agent_identity?: string | null;
  certificate_fingerprint?: string | null;
  agent_version?: string | null;
  last_seen?: string | null;
  last_error?: string | null;
  pending: boolean;
  health?: {
    healthy?: boolean;
    uptime_seconds?: number;
    resources?: Record<string, number | number[] | null>;
  } | null;
  cores?: NodeCores | null;
}

/** One node's core inventory: installed state + installable catalog. */
export interface NodeCores {
  installed: Record<string, NodeCoreStatus>;
  available: string[];
  preview: Record<string, NodeCatalogEntry>;
  stale?: boolean;
  error?: string | null;
}

export interface NodeCoreStatus {
  core_id: string;
  state: string;          // installed | running | stopped | error | ...
  health?: string | null;
  core_version?: string | null;
  version_reason?: string | null;
  message?: string | null;
  enabled?: boolean;
  pid?: number | null;
  uptime_seconds?: number | null;
  metrics?: CoreMetrics | null;
  binary_path?: string | null;
  settings?: Record<string, unknown>;
}

/** Catalog row for a core that is installable on a node. */
export interface NodeCatalogEntry {
  id: string;
  name: string;
  description?: string | null;
  protocols: string[];
  capabilities: string[];
  config_schema?: Record<string, unknown> | null;
  default_settings?: Record<string, unknown>;
  security_class?: string | null;
  homepage?: string | null;
  installed: boolean;
}

/** What a node publishes on its info port before it is trusted. */
export interface NodeDiscovery {
  reachable: boolean;
  node_id?: string | null;
  name?: string | null;
  agent_version?: string | null;
  certificate_sha256?: string | null;
  certificate_not_after?: string | null;
  registered?: boolean | null;
  pending_token?: boolean | null;
  control_plane_port?: number | null;
  already_paired?: boolean;
  error?: string | null;
}

export interface InstallerCommand {
  command: string;
  panel_id: string;
  registration_token?: string | null;
  notes: string[];
}

export interface NodeList { nodes: Node[] }
export interface NodeCoresResponse extends NodeCores {}
export interface SyncResult {
  node_id: number;
  pushed: { core_id: string; inbound_count: number }[];
  skipped: { core_id: string; reason: string }[];
  hosts: string[];
  errors: string[];
}

export interface NodesUsage { usages: { node_id: number; node_name: string; uplink: number; downlink: number }[] }

export interface SystemStats {
  version: string;
  mem_total: number;
  mem_used: number;
  cpu_cores: number;
  cpu_usage: number;
  total_user: number;
  online_users: number;
  users_active: number;
  incoming_bandwidth: number;
  outgoing_bandwidth: number;
  incoming_bandwidth_speed: number;
  outgoing_bandwidth_speed: number;
}

export interface InboundTag { tag: string; protocol: string; port: number | string; network?: string; tls?: string; sni?: string; host?: string; path?: string }
export type HostsMap = Record<string, { remark: string; address: string; port: number | null; sni: string; host: string; path: string; security: string; alpn: string; fingerprint: string; allowinsecure: boolean; is_disabled: boolean }[]>;

export interface UserTemplate {
  id: number;
  name: string;
  data_limit: number | null;
  expire_duration: number | null;
  username_prefix: string | null;
  username_suffix: string | null;
  inbounds: Record<string, string[]>;
  /** multi-core grants: core_id → inbound tags */
  core_access?: Record<string, string[]> | null;
}

/** Unified inbound catalog — one selectable tree across ALL cores. */
export interface InboundCatalogEntry {
  tag: string; protocol: string | null; port: number | null;
  source_core?: string; source_id?: string; duplicate_tag?: boolean;
  routing_only?: boolean; security_class?: string | null;
}
export interface InboundCatalogGroup {
  core_id: string; name: string; enabled: boolean;
  inbounds: InboundCatalogEntry[];
}

// ---------------- Zagros admin API ----------------

export interface CoreMetrics {
  cpu_percent?: number;
  memory_bytes?: number;
  /** real backend keys (app.cores.types.CoreMetrics) */
  network_rx_bytes?: number;
  network_tx_bytes?: number;
  active_accounts?: number;
  active_sessions?: number;
}

export interface CoreView {
  id: string;
  name: string;
  state: string; // installed|running|stopped|error|...
  enabled: boolean;
  /** panel-owned engine (xray): cannot be uninstalled/disabled/reinstalled */
  builtin?: boolean;
  health?: string | null;
  core_version?: string | null;
  version_reason?: string | null;
  pid?: number | null;
  uptime_seconds?: number | null;
  message?: string | null;
  metrics?: CoreMetrics | null;
  binary_path?: string | null;
  /** masked by the backend ("set (N chars)" for secrets) — display only */
  settings?: Record<string, unknown>;
  protocols: string[];
  capabilities: string[];
  config_schema?: Record<string, unknown> | null;
  description?: string | null;
  homepage?: string | null;
  /** non-null ⇒ the core hosts studio inbounds (wizard-capable) */
  studio_inbounds_path?: string | null;
  security_class?: string | null;
}

export interface CoreRegistryEntry {
  id: string; name: string; description?: string | null;
  protocols: string[]; capabilities: string[];
  provides: string[]; requires: string[];
  config_schema?: Record<string, unknown> | null;
  default_settings?: Record<string, unknown>;
  driver_version?: string | null;
  homepage?: string | null;
  security_class?: string | null;
  installed: boolean; enabled?: boolean; state?: string;
}

export interface RoutingRule {
  name: string;
  matcher: {
    inbounds?: string[];
    domains?: string[];
    domain_suffixes?: string[];
    geoips?: string[];
    ciders?: string[];
    source_ciders?: string[];
    ports?: string[];
    protocols?: string[];
    networks?: string[];
    process_names?: string[];
  };
  action: "allow" | "block" | "route_to" | "redirect" | "dns" | "fake_dns" | "dns_override";
  outbound?: string | null;
  redirect_to?: string | null;
  dns_server?: string | null;
  priority: number;
  enabled: boolean;
}

export interface RuleGap { rule: string; reason: string }
export interface RoutePreview {
  results: Record<string, { applied: string[]; unsupported: RuleGap[]; payload?: unknown }>;
}

export interface Outbound {
  name: string;
  kind: "direct" | "block" | "blackhole" | "dns" | "socks" | "http" | "vless" | "vmess" | "trojan" | "shadowsocks" | "wireguard" | "hysteria2" | "tuic" | "openvpn" | "ssh" | "l2tp_ipsec" | "l2tp_raw" | "sstp" | "pptp" | "softether_l2tp" | "softether_l2tp_raw" | "softether_sstp" | "softether_pptp" | "softether_native" | "core";
  settings: Record<string, unknown>;
  enabled: boolean;
  /** Secret values are never returned; true means leave blank to retain it. */
  secret_state?: Record<string, boolean>;
  /** Explicit deletion channel; an empty password input otherwise preserves. */
  clear_secret_keys?: string[];
  /** Opaque AES-GCM import capsule; never contains browser-readable secrets. */
  sealed_credentials?: string | null;
}

export interface OutboundTest {
  /** Public Test contract: no setup/PPP/HTTPS/first/p95 diagnostics. */
  status: "healthy" | "unhealthy";
  /** Post-readiness network RTT selected from the measurement window. */
  rtt_ms: number | null;
  error?: string;
  availability?: SupportState;
}

export type SupportState = "supported" | "unsupported" | "environment_limited" | "not_installed" | "not_applicable";
export interface OutboundCapability {
  state: SupportState;
  selectable: boolean;
  direction: "outbound";
  dataplane: "native_action" | "application_proxy" | "application_tcp" | "policy_tun" | "kernel_tun" | "dynamic_core" | "none";
  transports: string[];
  traffic_networks: ("tcp" | "udp")[];
  routing_contexts: ("policy_tun" | "native_application_tcp")[];
  routing_source_cores: string[];
  application_proxy: boolean;
  application_level: boolean;
  tun: boolean;
  kernel_routing: boolean;
  accounting: boolean;
  accounting_reason?: string | null;
  native_core_translation: string[];
  host_runtime?: string | null;
  provider?: string | null;
  protocol?: string | null;
  authentication: string[];
  ip_versions: string[];
  security_class: string;
  peer_compatibility: string[];
  reason?: string | null;
}
export interface OutboundsResponse {
  outbounds: Outbound[];
  capabilities: Record<string, OutboundCapability>;
}

export interface RoutingTarget {
  name: string;
  kind: Outbound["kind"];
  state: SupportState;
  selectable: boolean;
  direction: "outbound";
  dataplane: OutboundCapability["dataplane"];
  contexts: ("policy_tun" | "native_application_tcp")[];
  transports: string[];
  traffic_networks: ("tcp" | "udp")[];
  source_cores: string[];
  application_level: boolean;
  tun: boolean;
  reason?: string | null;
}

//: schema-driven outbound forms (/zagros/outbounds/schema)
export interface OutboundField {
  type?: string;
  title?: string;
  description?: string;
  default?: unknown;
  enum?: string[];
  minimum?: number;
  maximum?: number;
  "x-group"?: "basic" | "auth" | "transport" | "security";
  "x-widget"?: "text" | "password" | "textarea" | "number" | "select" | "toggle";
  "x-secret"?: boolean;
}
export interface OutboundKindSchema {
  type: string;
  description?: string;
  properties: Record<string, OutboundField>;
  required?: string[];
  "x-supported"?: boolean;
  "x-availability"?: SupportState;
  "x-capability"?: OutboundCapability;
  "x-disabled-reason"?: string;
  "x-security-class"?: string;
  "x-security-warning"?: string;
  "x-peer-compatibility"?: string[];
}
export type OutboundSchemas = Record<string, OutboundKindSchema>;

export interface ParsedShareURL {
  kind: Outbound["kind"];
  settings: Record<string, unknown>;
  name_hint?: string;
  protocol?: string;
  transport?: string;
  security?: string;
  supported_schemes: string[];
  secret_state?: Record<string, boolean>;
  sealed_credentials?: string | null;
}

export interface CoreRelease { tag: string; name?: string; prerelease: boolean; published_at?: string | null }

export interface SessionRecord {
  key: string; user_id: number; core_id: string; account_id: string; ip?: string | null;
  started_at: string; ended_at?: string | null; duration_seconds?: number | null;
  rx_bytes: number; tx_bytes: number;
}

export interface ClientSession {
  token_hash: string; user_id: number; username?: string | null;
  created_at?: string | null; expires_at?: string | null;
  revoked: boolean; rotated_to?: string | null; user_agent?: string | null;
}

export interface Device {
  id: number; device_id: string; user_id: number; username?: string | null;
  name?: string | null; platform?: string | null; app_version?: string | null;
  last_ip?: string | null; first_seen?: string | null; last_seen?: string | null;
  current_core?: string | null; cores?: string[];
}

export interface MonitoringConnection {
  key: string; user_id: number; username?: string | null; core_id: string;
  node_id?: number | null; node_name?: string | null; ip?: string | null;
  device?: string | null; started_at: string; last_activity: string;
  duration_seconds: number; upload_bytes: number; download_bytes: number;
  total_bytes: number; status: "active";
}

export interface MonitoringDevice {
  id: number; user_id: number; username: string; device: string;
  last_ip?: string | null; core_id?: string | null; node_id?: number | null;
  node_name?: string | null; first_seen: string; last_seen: string;
  status: "enrolled"; user_agent?: string | null;
}

export interface IPActivity {
  id: number; user_id: number; username: string; ip: string; core_id: string;
  node_id?: number | null; node_name?: string | null; first_seen: string;
  active_since: string; last_seen: string;
  status: "active" | "inactive" | "banned" | "unknown";
}

export interface TrafficPoint {
  bucket_start: string; upload_bytes: number; download_bytes: number;
  total_bytes: number;
}
export interface TrafficByCore {
  core_id: string; core_name: string; upload_bytes: number;
  download_bytes: number; total_bytes: number;
}
export interface TrafficByNode {
  node_id?: number | null; node_name: string; upload_bytes: number;
  download_bytes: number; total_bytes: number;
}
export interface StatisticsOverview {
  generated_at: string; total_traffic_bytes: number; upload_bytes: number;
  download_bytes: number; active_users: number; active_connections: number;
  total_nodes: number; total_cores: number; traffic_by_core: TrafficByCore[];
  traffic_by_node: TrafficByNode[]; monitoring_generated_at?: string | null;
  monitoring_partial: boolean; source: "usage_records";
}
export interface TrafficHistory {
  range: string; start: string; end: string; bucket_seconds: number;
  points: TrafficPoint[]; source: string;
}
export interface UserStatisticsOverview {
  user_id: number; username: string; status: string; total_traffic_bytes: number;
  upload_bytes: number; download_bytes: number; data_limit_bytes?: number | null;
  used_bytes: number; remaining_bytes?: number | null;
  usage_percentage?: number | null; updated_at?: string | null; source: string;
}
export interface UserTrafficStatistics extends TrafficHistory {
  upload_bytes: number; download_bytes: number; total_bytes: number;
  traffic_by_core: TrafficByCore[]; traffic_by_node: TrafficByNode[];
}

export interface CertificateInfo {
  name: string; path: string; subject: string; issuer: string;
  not_before: string; not_after: string; days_left: number;
  expired: boolean; self_signed: boolean; has_key: boolean; serial: string;
  /** stable delete identifier (data-dir-relative path) — item 18 */
  id: string;
  /** stored in the managed <data>/certs/<name>/ layout (vs scanned core cert) */
  managed: boolean;
}

export interface PanelNetworkSettings {
  domain?: string | null; port: number; scheme: "http" | "https";
  bind_address: string; trusted_proxies: string[];
  hsts: boolean; redirect_http_to_https: boolean;
  tls_certificate_id?: string | null;
}

export interface PanelInfo {
  version: string; app_name: string; domain: string;
  panel_base_url: string; app_base_url: string;
  client_auth_mode: string; subscription_path: string;
  tls_mode: string; uptime_seconds: number; database_driver: string;
}

export interface PortalSettings {
  portal_title: string; app_name: string; client_auth_mode: string;
  subscription_path: string; subscription_url_prefix?: string | null;
  public_domain?: string | null; custom_subdomain?: string | null;
  public_port?: number | null; public_scheme?: "http" | "https";
  tls_certificate_id?: string | null; force_https?: boolean;
  listener_mode?: "shared" | "dedicated" | "external_proxy";
  listen_address?: string;
  qr_base_url?: string | null;
  //: uploaded subscription page template (null = built-in)
  subscription_template?: string | null;
}

export interface SubscriptionTemplateFile {
  name: string; size: number; modified_at: number;
}

/** GET /zagros/subscription/templates — the files plus which one is active,
 *  whether that file still exists, and the last serve-time render failure
 *  (null when the active template renders fine). */
export interface SubscriptionTemplatesResponse {
  templates: SubscriptionTemplateFile[];
  active: string | null;
  active_exists: boolean;
  last_failure: { template: string; error: string; line: number | null; at: number } | null;
}

// Mirror of app/adminapi/dashboard.py DashboardSnapshot — flat fields,
// everything except the top counters optional (sudo surface; payloads may be
// minimal on degraded runtimes).
export interface DeployStatusView {
  deployed_at_available: boolean;
  per_core: Record<string, Record<string, unknown>>;
  unsupported_total: number;
}
export interface SnapshotCore {
  core_id: string; name: string; state: string; health: string; enabled: boolean;
  version?: string | null; version_reason?: string | null; uptime_seconds?: number | null;
  active_accounts?: number; active_sessions?: number; message?: string | null;
}
export interface SnapshotNode { node_id: number; name: string; address: string; status: string; last_seen?: string | null }
export interface SnapshotAlert { severity?: string; title?: string; message?: string; detail?: string; target?: string }
export interface Snapshot {
  generated_at: string;
  users_total: number;
  users_online: number;
  users_active?: number;
  usage_total_bytes: number;
  usage_by_core?: { core_id: string; uplink_bytes: number; downlink_bytes: number }[];
  cores?: SnapshotCore[];
  nodes?: SnapshotNode[];
  devices_active?: number;
  sessions_active?: number;
  routing_status?: DeployStatusView;
  outbound_status?: DeployStatusView;
  alerts?: SnapshotAlert[];
}

export interface StudioPatchOp { op: string; path: string; value?: unknown }
export interface StudioPreview {
  ok: boolean; changed: boolean;
  operations?: StudioPatchOp[];
  errors?: string[];
  warnings?: string[];
}
