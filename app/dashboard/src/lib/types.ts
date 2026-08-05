// Shared API types — legacy admin API (/api/*) + Zagros admin API (/api/zagros/*).

export interface Token { access_token: string; token_type: string }

export interface Admin { username: string; is_sudo: boolean }
export interface AdminUser { id: number; username: string; is_sudo: boolean; telegram_id?: number | null; discord_webhook?: string | null; enabled?: boolean }

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
  sub_updated_at?: string | null;
  sub_last_user_agent?: string | null;
  online_at?: string | null;
  created_at: string;
  admin?: string | null;
  telegram_id?: number | null;
  app_username?: string | null;
  proxies?: Record<string, Record<string, unknown>>;
  inbounds?: Record<string, string[]>;
  excluded_inbounds?: Record<string, string[]>;
}

export interface UsersResponse { users: User[]; total: number }

export interface Node {
  id: number;
  name: string;
  address: string;
  port: number;
  api_port: number;
  usage_coefficient: number;
  add_as_new_host: boolean;
  status: string; // connecting | connected | error | disabled
  message?: string | null;
  xray_version?: string | null;
  inbound_tags?: string[];
  certificate?: string;
}

export interface NodesUsage { usages: { node_id: number; node_name: string; uplink: number; downlink: number }[] }

export interface SystemStats {
  version: string;
  mem_total: number;
  mem_used: number;
  cpu_cores: number;
  cpu_usage: number;
  total_user: number;
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
}

// ---------------- Zagros admin API ----------------

export interface CoreMetrics { cpu_percent?: number; memory_bytes?: number; rx_bytes?: number; tx_bytes?: number; active_accounts?: number; active_sessions?: number }

export interface CoreView {
  id: string;
  name: string;
  state: string; // installed|running|stopped|error|...
  enabled: boolean;
  health?: string | null;
  core_version?: string | null;
  pid?: number | null;
  uptime_seconds?: number | null;
  message?: string | null;
  metrics?: CoreMetrics | null;
  binary_path?: string | null;
  settings_masked?: Record<string, string>;
  protocols: string[];
  capabilities: string[];
  config_schema?: Record<string, unknown> | null;
  description?: string | null;
  homepage?: string | null;
}

export interface CoreRegistryEntry {
  id: string; name: string; description?: string | null;
  protocols: string[]; capabilities: string[];
  provides: string[]; requires: string[];
  config_schema?: Record<string, unknown> | null;
  default_settings?: Record<string, unknown>;
  driver_version?: string | null;
  homepage?: string | null;
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
  kind: "direct" | "block" | "blackhole" | "dns" | "socks" | "http" | "vless" | "vmess" | "trojan" | "shadowsocks" | "wireguard" | "hysteria2" | "tuic" | "openvpn" | "ssh" | "core";
  settings: Record<string, unknown>;
  enabled: boolean;
}

export interface OutboundTest { ok: boolean; latency_ms: number | null; error?: string; detail?: string }

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

export interface CertificateInfo {
  name: string; subject_cn: string; issuer_cn: string;
  not_before: string; not_after: string; days_left: number;
  expired: boolean; self_signed: boolean; has_key: boolean; serial: string;
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
}

export interface Snapshot {
  version: string;
  uptime_seconds: number;
  totals: { users: number; active_users: number; online_users: number; devices: number; sessions: number };
  cores: { id: string; state: string; health?: string | null }[];
  alerts: { severity: string; title: string; detail?: string }[];
  bandwidth: { rx_bytes: number; tx_bytes: number };
}

export interface StudioPatchOp { op: string; path: string; value?: unknown }
export interface StudioPreview {
  ok: boolean; changed: boolean;
  operations?: StudioPatchOp[];
  errors?: string[];
  warnings?: string[];
}
