/**
 * Vault Connect API client.
 *
 * Config resolution (priority):
 * 1. OP_CONNECT_HOST + OP_CONNECT_TOKEN (op CLI compat, manual token)
 * 2. OP_CONNECT_HOST + GitHub Actions OIDC env vars (CI, no stored secret)
 * 3. crcl config (~/.config/crcl/config + credentials)
 *
 * CLI flags --profile and --org override crcl config values.
 */

import { existsSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { execSync } from "node:child_process"

const DEFAULT_VAULT_HOST = "https://vault.circles.ac"
const DEV_VAULT_HOST = "https://vault.crcl.es"

const OIDC_TOKEN_LEEWAY_MS = 60_000 // refresh 1 min before exp

type IniData = Record<string, Record<string, string>>

function parseIni(text: string): IniData {
  const data: IniData = {}
  let section = ""
  for (const raw of text.split("\n")) {
    const line = raw.trim()
    if (!line || line.startsWith("#") || line.startsWith(";")) continue
    const secMatch = line.match(/^\[(.+)\]$/)
    if (secMatch) {
      section = secMatch[1]!
      if (!data[section]) data[section] = {}
      continue
    }
    const eqIdx = line.indexOf("=")
    if (eqIdx > 0 && section) {
      data[section]![line.slice(0, eqIdx).trim()] = line.slice(eqIdx + 1).trim()
    }
  }
  return data
}

function crclConfigDir(): string {
  const xdg = process.env.XDG_CONFIG_HOME
  return join(xdg || join(process.env.HOME || homedir(), ".config"), "crcl")
}

function readCrclConfig(): IniData {
  const path = join(crclConfigDir(), "config")
  if (existsSync(path)) {
    try { return parseIni(readFileSync(path, "utf-8")) } catch { /* ignore */ }
  }
  return {}
}

function readCrclCredentials(): IniData {
  const path = join(crclConfigDir(), "credentials")
  if (existsSync(path)) {
    try { return parseIni(readFileSync(path, "utf-8")) } catch { /* ignore */ }
  }
  return {}
}

/** Get a fresh token via crcl auth token (handles refresh) */
function getCrclToken(profile: string): string | null {
  try {
    const args = profile !== "default" ? `--profile ${profile}` : ""
    return execSync(`crcl auth token ${args}`, { encoding: "utf-8", timeout: 10000, stdio: ["pipe", "pipe", "pipe"] }).trim()
  } catch {
    return null
  }
}

/** Detects GitHub Actions OIDC environment. Both vars are present together
 * when a workflow has `permissions: id-token: write`. */
export function hasGithubOidcEnv(env: NodeJS.ProcessEnv = process.env): boolean {
  return !!(env.ACTIONS_ID_TOKEN_REQUEST_URL && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)
}

let _oidcCache: { audience: string; token: string; expMs: number } | null = null

/** Reset the OIDC token cache. Exported for tests. */
export function _resetOidcCache() {
  _oidcCache = null
}

function parseJwtExpMs(token: string): number {
  try {
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString("utf8")
    ) as { exp?: number }
    return payload.exp ? payload.exp * 1000 : 0
  } catch {
    return 0
  }
}

/** Fetch a GitHub Actions OIDC ID token for the given audience.
 * Returns null when not running inside a GitHub Actions workflow, or when
 * the OIDC request fails (caller falls back to other auth methods). */
export async function fetchGithubOidcToken(
  audience: string,
  env: NodeJS.ProcessEnv = process.env
): Promise<string | null> {
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  if (!requestUrl || !requestToken) return null

  if (_oidcCache && _oidcCache.audience === audience && Date.now() < _oidcCache.expMs - OIDC_TOKEN_LEEWAY_MS) {
    return _oidcCache.token
  }

  // GitHub's OIDC endpoint already carries query params; append audience.
  const sep = requestUrl.includes("?") ? "&" : "?"
  const fullUrl = `${requestUrl}${sep}audience=${encodeURIComponent(audience)}`

  try {
    const res = await fetch(fullUrl, {
      headers: { Authorization: `Bearer ${requestToken}` },
    })
    if (!res.ok) {
      console.error(`[ERROR] GitHub OIDC token request failed: ${res.status}`)
      return null
    }
    const data = (await res.json()) as { value?: string }
    if (!data.value) return null
    _oidcCache = { audience, token: data.value, expMs: parseJwtExpMs(data.value) }
    return data.value
  } catch (e) {
    console.error(`[ERROR] GitHub OIDC token fetch error: ${(e as Error).message}`)
    return null
  }
}

// Global overrides set by CLI flags
let _profileOverride: string | undefined
let _orgOverride: string | undefined

export function setOverrides(opts: { profile?: string; org?: string }) {
  _profileOverride = opts.profile
  _orgOverride = opts.org
}

export async function getConfig() {
  // 1. OP_CONNECT_* env vars (op CLI compat, manual token)
  if (process.env.OP_CONNECT_HOST && process.env.OP_CONNECT_TOKEN) {
    const url = new URL(process.env.OP_CONNECT_HOST)
    // Scope is encoded in the host path (op CLI has no --org): a path segment
    // = that org, a bare host = personal (lock #22).
    const org = url.pathname.replace(/^\//, "").replace(/\/$/, "") || null
    const baseUrl = org ? `${url.origin}/${org}` : url.origin
    return { baseUrl, token: process.env.OP_CONNECT_TOKEN, org }
  }

  // 2. OP_CONNECT_HOST + GitHub Actions OIDC env vars (CI)
  // No stored secret: the workflow has `id-token: write` permission and the
  // runner mints a short-lived JWT scoped to the configured audience.
  if (process.env.OP_CONNECT_HOST && hasGithubOidcEnv()) {
    const url = new URL(process.env.OP_CONNECT_HOST)
    const org = url.pathname.replace(/^\//, "").replace(/\/$/, "") || null
    const baseUrl = org ? `${url.origin}/${org}` : url.origin
    const audience = process.env.OP_CONNECT_AUDIENCE || baseUrl
    const oidcToken = await fetchGithubOidcToken(audience)
    if (oidcToken) {
      return { baseUrl, token: oidcToken, org }
    }
    console.error("[ERROR] GitHub OIDC env vars set but token fetch failed")
    process.exit(1)
  }

  // 3. crcl config
  const profile = _profileOverride || process.env.CRCL_PROFILE || "default"
  const config = readCrclConfig()
  const section = config[profile] || {}

  // Scope (lock #22): personal by default. An org is targeted only when
  // explicitly requested via --org or CRCL_ORG — the crcl config's `org` no
  // longer auto-escalates, since personal is the safe default for any user
  // JWT (always available, non-shared). OIDC (CI) above always carries an org.
  const org = _orgOverride || process.env.CRCL_ORG || null

  // Determine vault host based on profile
  const isDevProfile = section.api_url?.includes("-dev") || section.auth_url?.includes("-dev")
  const host = isDevProfile ? DEV_VAULT_HOST : DEFAULT_VAULT_HOST
  // No org → personal namespace base (org slug never appears in the path)
  const baseUrl = org ? `${host}/${org}` : host

  // Get token (try cached credentials first, then crcl auth token)
  const creds = readCrclCredentials()
  let token = creds[profile]?.access_token

  // Check if token is expired
  if (token) {
    try {
      const payload = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString())
      if (payload.exp && payload.exp * 1000 < Date.now()) {
        token = undefined // expired, need refresh
      }
    } catch {
      token = undefined
    }
  }

  // Refresh via crcl auth token if needed
  if (!token) {
    token = getCrclToken(profile) || undefined
  }

  if (!token) {
    console.error("Error: Not authenticated. Run 'crcl login'" + (profile !== "default" ? ` --profile ${profile}` : ""))
    process.exit(1)
  }

  return { baseUrl, token, org }
}

/** Flat secrets API (vlt:// surface). Shares the unified scope of getConfig:
 * personal by default, org via --org / CRCL_ORG (lock #22). */
export async function secretsApi<T = unknown>(
  path: string,
  opts: { method?: string; body?: unknown } = {}
): Promise<T> {
  const { baseUrl, token } = await getConfig()
  return request<T>(`${baseUrl}${path}`, token, opts)
}

export async function api<T = unknown>(
  path: string,
  opts: { method?: string; body?: unknown } = {}
): Promise<T> {
  const { baseUrl, token } = await getConfig()
  return request<T>(`${baseUrl}${path}`, token, opts)
}

/** Like api(), but returns null on a non-OK response instead of exiting —
 * for best-effort lookups (e.g. OIDC callers can't list grants). */
export async function apiOptional<T = unknown>(path: string): Promise<T | null> {
  const { baseUrl, token } = await getConfig()
  try {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!res.ok) return null
    return (await res.json()) as T
  } catch {
    return null
  }
}

async function request<T = unknown>(
  url: string,
  token: string,
  opts: { method?: string; body?: unknown } = {}
): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
  }
  if (opts.body) {
    headers["Content-Type"] = "application/json"
  }

  const res = await fetch(url, {
    method: opts.method || "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  })

  if (!res.ok) {
    const text = await res.text()
    let message: string
    try {
      message = JSON.parse(text).message || text
    } catch {
      message = text
    }
    console.error(`[ERROR] ${res.status}: ${message}`)
    process.exit(1)
  }

  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

/** Resolve vault by name or ID */
export async function resolveVault(nameOrId: string): Promise<string> {
  type Vault = { id: string; name: string }
  const vaults = await api<Vault[]>("/v1/vaults")
  const match = vaults.find(
    (v) => v.id === nameOrId || v.name.toLowerCase() === nameOrId.toLowerCase()
  )
  if (!match) {
    console.error(`[ERROR] Vault "${nameOrId}" not found`)
    process.exit(1)
  }
  return match.id
}

/** Resolve item by name or ID within a vault */
export async function resolveItem(
  vaultId: string,
  nameOrId: string
): Promise<string> {
  type Item = { id: string; title: string }
  const items = await api<Item[]>(
    `/v1/vaults/${vaultId}/items?filter=${encodeURIComponent(`title eq "${nameOrId}"`)}`
  )
  if (items.length > 0) return items[0]!.id

  const { baseUrl, token } = await getConfig()
  const res = await fetch(`${baseUrl}/v1/vaults/${vaultId}/items/${nameOrId}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (res.ok) {
    const item = (await res.json()) as Item
    return item.id
  }

  console.error(`[ERROR] Item "${nameOrId}" not found in vault`)
  process.exit(1)
}
