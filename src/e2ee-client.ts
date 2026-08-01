import { loadDeviceKey, saveDeviceKey } from "./key-store"
import { parseVaultCoordinate } from "./refs"
import {
  createRecoveryEnvelope,
  decryptContent,
  decryptJson,
  encodeBase64,
  encryptContent,
  encryptJson,
  generateDeviceKey,
  generateOpaqueId,
  itemLocator,
  openRecoveryEnvelope,
  parseEncryptedBytes,
  parseKmsPlaintext,
  randomKey,
  serializeEncryptedBytes,
  unwrapAccountKeyForDevice,
  unwrapKey,
  wrapAccountKeyForDevice,
  wrapKey,
  wrapVaultKeyForKms,
  type AesEnvelope,
  type ContentEnvelope,
  type DeviceKey,
  type RecoveryEnvelope,
  type RsaEnvelope,
} from "./e2ee-crypto"

export type VaultConfig = { baseUrl: string; token: string; org: string | null }
export type RequestOptions = { method?: string; body?: unknown }
export type OidcTokenFetcher = (audience: string) => Promise<string | null>

type Status = {
  account: string
  initialized: boolean
  format_version: number | null
  client: {
    id: string
    public_key: JsonWebKey
    wrapped_account_key: RsaEnvelope
    platform: string | null
    created_at: string
  } | null
  kms: {
    public_key_pem: string | null
    wif_audience: string | null
    key_version: string | null
  }
}

type VaultRow = {
  id: string
  attribute_version: number
  content_version: number
  created_at: string
  updated_at: string
  items: number
  format_version: number
  overview: ContentEnvelope
  wrapped_vault_key: AesEnvelope
  kms_wrapped_vault_key: RsaEnvelope | null
  coordinate: { provider: string; owner: string; repository: string | null } | null
}

type ItemRow = {
  id: string
  vault_id: string
  version: number
  created_at: string
  updated_at: string
  format_version: number
  locator: string
  overview: ContentEnvelope
  details: ContentEnvelope
}

type FileRow = {
  id: string
  item_id: string
  vault_id: string
  created_at: string
  format_version: number
  metadata: ContentEnvelope
  ciphertext_size: number
  content_path: string
}

type VaultOverview = {
  name: string
  description: string
  type: string
  password_rotation_days?: number | null
}

type ItemOverview = {
  title: string
  category: string
  tags: string[]
  favorite: boolean
  state?: string
  urls: { href: string; primary?: boolean }[]
  last_edited_by?: string
  password_changed_at?: string | null
}

type ItemDetails = {
  fields: Record<string, unknown>[]
  sections: Record<string, unknown>[]
  password_history: string[]
}

type FileMetadata = { name: string; content_type: string; size: number }

type CryptoContext = {
  status: Status
  device: DeviceKey | null
  accountKey: Uint8Array | null
}

export class VaultApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
  }
}

const cryptoContexts = new Map<string, CryptoContext>()
const vaultKeys = new Map<string, Uint8Array>()
const encoder = new TextEncoder()

export function resetE2eeCaches() {
  cryptoContexts.clear()
  vaultKeys.clear()
}

function authHeaders(config: VaultConfig, device?: DeviceKey | null): Record<string, string> {
  const headers: Record<string, string> = { Authorization: `Bearer ${config.token}` }
  if (device) headers["X-CVLT-Client-ID"] = device.clientId
  return headers
}

async function errorMessage(response: Response): Promise<string> {
  const text = await response.text()
  try {
    return (JSON.parse(text) as { message?: string }).message || text
  } catch {
    return text
  }
}

async function jsonRequest<T>(
  config: VaultConfig,
  path: string,
  options: RequestOptions = {},
  headers: Record<string, string> = {}
): Promise<T> {
  const requestHeaders = { ...authHeaders(config), ...headers }
  if (options.body !== undefined) requestHeaders["Content-Type"] = "application/json"
  const response = await fetch(`${config.baseUrl}${path}`, {
    method: options.method || "GET",
    headers: requestHeaders,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  })
  if (!response.ok) throw new VaultApiError(response.status, await errorMessage(response))
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

function isOidc(): boolean {
  return !process.env.OP_CONNECT_TOKEN
    && !!(process.env.ACTIONS_ID_TOKEN_REQUEST_URL && process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)
}

async function readStatus(config: VaultConfig, device: DeviceKey | null): Promise<Status> {
  return jsonRequest<Status>(config, "/v2/status", {}, device ? { "X-CVLT-Client-ID": device.clientId } : {})
}

async function bootstrap(config: VaultConfig, device: DeviceKey | null): Promise<CryptoContext> {
  if (isOidc()) throw new Error("GitHub Actions cannot initialize account encryption")
  const installation = device ?? await generateDeviceKey()
  if (!device) await saveDeviceKey(new URL(config.baseUrl).origin, installation)
  const status = await readStatus(config, installation)
  if (status.initialized) return cryptoContext(config, false)
  const accountKey = randomKey()
  const recovery = await createRecoveryEnvelope(accountKey, status.account)
  await jsonRequest(config, "/v2/bootstrap", {
    method: "POST",
    body: {
      client: {
        id: installation.clientId,
        public_key: installation.publicKey,
        wrapped_account_key: await wrapAccountKeyForDevice(accountKey, installation.publicKey, status.account),
        platform: process.platform,
      },
      recovery: recovery.envelope,
    },
  })
  process.stderr.write("\nCircles Vault recovery code (store it outside Vault):\n")
  process.stderr.write(`${recovery.code}\n\n`)
  const initialized = await readStatus(config, installation)
  const context = { status: initialized, device: installation, accountKey }
  cryptoContexts.set(config.baseUrl, context)
  return context
}

async function cryptoContext(config: VaultConfig, allowBootstrap: boolean): Promise<CryptoContext> {
  const cached = cryptoContexts.get(config.baseUrl)
  if (cached) return cached
  const device = isOidc() ? null : await loadDeviceKey(new URL(config.baseUrl).origin)
  const status = await readStatus(config, device)
  if (!status.initialized) {
    if (!allowBootstrap) return { status, device, accountKey: null }
    return bootstrap(config, device)
  }
  if (isOidc()) {
    const context = { status, device: null, accountKey: null }
    cryptoContexts.set(config.baseUrl, context)
    return context
  }
  if (!device || !status.client) {
    throw new Error("This installation is not registered. Run cvlt recover after a fresh crcl login")
  }
  const accountKey = await unwrapAccountKeyForDevice(
    status.client.wrapped_account_key,
    device.privateKey,
    status.account
  )
  const context = { status, device, accountKey }
  cryptoContexts.set(config.baseUrl, context)
  return context
}

async function kmsVaultKey(
  context: CryptoContext,
  row: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Uint8Array> {
  const { wif_audience: audience, key_version: keyVersion } = context.status.kms
  if (!row.kms_wrapped_vault_key || !audience || !keyVersion) {
    throw new Error(`Vault ${row.id} has no GitHub OIDC KMS envelope`)
  }
  const subjectToken = await fetchOidcToken(audience)
  if (!subjectToken) throw new Error("Unable to mint a GitHub OIDC token for GCP")
  const sts = await fetch("https://sts.googleapis.com/v1/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
      audience,
      requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
      scope: "https://www.googleapis.com/auth/cloud-platform",
      subjectToken,
      subjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
    }),
  })
  if (!sts.ok) throw new Error(`GCP STS token exchange failed: ${sts.status}`)
  const accessToken = ((await sts.json()) as { access_token?: string }).access_token
  if (!accessToken) throw new Error("GCP STS returned no access token")
  const decrypted = await fetch(`https://cloudkms.googleapis.com/v1/${keyVersion}:asymmetricDecrypt`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ ciphertext: Buffer.from(row.kms_wrapped_vault_key.ciphertext, "base64url").toString("base64") }),
  })
  if (!decrypted.ok) throw new Error(`GCP KMS asymmetricDecrypt failed: ${decrypted.status}`)
  const plaintext = ((await decrypted.json()) as { plaintext?: string }).plaintext
  if (!plaintext) throw new Error("GCP KMS returned no plaintext")
  return parseKmsPlaintext(Buffer.from(plaintext, "base64").toString("base64url"), row.id)
}

async function vaultKey(
  config: VaultConfig,
  row: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Uint8Array> {
  const cacheKey = `${config.baseUrl}:${row.id}`
  const cached = vaultKeys.get(cacheKey)
  if (cached) return cached
  const context = await cryptoContext(config, false)
  let key: Uint8Array
  if (isOidc()) {
    key = await kmsVaultKey(context, row, fetchOidcToken)
  } else {
    if (!context.accountKey || !row.wrapped_vault_key) throw new Error(`Vault ${row.id} has no account key envelope`)
    key = await unwrapKey(
      row.wrapped_vault_key,
      context.accountKey,
      `cvlt:v1:account:${context.status.account}:vault:${row.id}`
    )
  }
  vaultKeys.set(cacheKey, key)
  return key
}

async function encryptedVault(
  config: VaultConfig,
  row: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  if (!row.overview) throw new Error(`Vault ${row.id} has no encrypted overview`)
  const overview = await decryptJson<VaultOverview>(
    row.overview,
    await vaultKey(config, row, fetchOidcToken),
    `cvlt:v1:vault:${row.id}:overview`
  )
  const result: Record<string, unknown> = {
    id: row.id,
    name: overview.name,
    content_version: row.content_version,
    attribute_version: row.attribute_version,
    type: overview.type,
    items: row.items,
    created_at: row.created_at,
    updated_at: row.updated_at,
  }
  if (overview.description) result.description = overview.description
  if (overview.password_rotation_days != null) result.password_rotation_days = overview.password_rotation_days
  return result
}

async function vaultRows(config: VaultConfig): Promise<VaultRow[]> {
  return jsonRequest<VaultRow[]>(config, "/v2/vaults")
}

async function findVaultRow(config: VaultConfig, vaultId: string): Promise<VaultRow> {
  return jsonRequest<VaultRow>(config, `/v2/vaults/${vaultId}`)
}

async function encryptedItem(
  config: VaultConfig,
  row: ItemRow,
  vault: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  if (!row.overview || !row.details) throw new Error(`Item ${row.id} has incomplete encrypted data`)
  const key = await vaultKey(config, vault, fetchOidcToken)
  const overview = await decryptJson<ItemOverview>(
    row.overview,
    key,
    `cvlt:v1:vault:${row.vault_id}:item:${row.id}:overview`
  )
  const details = await decryptJson<ItemDetails>(
    row.details,
    key,
    `cvlt:v1:vault:${row.vault_id}:item:${row.id}:details`
  )
  const fields = details.fields.map((field) => {
    if (field.purpose !== "PASSWORD" || details.password_history.length === 0) return field
    return {
      ...field,
      password_details: {
        ...(field.password_details as Record<string, unknown> | undefined),
        history: details.password_history,
      },
    }
  })
  const result: Record<string, unknown> = {
    id: row.id,
    title: overview.title,
    version: row.version,
    vault: { id: row.vault_id },
    category: overview.category,
    fields,
    sections: details.sections,
    urls: overview.urls,
    created_at: row.created_at,
    updated_at: row.updated_at,
  }
  if (overview.tags.length) result.tags = overview.tags
  if (overview.favorite) result.favorite = true
  if (overview.state) result.state = overview.state
  if (overview.last_edited_by) result.last_edited_by = overview.last_edited_by
  if (overview.password_changed_at) result.password_changed_at = overview.password_changed_at
  return result
}

function itemPayload(body: Record<string, unknown>, current?: Record<string, unknown>): {
  overview: ItemOverview
  details: ItemDetails
} {
  const currentFields = (current?.fields as Record<string, unknown>[] | undefined) ?? []
  const fields = (body.fields as Record<string, unknown>[] | undefined) ?? currentFields
  const previousPassword = currentFields.find((field) => field.purpose === "PASSWORD")?.value
  const nextPassword = fields.find((field) => field.purpose === "PASSWORD")?.value
  const passwordField = currentFields.find((field) => field.purpose === "PASSWORD") as {
    password_details?: { history?: string[] }
  } | undefined
  const currentHistory = (passwordField?.password_details?.history ?? []).slice(-20)
  if (typeof previousPassword === "string" && typeof nextPassword === "string" && previousPassword !== nextPassword) {
    currentHistory.push(previousPassword)
    if (currentHistory.length > 20) currentHistory.shift()
  }
  return {
    overview: {
      title: String(body.title ?? current?.title ?? "Untitled"),
      category: String(body.category ?? current?.category ?? "LOGIN"),
      tags: (body.tags as string[] | undefined) ?? (current?.tags as string[] | undefined) ?? [],
      favorite: Boolean(body.favorite ?? current?.favorite ?? false),
      ...(typeof body.state === "string" || typeof current?.state === "string"
        ? { state: String(body.state ?? current?.state) }
        : {}),
      urls: (body.urls as { href: string; primary?: boolean }[] | undefined)
        ?? (current?.urls as { href: string; primary?: boolean }[] | undefined)
        ?? [],
      ...(typeof current?.last_edited_by === "string" ? { last_edited_by: current.last_edited_by } : {}),
      ...(typeof nextPassword === "string" && nextPassword !== previousPassword
        ? { password_changed_at: new Date().toISOString() }
        : typeof current?.password_changed_at === "string"
          ? { password_changed_at: current.password_changed_at }
        : {}),
    },
    details: {
      fields,
      sections: (body.sections as Record<string, unknown>[] | undefined)
        ?? (current?.sections as Record<string, unknown>[] | undefined)
        ?? [],
      password_history: currentHistory,
    },
  }
}

async function createItem(
  config: VaultConfig,
  vault: VaultRow,
  body: Record<string, unknown>,
  fetchOidcToken: OidcTokenFetcher,
  id = generateOpaqueId()
): Promise<Record<string, unknown>> {
  const key = await vaultKey(config, vault, fetchOidcToken)
  const payload = itemPayload(body)
  const row = await jsonRequest<ItemRow>(config, `/v2/vaults/${vault.id}/items`, {
    method: "POST",
    body: {
      id,
      locator: await itemLocator(key, payload.overview.title),
      overview: await encryptJson(payload.overview, key, `cvlt:v1:vault:${vault.id}:item:${id}:overview`),
      details: await encryptJson(payload.details, key, `cvlt:v1:vault:${vault.id}:item:${id}:details`),
    },
  })
  return encryptedItem(config, row, vault, fetchOidcToken)
}

async function updateItem(
  config: VaultConfig,
  vault: VaultRow,
  row: ItemRow,
  body: Record<string, unknown>,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  const current = await encryptedItem(config, row, vault, fetchOidcToken)
  const key = await vaultKey(config, vault, fetchOidcToken)
  const payload = itemPayload(body, current)
  const updated = await jsonRequest<ItemRow>(config, `/v2/vaults/${vault.id}/items/${row.id}`, {
    method: "PUT",
    body: {
      version: row.version,
      locator: await itemLocator(key, payload.overview.title),
      overview: await encryptJson(payload.overview, key, `cvlt:v1:vault:${vault.id}:item:${row.id}:overview`),
      details: await encryptJson(payload.details, key, `cvlt:v1:vault:${vault.id}:item:${row.id}:details`),
    },
  })
  return encryptedItem(config, updated, vault, fetchOidcToken)
}

function filterItems(items: Record<string, unknown>[], query: URLSearchParams): Record<string, unknown>[] {
  let filtered = items.filter((item) => !item.state)
  const filter = query.get("filter")
  const title = filter?.match(/title\s+eq\s+"([^"]+)"/)?.[1]
  const tag = filter?.match(/tag\s+eq\s+"([^"]+)"/)?.[1]
  if (title) filtered = filtered.filter((item) => item.title === title)
  if (tag) filtered = filtered.filter((item) => (item.tags as string[] | undefined)?.includes(tag))
  const tags = query.get("tags")?.split(",").map((value) => value.trim()).filter(Boolean)
  if (tags?.length) filtered = filtered.filter((item) => tags.every((value) => (item.tags as string[] | undefined)?.includes(value)))
  const categories = query.get("categories")?.split(",").map((value) => value.trim().toUpperCase()).filter(Boolean)
  if (categories?.length) filtered = filtered.filter((item) => categories.includes(String(item.category).toUpperCase()))
  const offset = Number(query.get("offset") ?? 0)
  const limit = query.has("limit") ? Number(query.get("limit")) : undefined
  return filtered.slice(Number.isFinite(offset) ? offset : 0, limit ? offset + limit : undefined)
}

async function fileRows(config: VaultConfig, vaultId: string, itemId: string): Promise<FileRow[]> {
  return jsonRequest<FileRow[]>(config, `/v2/vaults/${vaultId}/items/${itemId}/files`)
}

async function encryptedFileInfo(
  config: VaultConfig,
  row: FileRow,
  vault: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  if (!row.metadata) throw new Error(`File ${row.id} has no encrypted metadata`)
  const metadata = await decryptJson<FileMetadata>(
    row.metadata,
    await vaultKey(config, vault, fetchOidcToken),
    `cvlt:v1:vault:${row.vault_id}:item:${row.item_id}:file:${row.id}:metadata`
  )
  return {
    id: row.id,
    name: metadata.name,
    size: metadata.size,
    content_type: metadata.content_type,
    content_path: row.content_path,
  }
}

export async function uploadEncryptedFile(
  config: VaultConfig,
  vaultId: string,
  itemId: string,
  name: string,
  contentType: string,
  content: Uint8Array,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  if (content.byteLength > 10 * 1024 * 1024) throw new Error("File exceeds 10MB limit")
  const vault = await findVaultRow(config, vaultId)
  const key = await vaultKey(config, vault, fetchOidcToken)
  const fileId = generateOpaqueId()
  const metadata = await encryptJson(
    { name, content_type: contentType || "application/octet-stream", size: content.byteLength },
    key,
    `cvlt:v1:vault:${vaultId}:item:${itemId}:file:${fileId}:metadata`
  )
  const encrypted = serializeEncryptedBytes(await encryptContent(
    content,
    key,
    `cvlt:v1:vault:${vaultId}:item:${itemId}:file:${fileId}:content`
  ))
  const response = await fetch(`${config.baseUrl}/v2/vaults/${vaultId}/items/${itemId}/files`, {
    method: "POST",
    headers: {
      ...authHeaders(config),
      "Content-Type": "application/octet-stream",
      "X-CVLT-File-ID": fileId,
      "X-CVLT-Metadata": Buffer.from(JSON.stringify(metadata)).toString("base64url"),
    },
    body: encrypted,
  })
  if (!response.ok) throw new VaultApiError(response.status, await errorMessage(response))
  return encryptedFileInfo(config, await response.json() as FileRow, vault, fetchOidcToken)
}

export async function downloadEncryptedFile(
  config: VaultConfig,
  vaultId: string,
  itemId: string,
  fileId: string,
  fetchOidcToken: OidcTokenFetcher
): Promise<{ info: Record<string, unknown>; content: Uint8Array }> {
  const vault = await findVaultRow(config, vaultId)
  const row = (await fileRows(config, vaultId, itemId)).find((file) => file.id === fileId)
  if (!row) throw new Error("File not found")
  const response = await fetch(`${config.baseUrl}/v2/vaults/${vaultId}/items/${itemId}/files/${fileId}/content`, {
    headers: authHeaders(config),
  })
  if (!response.ok) throw new VaultApiError(response.status, await errorMessage(response))
  const key = await vaultKey(config, vault, fetchOidcToken)
  const content = await decryptContent(
    parseEncryptedBytes(new Uint8Array(await response.arrayBuffer())),
    key,
    `cvlt:v1:vault:${vaultId}:item:${itemId}:file:${fileId}:content`
  )
  return { info: await encryptedFileInfo(config, row, vault, fetchOidcToken), content }
}

async function createVault(
  config: VaultConfig,
  body: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const context = await cryptoContext(config, true)
  if (!context.accountKey) throw new Error("A user account key is required to create a vault")
  const id = generateOpaqueId()
  const key = randomKey()
  const overview: VaultOverview = {
    name: String(body.name ?? ""),
    description: String(body.description ?? ""),
    type: "USER_CREATED",
    ...(body.password_rotation_days !== undefined
      ? { password_rotation_days: body.password_rotation_days as number | null }
      : {}),
  }
  const coordinate = parseVaultCoordinate(overview.name)
  const kmsWrapped = context.status.kms.public_key_pem
    ? await wrapVaultKeyForKms(key, id, context.status.kms.public_key_pem)
    : null
  const row = await jsonRequest<VaultRow>(config, "/v2/vaults", {
    method: "POST",
    body: {
      id,
      overview: await encryptJson(overview, key, `cvlt:v1:vault:${id}:overview`),
      wrapped_vault_key: await wrapKey(
        key,
        context.accountKey,
        `cvlt:v1:account:${context.status.account}:vault:${id}`
      ),
      kms_wrapped_vault_key: kmsWrapped,
      coordinate: coordinate
        ? { provider: coordinate.provider, owner: coordinate.owner, repository: coordinate.repo }
        : null,
    },
  })
  vaultKeys.set(`${config.baseUrl}:${id}`, key)
  return encryptedVault(config, row, async () => null)
}

async function coordinateRead(
  config: VaultConfig,
  ref: string,
  fetchOidcToken: OidcTokenFetcher
): Promise<{ value: string }> {
  const match = ref.match(/^vlt:\/\/([^/]+)\/([^/]+)(?:\/([^/]+))?\/([^/]+)$/)
  if (!match) throw new Error("Invalid vlt:// reference")
  const provider = match[1]!.toLowerCase()
  const owner = match[2]!.toLowerCase()
  const repository = match[3]?.toLowerCase() ?? null
  const name = decodeURIComponent(match[4]!)
  const query = new URLSearchParams({ provider, owner })
  if (repository) query.set("repository", repository)
  const rows = await jsonRequest<VaultRow[]>(config, `/v2/coordinates?${query}`)
  const candidates: { vault_id: string; locator: string }[] = []
  for (const row of rows) {
    candidates.push({ vault_id: row.id, locator: await itemLocator(await vaultKey(config, row, fetchOidcToken), name) })
  }
  const item = await jsonRequest<ItemRow>(config, "/v2/coordinates/read", {
    method: "POST",
    body: { provider, owner, repository, candidates },
  })
  const vault = rows.find((row) => row.id === item.vault_id)!
  const decrypted = await encryptedItem(config, item, vault, fetchOidcToken)
  const fields = decrypted.fields as { id?: string; value?: string }[] | undefined
  const field = fields?.find((entry) => entry.id === "value") ?? fields?.[0]
  if (typeof field?.value !== "string") throw new Error("Secret item has no value field")
  return { value: field.value }
}

export async function handleSecretsApi<T>(
  config: VaultConfig,
  path: string,
  fetchOidcToken: OidcTokenFetcher
): Promise<{ handled: boolean; value?: T }> {
  if (!path.startsWith("/v1/read")) return { handled: false }
  const context = await cryptoContext(config, false)
  if (!context.status.initialized) throw new Error("Account encryption is not initialized")
  const ref = new URL(path, "https://cvlt.local").searchParams.get("ref")
  if (!ref) throw new Error("Missing ref")
  return { handled: true, value: await coordinateRead(config, ref, fetchOidcToken) as T }
}

export async function handleApi<T>(
  config: VaultConfig,
  path: string,
  options: RequestOptions,
  fetchOidcToken: OidcTokenFetcher
): Promise<{ handled: boolean; value?: T }> {
  const url = new URL(path, "https://cvlt.local")
  const method = options.method || "GET"
  const parts = url.pathname.split("/").filter(Boolean)
  if (parts[0] !== "v1" || parts[1] !== "vaults") return { handled: false }
  await cryptoContext(config, method !== "GET")

  if (parts.length === 2) {
    if (method === "POST") {
      return { handled: true, value: await createVault(config, options.body as Record<string, unknown>) as T }
    }
    const rows = await vaultRows(config)
    return {
      handled: true,
      value: await Promise.all(rows.map((row) => encryptedVault(config, row, fetchOidcToken))) as T,
    }
  }

  const vaultId = parts[2]!
  const vault = await findVaultRow(config, vaultId)
  if (parts.length === 3) {
    if (method === "DELETE") {
      await jsonRequest(config, `/v2/vaults/${vaultId}`, { method: "DELETE" })
      return { handled: true, value: undefined as T }
    }
    if (method === "PUT") {
      const current = await encryptedVault(config, vault, fetchOidcToken)
      const overview: VaultOverview = {
        name: String((options.body as Record<string, unknown>).name ?? current.name),
        description: String((options.body as Record<string, unknown>).description ?? current.description ?? ""),
        type: String(current.type ?? "USER_CREATED"),
        ...((options.body as Record<string, unknown>).password_rotation_days !== undefined
          ? { password_rotation_days: (options.body as Record<string, unknown>).password_rotation_days as number | null }
          : current.password_rotation_days !== undefined
            ? { password_rotation_days: current.password_rotation_days as number }
            : {}),
      }
      const row = await jsonRequest<VaultRow>(config, `/v2/vaults/${vaultId}`, {
        method: "PUT",
        body: {
          overview: await encryptJson(
            overview,
            await vaultKey(config, vault, fetchOidcToken),
            `cvlt:v1:vault:${vaultId}:overview`
          ),
        },
      })
      return { handled: true, value: await encryptedVault(config, row, fetchOidcToken) as T }
    }
    return { handled: true, value: await encryptedVault(config, vault, fetchOidcToken) as T }
  }

  if (parts[3] !== "items") return { handled: false }
  if (parts.length === 4) {
    if (method === "POST") {
      return {
        handled: true,
        value: await createItem(config, vault, options.body as Record<string, unknown>, fetchOidcToken) as T,
      }
    }
    const rows = await jsonRequest<ItemRow[]>(config, `/v2/vaults/${vaultId}/items`)
    const items = await Promise.all(rows.map((row) => encryptedItem(config, row, vault, fetchOidcToken)))
    return { handled: true, value: filterItems(items, url.searchParams) as T }
  }

  const itemId = parts[4]!
  if (parts[5] === "files") {
    if (parts.length === 6 && method === "GET") {
      const rows = await fileRows(config, vaultId, itemId)
      return {
        handled: true,
        value: await Promise.all(rows.map((row) => encryptedFileInfo(config, row, vault, fetchOidcToken))) as T,
      }
    }
    return { handled: false }
  }

  const row = await jsonRequest<ItemRow>(config, `/v2/vaults/${vaultId}/items/${itemId}`)
  if (parts[5] === "move" && method === "POST") {
    const destinationId = String((options.body as Record<string, unknown>).vault)
    const destination = await findVaultRow(config, destinationId)
    const current = await encryptedItem(config, row, vault, fetchOidcToken)
    const attachments = await fileRows(config, vaultId, itemId)
    const contents = await Promise.all(
      attachments.map((file) => downloadEncryptedFile(config, vaultId, itemId, file.id, fetchOidcToken))
    )
    const created = await createItem(config, destination, current, fetchOidcToken)
    for (const file of contents) {
      await uploadEncryptedFile(
        config,
        destinationId,
        String(created.id),
        String(file.info.name),
        String(file.info.content_type ?? "application/octet-stream"),
        file.content,
        fetchOidcToken
      )
    }
    await jsonRequest(config, `/v2/vaults/${vaultId}/items/${itemId}`, { method: "DELETE" })
    return { handled: true, value: created as T }
  }
  if (method === "DELETE") {
    await jsonRequest(config, `/v2/vaults/${vaultId}/items/${itemId}`, { method: "DELETE" })
    return { handled: true, value: undefined as T }
  }
  if (method === "PUT") {
    return {
      handled: true,
      value: await updateItem(config, vault, row, options.body as Record<string, unknown>, fetchOidcToken) as T,
    }
  }
  return { handled: true, value: await encryptedItem(config, row, vault, fetchOidcToken) as T }
}

export async function e2eeDoctor(config: VaultConfig): Promise<{
  initialized: boolean
  client_registered: boolean
  vaults: number
  items: number
  kms_ready: boolean
}> {
  const context = await cryptoContext(config, false)
  const rows = await vaultRows(config)
  let items = 0
  for (const row of rows) {
    items += (await jsonRequest<ItemRow[]>(config, `/v2/vaults/${row.id}/items`)).length
  }
  return {
    initialized: context.status.initialized,
    client_registered: isOidc() || !!context.status.client,
    vaults: rows.length,
    items,
    kms_ready: !!(
      context.status.kms.public_key_pem
      && context.status.kms.wif_audience
      && context.status.kms.key_version
      && rows.every((row) => row.kms_wrapped_vault_key)
    ),
  }
}

export async function startRecovery(config: VaultConfig): Promise<void> {
  await jsonRequest(config, "/v2/recovery/start", { method: "POST" })
}

export async function completeRecovery(
  config: VaultConfig,
  emailCode: string,
  recoveryCode: string
): Promise<void> {
  const status = await readStatus(config, null)
  const verified = await jsonRequest<{ recovery_token: string; recovery: RecoveryEnvelope }>(
    config,
    "/v2/recovery/verify",
    { method: "POST", body: { code: emailCode } }
  )
  const accountKey = await openRecoveryEnvelope(verified.recovery, recoveryCode, status.account)
  const device = await generateDeviceKey()
  await saveDeviceKey(new URL(config.baseUrl).origin, device)
  const replacementRecovery = await createRecoveryEnvelope(accountKey, status.account)
  await jsonRequest(config, "/v2/recovery/complete", {
    method: "POST",
    body: {
      recovery_token: verified.recovery_token,
      recovery: replacementRecovery.envelope,
      client: {
        id: device.clientId,
        public_key: device.publicKey,
        wrapped_account_key: await wrapAccountKeyForDevice(accountKey, device.publicKey, status.account),
        platform: process.platform,
      },
    },
  })
  process.stderr.write("\nNew Circles Vault recovery code (the previous code and clients are revoked):\n")
  process.stderr.write(`${replacementRecovery.code}\n\n`)
  resetE2eeCaches()
}
