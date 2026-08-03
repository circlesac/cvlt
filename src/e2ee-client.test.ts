import { afterEach, beforeEach, describe, expect, it, mock } from "bun:test"
import { handleApi, resetE2eeCaches } from "./e2ee-client"
import { encodeBase64, encryptJson, itemLocator, randomKey } from "./e2ee-crypto"

const vaultId = "01j00000000000000000000001"
const itemId = "01j00000000000000000000002"
const realFetch = globalThis.fetch
const originalOidcUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL
const originalOidcToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
const originalConnectToken = process.env.OP_CONNECT_TOKEN

beforeEach(() => {
  resetE2eeCaches()
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = "https://github.example/oidc"
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "request-token"
  delete process.env.OP_CONNECT_TOKEN
})

afterEach(() => {
  globalThis.fetch = realFetch
  resetE2eeCaches()
  if (originalOidcUrl === undefined) delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL
  else process.env.ACTIONS_ID_TOKEN_REQUEST_URL = originalOidcUrl
  if (originalOidcToken === undefined) delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  else process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = originalOidcToken
  if (originalConnectToken === undefined) delete process.env.OP_CONNECT_TOKEN
  else process.env.OP_CONNECT_TOKEN = originalConnectToken
})

describe("E2EE request cache", () => {
  it("deduplicates raw rows and resolves titles without sending plaintext", async () => {
    const key = randomKey()
    const vaultRow = {
      id: vaultId,
      attribute_version: 1,
      content_version: 1,
      created_at: "2026-08-03T00:00:00Z",
      updated_at: "2026-08-03T00:00:00Z",
      items: 1,
      format_version: 1,
      overview: await encryptJson(
        { name: "Production", description: "", type: "USER_CREATED" },
        key,
        `cvlt:v1:vault:${vaultId}:overview`
      ),
      wrapped_vault_key: null,
      kms_wrapped_vault_key: {
        version: 1,
        algorithm: "RSA-OAEP-3072-SHA256",
        ciphertext: "wrapped",
      },
      coordinate: null,
    }
    const itemRow = {
      id: itemId,
      vault_id: vaultId,
      version: 1,
      created_at: "2026-08-03T00:00:00Z",
      updated_at: "2026-08-03T00:00:00Z",
      format_version: 1,
      locator: await itemLocator(key, "Database"),
      overview: await encryptJson(
        { title: "Database", category: "LOGIN", tags: [], favorite: false, urls: [] },
        key,
        `cvlt:v1:vault:${vaultId}:item:${itemId}:overview`
      ),
      details: await encryptJson(
        { fields: [{ id: "password", value: "secret" }], sections: [], password_history: [] },
        key,
        `cvlt:v1:vault:${vaultId}:item:${itemId}:details`
      ),
    }
    const requests: { url: string; method: string; body?: string }[] = []
    globalThis.fetch = mock(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? "GET"
      const body = typeof init?.body === "string" ? init.body : undefined
      requests.push({ url, method, ...(body === undefined ? {} : { body }) })
      if (url === "https://vault.example/v1/status") {
        return Response.json({
          account: "user:1",
          initialized: true,
          format_version: 1,
          client: null,
          kms: {
            public_key_pem: null,
            wif_audience: "kms-audience",
            key_version: "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1",
          },
        })
      }
      if (url === "https://vault.example/v1/vaults") return Response.json([vaultRow])
      if (url === "https://sts.googleapis.com/v1/token") return Response.json({ access_token: "gcp-token" })
      if (url.startsWith("https://cloudkms.googleapis.com/v1/")) {
        return Response.json({
          plaintext: Buffer.from(JSON.stringify({
            version: 1,
            vault_id: vaultId,
            vault_key: encodeBase64(key),
          })).toString("base64"),
        })
      }
      if (url === `https://vault.example/v1/vaults/${vaultId}/items/resolve`) {
        return Response.json(itemRow)
      }
      return Response.json({ status: 404, message: "unexpected request" }, { status: 404 })
    }) as unknown as typeof fetch

    const config = { baseUrl: "https://vault.example", token: "caller", org: null }
    const fetchOidcToken = async () => "subject-token"
    const [firstVaults, secondVaults] = await Promise.all([
      handleApi<Record<string, unknown>[]>(config, "/v1/vaults", {}, fetchOidcToken),
      handleApi<Record<string, unknown>[]>(config, "/v1/vaults", {}, fetchOidcToken),
    ])
    expect(firstVaults.value).toEqual(secondVaults.value)

    const resolved = await handleApi<Record<string, unknown>>(
      config,
      `/v1/vaults/${vaultId}/items/resolve`,
      { method: "POST", body: { title: "Database" } },
      fetchOidcToken
    )
    expect(resolved.value).toMatchObject({ id: itemId, title: "Database" })

    const item = await handleApi<Record<string, unknown>>(
      config,
      `/v1/vaults/${vaultId}/items/${itemId}`,
      {},
      fetchOidcToken
    )
    expect(item.value).toMatchObject({ id: itemId, title: "Database" })

    expect(requests.filter((request) => request.url.endsWith("/v1/status"))).toHaveLength(1)
    expect(requests.filter((request) => request.url.startsWith("https://vault.example/"))).toHaveLength(3)
    expect(requests.filter((request) => request.url === "https://vault.example/v1/vaults")).toHaveLength(1)
    expect(requests.filter((request) => request.url === `https://vault.example/v1/vaults/${vaultId}`)).toHaveLength(0)
    expect(requests.filter((request) => request.url.endsWith(`/items/${itemId}`))).toHaveLength(0)
    expect(requests.filter((request) => request.url === "https://sts.googleapis.com/v1/token")).toHaveLength(1)
    expect(requests.filter((request) => request.url.startsWith("https://cloudkms.googleapis.com/v1/"))).toHaveLength(1)
    const resolveRequest = requests.find((request) => request.url.endsWith("/items/resolve"))!
    expect(JSON.parse(resolveRequest.body!)).toEqual({ locator: itemRow.locator })
    expect(resolveRequest.body).not.toContain("Database")
  })
})
