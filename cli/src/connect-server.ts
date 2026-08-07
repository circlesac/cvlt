import {
  encodeBase64,
  fetchGithubOidcToken,
  getConfig,
  handleApi,
  handleSecretsApi,
  VaultApiError,
  type VaultConfig,
} from "@circlesac/vault/cli"

function jsonResponse(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  const responseHeaders = new Headers(headers)
  responseHeaders.set("Content-Type", "application/json")
  responseHeaders.set("Cache-Control", "no-store")
  return new Response(JSON.stringify(value), { status, headers: responseHeaders })
}

export function createConnectHandler(config: VaultConfig, localToken: string) {
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url)
    if (url.pathname === "/heartbeat") return new Response(".", { headers: { "Cache-Control": "no-store" } })
    if (url.pathname === "/health") return jsonResponse({ name: "Circles Vault Connect", version: 1 })
    if (request.headers.get("Authorization") !== `Bearer ${localToken}`) {
      return jsonResponse({ status: 401, message: "Invalid Connect token" }, 401)
    }
    try {
      const body = request.method === "GET" || request.method === "HEAD" || request.method === "DELETE"
        ? undefined
        : await request.json()
      const options = { method: request.method, ...(body === undefined ? {} : { body }) }
      const secret = await handleSecretsApi<unknown>(config, `${url.pathname}${url.search}`, fetchGithubOidcToken)
      if (secret.handled) return jsonResponse(secret.value)
      const translated = await handleApi<Record<string, unknown>>(config, `${url.pathname}${url.search}`, options, fetchGithubOidcToken)
      if (!translated.handled) return jsonResponse({ status: 404, message: "Not found" }, 404)
      if (request.method === "DELETE") return new Response(null, { status: 204 })
      const value = translated.value
      const version = value && !Array.isArray(value) && typeof value.version === "number" ? value.version : null
      return jsonResponse(value, 200, version === null ? {} : { ETag: `"${version}"` })
    } catch (error) {
      if (error instanceof VaultApiError) return jsonResponse({ status: error.status, message: error.message }, error.status)
      return jsonResponse({ status: 500, message: (error as Error).message }, 500)
    }
  }
}

export async function startConnectServer(port: number) {
  const config = await getConfig()
  const localToken = encodeBase64(crypto.getRandomValues(new Uint8Array(32)))
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port,
    fetch: createConnectHandler(config, localToken),
  })
  return {
    host: `http://127.0.0.1:${server.port}`,
    token: localToken,
    stop: () => server.stop(true),
  }
}
