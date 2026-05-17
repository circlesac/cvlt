/**
 * Unit tests for the OIDC client helpers in api.ts.
 * Uses bun's built-in test runner — no extra deps.
 *
 * Run: bun test
 */

import { describe, it, expect, beforeEach, afterEach, mock } from "bun:test"
import { _resetOidcCache, fetchGithubOidcToken, hasGithubOidcEnv } from "./api"

// Build a minimal valid JWT structure (header.payload.signature) so callers
// that try to parse `exp` from the payload succeed.
function fakeJwt(exp: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" }))
    .toString("base64url")
  const payload = Buffer.from(JSON.stringify({ exp })).toString("base64url")
  return `${header}.${payload}.sig`
}

const realFetch = globalThis.fetch
let fetchSpy: ReturnType<typeof mock>

beforeEach(() => {
  _resetOidcCache()
  fetchSpy = mock(async () => new Response(null, { status: 200 }))
  globalThis.fetch = fetchSpy as unknown as typeof fetch
})

afterEach(() => {
  globalThis.fetch = realFetch
})

describe("hasGithubOidcEnv", () => {
  it("returns true when both vars are present", () => {
    expect(
      hasGithubOidcEnv({
        ACTIONS_ID_TOKEN_REQUEST_URL: "https://example/token?token=x",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "abc",
      } as NodeJS.ProcessEnv)
    ).toBe(true)
  })

  it("returns false when either var is missing", () => {
    expect(hasGithubOidcEnv({} as NodeJS.ProcessEnv)).toBe(false)
    expect(
      hasGithubOidcEnv({
        ACTIONS_ID_TOKEN_REQUEST_URL: "x",
      } as NodeJS.ProcessEnv)
    ).toBe(false)
    expect(
      hasGithubOidcEnv({
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "abc",
      } as NodeJS.ProcessEnv)
    ).toBe(false)
  })
})

describe("fetchGithubOidcToken", () => {
  it("returns null when OIDC env vars are missing", async () => {
    const tok = await fetchGithubOidcToken("aud", {} as NodeJS.ProcessEnv)
    expect(tok).toBeNull()
    expect(fetchSpy.mock.calls.length).toBe(0)
  })

  it("appends audience to the request URL and uses request token as Bearer", async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600
    const fakeToken = fakeJwt(futureExp)
    fetchSpy = mock(async () => new Response(JSON.stringify({ value: fakeToken }), { status: 200 }))
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    const aud = "https://vault.circles.ac/circlesac"
    const tok = await fetchGithubOidcToken(aud, {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token?token=x",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token",
    } as NodeJS.ProcessEnv)
    expect(tok).toBe(fakeToken)
    expect(fetchSpy.mock.calls.length).toBe(1)
    const [calledUrl, init] = fetchSpy.mock.calls[0]!
    expect(calledUrl).toBe(`https://gh.example/token?token=x&audience=${encodeURIComponent(aud)}`)
    expect((init as RequestInit).headers).toEqual({ Authorization: "Bearer request-token" })
  })

  it("appends ? when the request URL has no existing query string", async () => {
    fetchSpy = mock(async () =>
      new Response(JSON.stringify({ value: fakeJwt(Math.floor(Date.now() / 1000) + 3600) }))
    )
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    await fetchGithubOidcToken("aud", {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv)
    expect(fetchSpy.mock.calls[0]![0]).toBe("https://gh.example/token?audience=aud")
  })

  it("returns null on non-OK response", async () => {
    fetchSpy = mock(async () => new Response("Forbidden", { status: 403 }))
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const tok = await fetchGithubOidcToken("aud", {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv)
    expect(tok).toBeNull()
  })

  it("returns null when response has no value field", async () => {
    fetchSpy = mock(async () => new Response(JSON.stringify({}), { status: 200 }))
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const tok = await fetchGithubOidcToken("aud", {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv)
    expect(tok).toBeNull()
  })

  it("caches the token for the same audience until near expiry", async () => {
    const fakeToken = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    fetchSpy = mock(async () => new Response(JSON.stringify({ value: fakeToken })))
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const env = {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv

    const a = await fetchGithubOidcToken("aud-1", env)
    const b = await fetchGithubOidcToken("aud-1", env)
    expect(a).toBe(fakeToken)
    expect(b).toBe(fakeToken)
    // Single network call thanks to the cache
    expect(fetchSpy.mock.calls.length).toBe(1)
  })

  it("re-fetches when the audience changes", async () => {
    fetchSpy = mock(async () =>
      new Response(JSON.stringify({ value: fakeJwt(Math.floor(Date.now() / 1000) + 3600) }))
    )
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const env = {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv
    await fetchGithubOidcToken("aud-A", env)
    await fetchGithubOidcToken("aud-B", env)
    expect(fetchSpy.mock.calls.length).toBe(2)
  })

  it("returns null when fetch throws", async () => {
    fetchSpy = mock(async () => {
      throw new Error("network down")
    })
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const tok = await fetchGithubOidcToken("aud", {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv)
    expect(tok).toBeNull()
  })
})
