import { describe, expect, it } from "bun:test"
import {
  createRecoveryEnvelope,
  decryptJson,
  encryptJson,
  generateDeviceKey,
  itemLocator,
  openRecoveryEnvelope,
  randomKey,
  unwrapAccountKeyForDevice,
  unwrapKey,
  wrapAccountKeyForDevice,
  wrapKey,
} from "./e2ee-crypto"

describe("client E2EE primitives", () => {
  it("round-trips content and rejects a changed context", async () => {
    const key = randomKey()
    const envelope = await encryptJson({ mnemonic: "not logged" }, key, "vault:v:item:i:details")
    expect(await decryptJson(envelope, key, "vault:v:item:i:details")).toEqual({ mnemonic: "not logged" })
    await expect(decryptJson(envelope, key, "vault:v:item:other:details")).rejects.toThrow()
  })

  it("binds wrapped keys to their context", async () => {
    const wrappingKey = randomKey()
    const value = randomKey()
    const envelope = await wrapKey(value, wrappingKey, "vault:v")
    expect(await unwrapKey(envelope, wrappingKey, "vault:v")).toEqual(value)
    await expect(unwrapKey(envelope, wrappingKey, "vault:x")).rejects.toThrow()
  })

  it("wraps an account key to one installation key", async () => {
    const device = await generateDeviceKey()
    const accountKey = randomKey()
    const envelope = await wrapAccountKeyForDevice(accountKey, device.publicKey, "org:1")
    expect(await unwrapAccountKeyForDevice(envelope, device.privateKey, "org:1")).toEqual(accountKey)
    await expect(unwrapAccountKeyForDevice(envelope, device.privateKey, "org:2")).rejects.toThrow()
  })

  it("recovers the account key only with the recovery code", async () => {
    const accountKey = randomKey()
    const recovery = await createRecoveryEnvelope(accountKey, "user:1")
    expect(await openRecoveryEnvelope(recovery.envelope, recovery.code, "user:1")).toEqual(accountKey)
    await expect(openRecoveryEnvelope(recovery.envelope, `${recovery.code}x`, "user:1")).rejects.toThrow()
  })

  it("creates deterministic keyed locators without exposing the name", async () => {
    const key = randomKey()
    const first = await itemLocator(key, "DB_PASSWORD")
    expect(await itemLocator(key, "DB_PASSWORD")).toBe(first)
    expect(await itemLocator(key, "db_password")).not.toBe(first)
    expect(first).not.toContain("DB_PASSWORD")
  })
})
