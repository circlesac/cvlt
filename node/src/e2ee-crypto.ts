export type AesEnvelope = {
  version: 1
  algorithm: "A256GCM"
  nonce: string
  ciphertext: string
}

export type ContentEnvelope = {
  version: 1
  algorithm: "A256GCM"
  nonce: string
  ciphertext: string
  wrapped_key: AesEnvelope
}

export type RsaEnvelope = {
  version: 1
  algorithm: "RSA-OAEP-3072-SHA256"
  ciphertext: string
}

export type RecoveryEnvelope = {
  version: 1
  kdf: "PBKDF2-SHA256"
  iterations: 600000
  salt: string
  wrapped_account_key: AesEnvelope
}

export type DeviceKey = {
  clientId: string
  publicKey: JsonWebKey
  privateKey: JsonWebKey
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer
}

export function encodeBase64(value: Uint8Array): string {
  let binary = ""
  for (let offset = 0; offset < value.length; offset += 0x8000) {
    binary += String.fromCharCode(...value.subarray(offset, offset + 0x8000))
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
}

export function decodeBase64(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/")
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4))
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

export function randomKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

export function generateOpaqueId(): string {
  const chars = "0123456789abcdefghjkmnpqrstvwxyz"
  let timestamp = Date.now()
  let id = ""
  for (let index = 9; index >= 0; index--) {
    id = chars[timestamp & 31]! + id
    timestamp = Math.floor(timestamp / 32)
  }
  const random = crypto.getRandomValues(new Uint8Array(16))
  for (const byte of random) id += chars[byte & 31]
  return id
}

async function aesKey(bytes: Uint8Array, usage: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", arrayBuffer(bytes), "AES-GCM", false, usage)
}

async function encryptAes(plaintext: Uint8Array, keyBytes: Uint8Array, context: string): Promise<AesEnvelope> {
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: arrayBuffer(nonce),
      additionalData: arrayBuffer(encoder.encode(context)),
      tagLength: 128,
    },
    await aesKey(keyBytes, ["encrypt"]),
    arrayBuffer(plaintext)
  )
  return {
    version: 1,
    algorithm: "A256GCM",
    nonce: encodeBase64(nonce),
    ciphertext: encodeBase64(new Uint8Array(ciphertext)),
  }
}

async function decryptAes(envelope: AesEnvelope, keyBytes: Uint8Array, context: string): Promise<Uint8Array> {
  if (envelope.version !== 1 || envelope.algorithm !== "A256GCM") {
    throw new Error("Unsupported encrypted envelope")
  }
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: arrayBuffer(decodeBase64(envelope.nonce)),
      additionalData: arrayBuffer(encoder.encode(context)),
      tagLength: 128,
    },
    await aesKey(keyBytes, ["decrypt"]),
    arrayBuffer(decodeBase64(envelope.ciphertext))
  )
  return new Uint8Array(plaintext)
}

export async function wrapKey(key: Uint8Array, wrappingKey: Uint8Array, context: string): Promise<AesEnvelope> {
  return encryptAes(key, wrappingKey, `${context}:key`)
}

export async function unwrapKey(envelope: AesEnvelope, wrappingKey: Uint8Array, context: string): Promise<Uint8Array> {
  return decryptAes(envelope, wrappingKey, `${context}:key`)
}

export async function encryptContent(
  plaintext: Uint8Array,
  vaultKey: Uint8Array,
  context: string
): Promise<ContentEnvelope> {
  const dataKey = randomKey()
  const encrypted = await encryptAes(plaintext, dataKey, `${context}:content`)
  return {
    ...encrypted,
    wrapped_key: await wrapKey(dataKey, vaultKey, `${context}:dek`),
  }
}

export async function decryptContent(
  envelope: ContentEnvelope,
  vaultKey: Uint8Array,
  context: string
): Promise<Uint8Array> {
  const dataKey = await unwrapKey(envelope.wrapped_key, vaultKey, `${context}:dek`)
  return decryptAes(envelope, dataKey, `${context}:content`)
}

export async function encryptJson(value: unknown, vaultKey: Uint8Array, context: string): Promise<ContentEnvelope> {
  return encryptContent(encoder.encode(JSON.stringify(value)), vaultKey, context)
}

export async function decryptJson<T>(
  envelope: ContentEnvelope,
  vaultKey: Uint8Array,
  context: string
): Promise<T> {
  return JSON.parse(decoder.decode(await decryptContent(envelope, vaultKey, context))) as T
}

export async function generateDeviceKey(): Promise<DeviceKey> {
  const pair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  )
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey)
  const privateKey = await crypto.subtle.exportKey("jwk", pair.privateKey)
  const publicBytes = encoder.encode(JSON.stringify(publicKey))
  const digest = await crypto.subtle.digest("SHA-256", publicBytes)
  return { clientId: encodeBase64(new Uint8Array(digest)), publicKey, privateKey }
}

export async function wrapAccountKeyForDevice(
  accountKey: Uint8Array,
  publicKeyJwk: JsonWebKey,
  account: string
): Promise<RsaEnvelope> {
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  )
  const ciphertext = await crypto.subtle.encrypt(
    { name: "RSA-OAEP", label: arrayBuffer(encoder.encode(`cvlt:v1:account:${account}`)) },
    publicKey,
    arrayBuffer(accountKey)
  )
  return { version: 1, algorithm: "RSA-OAEP-3072-SHA256", ciphertext: encodeBase64(new Uint8Array(ciphertext)) }
}

export async function unwrapAccountKeyForDevice(
  envelope: RsaEnvelope,
  privateKeyJwk: JsonWebKey,
  account: string
): Promise<Uint8Array> {
  if (envelope.version !== 1 || envelope.algorithm !== "RSA-OAEP-3072-SHA256") {
    throw new Error("Unsupported device key envelope")
  }
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  )
  const plaintext = await crypto.subtle.decrypt(
    { name: "RSA-OAEP", label: arrayBuffer(encoder.encode(`cvlt:v1:account:${account}`)) },
    privateKey,
    arrayBuffer(decodeBase64(envelope.ciphertext))
  )
  return new Uint8Array(plaintext)
}

async function recoveryKey(code: string, salt: Uint8Array): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey("raw", arrayBuffer(encoder.encode(code)), "PBKDF2", false, ["deriveBits"])
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: arrayBuffer(salt), iterations: 600000 },
    material,
    256
  )
  return new Uint8Array(bits)
}

export async function createRecoveryEnvelope(
  accountKey: Uint8Array,
  account: string
): Promise<{ code: string; envelope: RecoveryEnvelope }> {
  const code = encodeBase64(randomKey())
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await recoveryKey(code, salt)
  return {
    code,
    envelope: {
      version: 1,
      kdf: "PBKDF2-SHA256",
      iterations: 600000,
      salt: encodeBase64(salt),
      wrapped_account_key: await wrapKey(accountKey, key, `cvlt:v1:recovery:${account}`),
    },
  }
}

export async function openRecoveryEnvelope(
  envelope: RecoveryEnvelope,
  code: string,
  account: string
): Promise<Uint8Array> {
  if (envelope.version !== 1 || envelope.kdf !== "PBKDF2-SHA256" || envelope.iterations !== 600000) {
    throw new Error("Unsupported recovery envelope")
  }
  const key = await recoveryKey(code, decodeBase64(envelope.salt))
  return unwrapKey(envelope.wrapped_account_key, key, `cvlt:v1:recovery:${account}`)
}

export async function itemLocator(vaultKey: Uint8Array, name: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    arrayBuffer(vaultKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  )
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    arrayBuffer(encoder.encode(`cvlt:v1:locator\0${name.normalize("NFKC")}`))
  )
  return encodeBase64(new Uint8Array(signature))
}

function pemBytes(pem: string): Uint8Array {
  const base64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, "")
  return decodeBase64(base64)
}

export async function wrapVaultKeyForKms(
  vaultKey: Uint8Array,
  vaultId: string,
  publicKeyPem: string
): Promise<RsaEnvelope> {
  const publicKey = await crypto.subtle.importKey(
    "spki",
    arrayBuffer(pemBytes(publicKeyPem)),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  )
  const plaintext = encoder.encode(JSON.stringify({ version: 1, vault_id: vaultId, vault_key: encodeBase64(vaultKey) }))
  const ciphertext = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, arrayBuffer(plaintext))
  return { version: 1, algorithm: "RSA-OAEP-3072-SHA256", ciphertext: encodeBase64(new Uint8Array(ciphertext)) }
}

export function parseKmsPlaintext(value: string, vaultId: string): Uint8Array {
  const parsed = JSON.parse(decoder.decode(decodeBase64(value))) as {
    version?: number
    vault_id?: string
    vault_key?: string
  }
  if (parsed.version !== 1 || parsed.vault_id !== vaultId || typeof parsed.vault_key !== "string") {
    throw new Error("KMS returned a vault key for a different context")
  }
  return decodeBase64(parsed.vault_key)
}

export function serializeEncryptedBytes(envelope: ContentEnvelope): Uint8Array {
  return encoder.encode(JSON.stringify(envelope))
}

export function parseEncryptedBytes(value: Uint8Array): ContentEnvelope {
  return JSON.parse(decoder.decode(value)) as ContentEnvelope
}
