import { rawApi, rawSecretsApi, setOverrides } from "./api.js"
import { parseRef } from "./refs.js"
import { VaultApiError } from "./e2ee-client.js"

export { VaultApiError }

export type VaultClientOptions = {
  profile?: string
  org?: string
}

export type VaultItem = {
  id: string
  title: string
  version: number
  vault: { id: string }
  category: string
  tags: string[]
  favorite: boolean
  fields?: Array<{
    id: string
    label: string
    value: string
    type: string
    purpose?: string
  }>
  sections?: object[]
  urls?: Array<{ href: string; primary?: boolean }>
  created_at: string
  updated_at: string
}

export type VaultClient = {
  read(reference: string): Promise<string>
  getItem(vault: string, item: string): Promise<VaultItem>
}

async function resolveVault(nameOrId: string): Promise<string> {
  if (/^[0-9a-hjkmnp-tv-z]{26}$/.test(nameOrId)) return nameOrId
  const vaults = await rawApi<Array<{ id: string; name: string }>>("/v1/vaults")
  const match = vaults.find(
    (vault) => vault.id === nameOrId || vault.name.toLowerCase() === nameOrId.toLowerCase()
  )
  if (!match) throw new VaultApiError(404, `Vault "${nameOrId}" not found`)
  return match.id
}

async function resolveItem(vaultId: string, nameOrId: string): Promise<string> {
  if (/^[0-9a-hjkmnp-tv-z]{26}$/.test(nameOrId)) return nameOrId
  const item = await rawApi<{ id: string }>(`/v1/vaults/${vaultId}/items/resolve`, {
    method: "POST",
    body: { title: nameOrId },
  })
  return item.id
}

export function createVaultClient(options: VaultClientOptions = {}): VaultClient {
  setOverrides(options)
  return {
    async read(reference) {
      const parsed = parseRef(reference)
      if (!parsed.ok) throw new TypeError(parsed.message)
      if (parsed.ref.scheme === "cvlt") {
        const response = await rawSecretsApi<{ value: string }>(
          `/v1/read?ref=${encodeURIComponent(reference)}`
        )
        return response.value
      }
      const ref = parsed.ref
      const vaultId = await resolveVault(ref.vault)
      const itemId = await resolveItem(vaultId, ref.item)
      const item = await rawApi<VaultItem>(`/v1/vaults/${vaultId}/items/${itemId}`)
      const field = item.fields?.find(
        (candidate) => candidate.label === ref.field
          || candidate.id === ref.field
          || candidate.purpose?.toLowerCase() === ref.field.toLowerCase()
      )
      if (!field) {
        throw new VaultApiError(404, `Field "${ref.field}" not found on item "${ref.item}"`)
      }
      return field.value
    },
    async getItem(vault, item) {
      const vaultId = await resolveVault(vault)
      const itemId = await resolveItem(vaultId, item)
      return rawApi<VaultItem>(`/v1/vaults/${vaultId}/items/${itemId}`)
    },
  }
}
