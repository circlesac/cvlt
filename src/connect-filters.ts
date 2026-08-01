export function filterVaults(
  vaults: Record<string, unknown>[],
  query: URLSearchParams
): Record<string, unknown>[] {
  const filter = query.get("filter")
  const title = filter?.match(/title\s+eq\s+"([^"]+)"/)?.[1]?.toLowerCase()
  if (title) {
    return vaults.filter((vault) =>
      String(vault.name).toLowerCase() === title || String(vault.id).toLowerCase() === title
    )
  }
  const name = filter?.match(/name\s+(co|eq)\s+"([^"]+)"/)
  if (!name) return vaults
  const expected = name[2]!.toLowerCase()
  return vaults.filter((vault) => name[1] === "eq"
    ? String(vault.name).toLowerCase() === expected
    : String(vault.name).toLowerCase().includes(expected))
}
