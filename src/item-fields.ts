export type ItemField = {
  id: string
  label: string
  value: string
  type: string
  purpose?: string
}

export type FieldAssignment = {
  label: string
  section?: string
  value?: string
  type?: string
}

const FIELD_TYPES: Record<string, string> = {
  password: "CONCEALED",
  concealed: "CONCEALED",
  text: "STRING",
  string: "STRING",
  email: "EMAIL",
  url: "URL",
  date: "DATE",
  monthyear: "MONTH_YEAR",
  month_year: "MONTH_YEAR",
  phone: "PHONE",
  otp: "OTP",
}

function normalizeFieldType(fieldType: string): string {
  return FIELD_TYPES[fieldType.toLowerCase()] ?? fieldType.toUpperCase()
}

export function isFieldAssignment(arg: string): boolean {
  return !arg.startsWith("--") && (arg.includes("=") || /^.+\[\w+\]$/.test(arg))
}

// 1Password assignment syntax:
// [section.]field[type]=value, with the value optional when only changing type.
export function parseFieldAssignment(arg: string): FieldAssignment {
  const eqIdx = arg.indexOf("=")
  const left = eqIdx >= 0 ? arg.slice(0, eqIdx) : arg
  const value = eqIdx >= 0 ? arg.slice(eqIdx + 1) : undefined

  const typeMatch = left.match(/^(.+)\[(\w+)\]$/)
  if (eqIdx < 0 && !typeMatch) {
    throw new Error(`Invalid assignment: ${arg}`)
  }

  const qualifiedLabel = typeMatch ? typeMatch[1]! : left
  if (!qualifiedLabel) {
    throw new Error(`Invalid assignment: ${arg}`)
  }

  const type = typeMatch ? normalizeFieldType(typeMatch[2]!) : undefined
  const dotIdx = qualifiedLabel.indexOf(".")
  if (dotIdx > 0) {
    return {
      section: qualifiedLabel.slice(0, dotIdx),
      label: qualifiedLabel.slice(dotIdx + 1),
      value,
      type,
    }
  }
  return { label: qualifiedLabel, value, type }
}

function defaultFieldType(label: string): string {
  return label.toLowerCase() === "password" ? "CONCEALED" : "STRING"
}

export function applyFieldAssignments(
  fields: ItemField[],
  assignments: string[]
): ItemField[] {
  const updated = fields.map((field) => ({ ...field }))

  for (const raw of assignments) {
    const assignment = parseFieldAssignment(raw)
    const existing = updated.findIndex(
      (field) => field.label === assignment.label || field.id === assignment.label
    )

    if (existing >= 0) {
      const field = { ...updated[existing]! }
      if (assignment.value !== undefined) field.value = assignment.value
      if (assignment.type !== undefined) field.type = assignment.type
      updated[existing] = field
      continue
    }

    updated.push({
      id: assignment.label,
      label: assignment.label,
      value: assignment.value ?? "",
      type: assignment.type ?? defaultFieldType(assignment.label),
    })
  }

  return updated
}
