import { describe, expect, it } from "bun:test"
import {
  applyFieldAssignments,
  isFieldAssignment,
  parseFieldAssignment,
} from "./item-fields"

describe("parseFieldAssignment", () => {
  it("parses a type-only password assignment", () => {
    expect(parseFieldAssignment("mnemonic[password]")).toEqual({
      label: "mnemonic",
      value: undefined,
      type: "CONCEALED",
    })
  })

  it("maps op field types to item JSON types", () => {
    expect(parseFieldAssignment("name[text]=Alfred").type).toBe("STRING")
    expect(parseFieldAssignment("expires[monthYear]=2026/07").type).toBe("MONTH_YEAR")
  })

  it("parses a section and an empty value", () => {
    expect(parseFieldAssignment("wallet.mnemonic[password]=")).toEqual({
      section: "wallet",
      label: "mnemonic",
      value: "",
      type: "CONCEALED",
    })
  })

  it("rejects an argument without a value or field type", () => {
    expect(() => parseFieldAssignment("mnemonic")).toThrow("Invalid assignment")
  })
})

describe("isFieldAssignment", () => {
  it("recognizes value and type-only assignments", () => {
    expect(isFieldAssignment("mnemonic=words")).toBe(true)
    expect(isFieldAssignment("mnemonic[password]")).toBe(true)
    expect(isFieldAssignment("--title")).toBe(false)
    expect(isFieldAssignment("telegram-wallet-signer")).toBe(false)
  })
})

describe("applyFieldAssignments", () => {
  const mnemonic = {
    id: "mnemonic",
    label: "mnemonic",
    value: "test words",
    type: "TEXT",
  }

  it("changes an existing field type without changing its value", () => {
    expect(applyFieldAssignments([mnemonic], ["mnemonic[password]"])).toEqual([
      { ...mnemonic, type: "CONCEALED" },
    ])
  })

  it("changes an existing value without changing its type", () => {
    expect(applyFieldAssignments([mnemonic], ["mnemonic=new words"])).toEqual([
      { ...mnemonic, value: "new words" },
    ])
  })

  it("changes an existing field type and value together", () => {
    expect(
      applyFieldAssignments([mnemonic], ["mnemonic[password]=new words"])
    ).toEqual([{ ...mnemonic, value: "new words", type: "CONCEALED" }])
  })

  it("creates a missing field with op-compatible defaults", () => {
    expect(applyFieldAssignments([], ["alias=wallet"])).toEqual([
      { id: "alias", label: "alias", value: "wallet", type: "STRING" },
    ])
  })
})
