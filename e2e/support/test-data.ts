import { randomBytes } from "node:crypto"

export function e2eName(kind: string): string {
  const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)
  const suffix = randomBytes(3).toString("hex")
  const safeKind = kind.toLowerCase().replace(/[^a-z0-9_.-]/g, "-")

  return `e2e-${safeKind}-${timestamp}-${suffix}`
}
