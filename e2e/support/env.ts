import { existsSync, readFileSync } from "node:fs"
import path from "node:path"

export type E2EProfile = "smoke" | "full"

export type E2EEnv = {
  baseUrl: string
  adminUser: string
  adminPassword: string
  sshUser: string
  sshHost: string
  profile: E2EProfile
  sensorName: string
  sensorMaxAgeSeconds: number
  requiredServices: string[]
  managerDbPath: string
  allowDbCleanup: boolean
  skipSshPreflight: boolean
}

type LoadOptions = {
  requireCredentials?: boolean
}

const defaultServices = [
  "config-manager.service",
  "sensor-agent.service",
  "pcap-ring-writer.service",
  "zeek.service",
  "suricata.service",
  "vector.service"
]

let dotEnvLoaded = false

export function loadE2EEnv(options: LoadOptions = {}): E2EEnv {
  loadLocalDotEnv()

  const requireCredentials = options.requireCredentials ?? true
  const adminUser = process.env.E2E_ADMIN_USER ?? ""
  const adminPassword = process.env.E2E_ADMIN_PASSWORD ?? ""

  if (requireCredentials) {
    const missing = []
    if (!adminUser) missing.push("E2E_ADMIN_USER")
    if (!adminPassword) missing.push("E2E_ADMIN_PASSWORD")

    if (missing.length > 0) {
      throw new Error(
        [
          `Missing required E2E environment variable(s): ${missing.join(", ")}`,
          "Set them in your shell or create e2e/.env from e2e/.env.example.",
          "Shell exports take precedence over values in e2e/.env."
        ].join("\n")
      )
    }
  }

  return {
    baseUrl: normalizeBaseUrl(process.env.E2E_BASE_URL ?? "http://172.16.10.38:4000"),
    adminUser,
    adminPassword,
    sshUser: process.env.E2E_SSH_USER ?? "eric",
    sshHost: process.env.E2E_SSH_HOST ?? "172.16.10.38",
    profile: parseProfile(process.env.E2E_PROFILE ?? "smoke"),
    sensorName: process.env.E2E_SENSOR_NAME ?? "sensor-01",
    sensorMaxAgeSeconds: parsePositiveInt(process.env.E2E_SENSOR_MAX_AGE_SECONDS, 600),
    requiredServices: parseList(process.env.E2E_REQUIRED_SERVICES, defaultServices),
    managerDbPath: process.env.E2E_MANAGER_DB_PATH ?? "/data/config_manager/config_manager.db",
    allowDbCleanup: parseBool(process.env.E2E_ALLOW_DB_CLEANUP),
    skipSshPreflight: parseBool(process.env.E2E_SKIP_SSH_PREFLIGHT)
  }
}

function loadLocalDotEnv() {
  if (dotEnvLoaded) return
  dotEnvLoaded = true

  const candidates = [path.join(process.cwd(), "e2e", ".env"), path.join(process.cwd(), ".env")]
  const dotEnvPath = candidates.find((candidate) => existsSync(candidate))

  if (!dotEnvPath) return

  for (const line of readFileSync(dotEnvPath, "utf8").split(/\r?\n/)) {
    const parsed = parseDotEnvLine(line)
    if (!parsed || process.env[parsed.key] !== undefined) continue

    process.env[parsed.key] = parsed.value
  }
}

function parseDotEnvLine(line: string): { key: string; value: string } | undefined {
  const trimmed = line.trim()
  if (!trimmed || trimmed.startsWith("#")) return undefined

  const match = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/)
  if (!match) return undefined

  return {
    key: match[1],
    value: parseDotEnvValue(match[2])
  }
}

function parseDotEnvValue(value: string): string {
  const trimmed = value.trim()
  const quote = trimmed[0]

  if ((quote === "'" || quote === '"') && trimmed.endsWith(quote)) {
    const unquoted = trimmed.slice(1, -1)
    return quote === '"' ? unquoted.replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\"/g, '"') : unquoted
  }

  return trimmed.replace(/\s+#.*$/, "")
}

export function redactSecrets(value: string, env: E2EEnv): string {
  let redacted = value

  for (const secret of [env.adminPassword]) {
    if (secret) {
      redacted = redacted.split(secret).join("[redacted]")
    }
  }

  return redacted
}

function normalizeBaseUrl(value: string): string {
  const parsed = new URL(value)
  parsed.pathname = parsed.pathname.replace(/\/+$/, "")
  return parsed.toString().replace(/\/$/, "")
}

function parseProfile(value: string): E2EProfile {
  if (value === "smoke" || value === "full") return value
  throw new Error(`E2E_PROFILE must be "smoke" or "full", got "${value}"`)
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback

  const parsed = Number.parseInt(value, 10)
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Expected positive integer, got "${value}"`)
  }

  return parsed
}

function parseBool(value: string | undefined): boolean {
  return value === "1" || value === "true" || value === "yes"
}

function parseList(value: string | undefined, fallback: string[]): string[] {
  if (!value) return fallback

  const parsed = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)

  return parsed.length > 0 ? parsed : fallback
}
