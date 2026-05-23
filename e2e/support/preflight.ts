import { mkdir, writeFile } from "node:fs/promises"
import path from "node:path"

import { type E2EEnv, loadE2EEnv, redactSecrets } from "./env"
import { runSsh, shellQuote } from "./ssh"

export type PreflightCheck = {
  name: string
  ok: boolean
  detail: string
}

export type PreflightSummary = {
  ok: boolean
  baseUrl: string
  sshHost: string
  sensorName: string
  checks: PreflightCheck[]
}

export async function runPreflight(env: E2EEnv = loadE2EEnv({ requireCredentials: false })): Promise<PreflightSummary> {
  const checks: PreflightCheck[] = []

  await record(checks, "http:/login", async () => {
    const response = await fetchWithTimeout(new URL("/login", env.baseUrl).toString())
    if (!response.ok) throw new Error(`GET /login returned HTTP ${response.status}`)
    return `HTTP ${response.status}`
  })

  for (const asset of ["/assets/app.js", "/assets/phoenix.min.js", "/assets/phoenix_live_view.min.js"]) {
    await record(checks, `asset:${asset}`, async () => {
      const response = await fetchWithTimeout(new URL(asset, env.baseUrl).toString())
      if (!response.ok) throw new Error(`GET ${asset} returned HTTP ${response.status}`)
      return `HTTP ${response.status}`
    })
  }

  if (env.skipSshPreflight) {
    checks.push({
      name: "ssh:services",
      ok: true,
      detail: "Skipped because E2E_SKIP_SSH_PREFLIGHT is set"
    })
    checks.push({
      name: "ssh:sensor-health",
      ok: true,
      detail: "Skipped because E2E_SKIP_SSH_PREFLIGHT is set"
    })
  } else {
    await record(checks, "ssh:services", async () => checkServices(env))
    await record(checks, "ssh:sensor-health", async () => checkSensorHealth(env))
  }

  const summary = {
    ok: checks.every((check) => check.ok),
    baseUrl: env.baseUrl,
    sshHost: env.sshHost,
    sensorName: env.sensorName,
    checks
  }

  await writePreflightSummary(summary)

  if (!summary.ok) {
    throw new Error(formatPreflightFailure(summary, env))
  }

  return summary
}

async function record(checks: PreflightCheck[], name: string, run: () => Promise<string>) {
  try {
    checks.push({ name, ok: true, detail: await run() })
  } catch (error) {
    checks.push({
      name,
      ok: false,
      detail: error instanceof Error ? error.message : String(error)
    })
  }
}

async function checkServices(env: E2EEnv): Promise<string> {
  const command = `systemctl is-active ${env.requiredServices.map(shellQuote).join(" ")}`
  const result = await runSsh(env, command)
  const statuses = result.stdout.split(/\r?\n/).filter(Boolean)
  const inactive = env.requiredServices.filter((unit, index) => statuses[index] !== "active")

  if (inactive.length > 0) {
    throw new Error(`Inactive service(s): ${inactive.join(", ")}; output: ${result.stdout || result.stderr}`)
  }

  return `Active services: ${env.requiredServices.join(", ")}`
}

async function checkSensorHealth(env: E2EEnv): Promise<string> {
  const query = [
    "select name || '|' || status || '|' || coalesce(last_seen_at, '') || '|' ||",
    "cast((julianday('now') - julianday(last_seen_at)) * 86400 as integer)",
    "from sensor_pods",
    `where name = ${sqlString(env.sensorName)}`,
    "order by last_seen_at desc",
    "limit 1;"
  ].join(" ")

  const command = `sqlite3 -readonly -noheader -batch ${shellQuote(env.managerDbPath)} ${shellQuote(query)}`
  const result = await runSsh(env, command)
  const [name, status, lastSeenAt, ageText] = result.stdout.split("|")

  if (!name) {
    throw new Error(`No sensor_pods row found for ${env.sensorName}`)
  }

  if (status !== "enrolled") {
    throw new Error(`Sensor ${env.sensorName} status is ${status}, expected enrolled`)
  }

  if (!lastSeenAt) {
    throw new Error(`Sensor ${env.sensorName} has no last_seen_at value`)
  }

  const ageSeconds = Number.parseInt(ageText, 10)
  if (!Number.isFinite(ageSeconds)) {
    throw new Error(`Could not parse last_seen_at age for ${env.sensorName}: ${lastSeenAt}`)
  }

  if (ageSeconds > env.sensorMaxAgeSeconds) {
    throw new Error(
      `Sensor ${env.sensorName} last_seen_at is stale: ${lastSeenAt} (${ageSeconds}s old, max ${env.sensorMaxAgeSeconds}s)`
    )
  }

  return `Sensor ${env.sensorName} last seen ${ageSeconds}s ago at ${lastSeenAt}`
}

async function fetchWithTimeout(url: string, timeoutMs = 10_000): Promise<Response> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)

  try {
    return await fetch(url, { signal: controller.signal })
  } finally {
    clearTimeout(timeout)
  }
}

async function writePreflightSummary(summary: PreflightSummary) {
  const outputDir = path.join(process.cwd(), "test-results")
  await mkdir(outputDir, { recursive: true })
  await writeFile(path.join(outputDir, "preflight.json"), `${JSON.stringify(summary, null, 2)}\n`)
}

function formatPreflightFailure(summary: PreflightSummary, env: E2EEnv): string {
  const lines = [
    "E2E preflight failed:",
    ...summary.checks
      .filter((check) => !check.ok)
      .map((check) => `- ${check.name}: ${check.detail}`)
  ]

  return redactSecrets(lines.join("\n"), env)
}

function sqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}
