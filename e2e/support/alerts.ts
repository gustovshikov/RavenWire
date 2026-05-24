import { randomUUID } from "node:crypto"

import type { E2EEnv } from "./env"
import { runSsh, shellQuote } from "./ssh"

export type CreatedAlert = {
  id: string
  message: string
  sensorName: string
}

export async function createAlertFixture(env: E2EEnv, sensorName: string, message: string): Promise<CreatedAlert> {
  if (!env.allowDbCleanup) {
    throw new Error("Alert fixtures require E2E_ALLOW_DB_CLEANUP=true")
  }

  if (!message.startsWith("e2e-")) {
    throw new Error(`Refusing to create non-E2E alert fixture: ${message}`)
  }

  const sensorIdQuery = `select id from sensor_pods where name = ${sqlString(sensorName)} limit 1;`
  const sensorIdResult = await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(sensorIdQuery)}`)
  const sensorId = sensorIdResult.stdout.trim()

  if (!/^[0-9a-f-]{36}$/i.test(sensorId)) {
    throw new Error(`Could not find enrolled sensor ${sensorName} for alert fixture`)
  }

  const id = randomUUID()
  const now = sqlString(sqlDate(new Date()))

  const query = [
    "pragma foreign_keys = on;",
    `insert into alerts (id, alert_type, sensor_pod_id, sensor_pod_db_id, severity, status, message, threshold_value, observed_value, fired_at, inserted_at, updated_at) values (${sqlString(id)}, 'disk_critical', ${sqlString(sensorName)}, ${sqlString(sensorId)}, 'critical', 'firing', ${sqlString(message)}, 90.0, 95.0, ${now}, ${now}, ${now});`
  ].join(" ")

  await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(query)}`)
  return { id, message, sensorName }
}

export async function cleanupAlertFixturesByDatabase(env: E2EEnv, alerts: CreatedAlert[]) {
  if (!env.allowDbCleanup || alerts.length === 0) return

  for (const alert of alerts) {
    if (!/^[0-9a-f-]{36}$/i.test(alert.id) || !alert.message.startsWith("e2e-")) {
      throw new Error(`Refusing to clean invalid alert fixture: ${alert.id}`)
    }
  }

  const ids = alerts.map((alert) => sqlString(alert.id)).join(",")
  const query = `delete from alerts where id in (${ids}) and message like 'e2e-%';`
  await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(query)}`)
}

function sqlDate(value: Date): string {
  return value.toISOString().replace("T", " ").replace("Z", "000")
}

function sqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}
