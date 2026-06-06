import { randomUUID } from "node:crypto"

import type { E2EEnv } from "./env"
import { runSsh, shellQuote } from "./ssh"

export type CreatedMetricFixture = {
  ids: string[]
  sensorId: string
  sensorName: string
}

export async function createMetricFixture(env: E2EEnv, sensorName: string): Promise<CreatedMetricFixture> {
  if (!env.allowDbCleanup) {
    throw new Error("Metric fixtures require E2E_ALLOW_DB_CLEANUP=true")
  }

  const sensorIdQuery = `select id from sensor_pods where name = ${sqlString(sensorName)} limit 1;`
  const sensorIdResult = await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(sensorIdQuery)}`)
  const sensorId = sensorIdResult.stdout.trim()

  if (!/^[0-9a-f-]{36}$/i.test(sensorId)) {
    throw new Error(`Could not find enrolled sensor ${sensorName} for metrics fixture`)
  }

  const now = new Date()
  const timestamps = [20, 10, 2].map((minutesAgo) => new Date(now.getTime() - minutesAgo * 60_000))
  const ids = Array.from({ length: 6 }, () => randomUUID())
  const fixtureName = `e2e-metrics-${Date.now()}`

  const rows = [
    metricRow(ids[0], sensorId, "drop_percent", "default", 1.25, timestamps[0], fixtureName),
    metricRow(ids[1], sensorId, "drop_percent", "default", 2.5, timestamps[1], fixtureName),
    metricRow(ids[2], sensorId, "drop_percent", "default", 3.75, timestamps[2], fixtureName),
    metricRow(ids[3], sensorId, "clock_offset_ms", "default", 10, timestamps[0], fixtureName),
    metricRow(ids[4], sensorId, "clock_offset_ms", "default", 15, timestamps[1], fixtureName),
    metricRow(ids[5], sensorId, "clock_offset_ms", "default", 20, timestamps[2], fixtureName)
  ]

  const query = `pragma foreign_keys = on; insert into metric_snapshots (id, sensor_pod_id, metric_type, series_key, value, recorded_at, metadata, inserted_at, updated_at) values ${rows.join(",")};`
  await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(query)}`)

  return { ids, sensorId, sensorName }
}

export async function cleanupMetricFixturesByDatabase(env: E2EEnv, fixtures: CreatedMetricFixture[]) {
  if (!env.allowDbCleanup || fixtures.length === 0) return

  const ids = fixtures.flatMap((fixture) => fixture.ids)
  if (ids.some((id) => !/^[0-9a-f-]{36}$/i.test(id))) {
    throw new Error("Refusing to clean invalid metric fixture IDs")
  }

  const query = `delete from metric_snapshots where id in (${ids.map(sqlString).join(",")});`
  await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(query)}`)
}

function metricRow(
  id: string,
  sensorId: string,
  metricType: string,
  seriesKey: string,
  value: number,
  recordedAt: Date,
  fixtureName: string
): string {
  const now = sqlString(sqlDate(new Date()))
  const metadata = JSON.stringify({ fixture: fixtureName })

  return `(${sqlString(id)}, ${sqlString(sensorId)}, ${sqlString(metricType)}, ${sqlString(seriesKey)}, ${value}, ${sqlString(sqlDate(recordedAt))}, ${sqlString(metadata)}, ${now}, ${now})`
}

function sqlDate(value: Date): string {
  return value.toISOString()
}

function sqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}
