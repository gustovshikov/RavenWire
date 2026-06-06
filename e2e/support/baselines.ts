import { randomUUID } from "node:crypto"

import type { E2EEnv } from "./env"
import { runSsh, shellQuote } from "./ssh"

export type CreatedBaselineFixture = {
  baselineIds: string[]
  metricIds: string[]
  sensorId: string
  sensorName: string
}

export async function createBaselineFixture(env: E2EEnv): Promise<CreatedBaselineFixture> {
  if (!env.allowDbCleanup) {
    throw new Error("Baseline fixtures require E2E_ALLOW_DB_CLEANUP=true")
  }

  const now = new Date()
  const sensorId = randomUUID()
  const baselineId = randomUUID()
  const metricId = randomUUID()
  const fixtureName = `e2e-baselines-${Date.now()}`
  const sensorName = `e2e-baselines-sensor-${Date.now()}`
  const windowStart = new Date(now.getTime() - 60 * 60_000)
  const windowEnd = new Date(now.getTime() - 10 * 60_000)
  const certExpiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60_000)

  const query = [
    "pragma foreign_keys = on;",
    `insert into sensor_pods (id, name, status, cert_serial, cert_expires_at, last_seen_at, enrolled_at, enrolled_by, public_key_pem, key_fingerprint, inserted_at, updated_at) values (${sqlString(sensorId)}, ${sqlString(sensorName)}, 'enrolled', ${sqlString(`${sensorName}-serial`)}, ${sqlString(sqlDate(certExpiresAt))}, ${sqlString(sqlDate(now))}, ${sqlString(sqlDate(now))}, 'e2e', 'public-key', ${sqlString(`${sensorName}-fingerprint`)}, ${sqlString(sqlDate(now))}, ${sqlString(sqlDate(now))});`,
    `insert into health_baselines (id, sensor_pod_id, pool_id, metric_type, series_key, mean, stddev, p5, p95, min_value, max_value, sample_count, window_start, window_end, computed_at, inserted_at, updated_at) values (${sqlString(baselineId)}, ${sqlString(sensorId)}, null, 'cpu_percent', 'default', 50.0, 5.0, 40.0, 60.0, 35.0, 65.0, 12, ${sqlString(sqlDate(windowStart))}, ${sqlString(sqlDate(windowEnd))}, ${sqlString(sqlDate(now))}, ${sqlString(sqlDate(now))}, ${sqlString(sqlDate(now))});`,
    `insert into metric_snapshots (id, sensor_pod_id, metric_type, series_key, value, recorded_at, metadata, inserted_at, updated_at) values (${sqlString(metricId)}, ${sqlString(sensorId)}, 'cpu_percent', 'default', 52.0, ${sqlString(sqlDate(now))}, ${sqlString(JSON.stringify({ fixture: fixtureName }))}, ${sqlString(sqlDate(now))}, ${sqlString(sqlDate(now))});`
  ].join(" ")

  await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(query)}`)

  return { baselineIds: [baselineId], metricIds: [metricId], sensorId, sensorName }
}

export async function cleanupBaselineFixturesByDatabase(env: E2EEnv, fixtures: CreatedBaselineFixture[]) {
  if (!env.allowDbCleanup || fixtures.length === 0) return

  const baselineIds = fixtures.flatMap((fixture) => fixture.baselineIds)
  const metricIds = fixtures.flatMap((fixture) => fixture.metricIds)
  const sensorIds = fixtures.map((fixture) => fixture.sensorId)

  if ([...baselineIds, ...metricIds, ...sensorIds].some((id) => !/^[0-9a-f-]{36}$/i.test(id))) {
    throw new Error("Refusing to clean invalid baseline fixture IDs")
  }

  const statements = [
    `delete from health_baselines where id in (${baselineIds.map(sqlString).join(",")});`,
    `delete from metric_snapshots where id in (${metricIds.map(sqlString).join(",")});`,
    `delete from sensor_pods where id in (${sensorIds.map(sqlString).join(",")}) and name like 'e2e-baselines-sensor-%';`
  ].join(" ")

  await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(statements)}`)
}

function sqlDate(value: Date): string {
  return value.toISOString()
}

function sqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}
