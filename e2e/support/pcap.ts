import { expect, type Page } from "@playwright/test"

import type { E2EEnv } from "./env"
import { checkAndSettle, expectLiveViewConnected, selectAndSettle } from "./live-view"
import { runSsh, shellQuote } from "./ssh"

export async function submitTimeRangePcapSearch(page: Page, sensorName: string): Promise<string> {
  await page.goto("/pcap")
  await expect(page.getByRole("heading", { name: "PCAP Search" })).toBeVisible()
  await expectLiveViewConnected(page)

  await selectAndSettle(page, "#search-type", "time_range")
  await checkAndSettle(page, page.getByLabel(sensorName))

  const end = new Date()
  const start = new Date(end.getTime() - 5 * 60_000)
  await page.locator("#start-time").fill(formatDateTimeLocal(start))
  await page.locator("#end-time").fill(formatDateTimeLocal(end))

  await page.getByRole("button", { name: "Search PCAP" }).click()
  await expect(page.getByText("PCAP search submitted.")).toBeVisible()

  const requestLink = page.locator('a[href^="/pcap/requests/"]', { hasText: sensorName }).first()
  await expect(requestLink).toBeVisible()

  const href = await requestLink.getAttribute("href")
  const match = href?.match(/\/pcap\/requests\/([^/]+)$/)
  if (!match) {
    throw new Error(`Could not determine PCAP request id from ${href}`)
  }

  return match[1]
}

export async function cleanupPcapRequestsByDatabase(env: E2EEnv, requestIds: string[]) {
  if (!env.allowDbCleanup || requestIds.length === 0) return

  for (const requestId of requestIds) {
    if (!/^[0-9a-f-]{36}$/i.test(requestId)) {
      throw new Error(`Refusing to clean invalid PCAP request id: ${requestId}`)
    }
  }

  const ids = requestIds.map(sqlString).join(",")
  const query = [
    `delete from pcap_custody_events where carve_request_id in (${ids});`,
    `delete from pcap_carve_requests where id in (${ids});`
  ].join(" ")

  await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(query)}`)
}

function formatDateTimeLocal(value: Date): string {
  return value.toISOString().slice(0, 16)
}

function sqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}
