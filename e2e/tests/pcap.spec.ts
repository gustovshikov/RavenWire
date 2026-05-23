import { login } from "../support/auth"
import { expect, test } from "../support/fixtures"
import { expectLiveViewConnected } from "../support/live-view"
import { cleanupPcapRequestsByDatabase, submitTimeRangePcapSearch } from "../support/pcap"

test.describe("PCAP search and retrieval workflows @full", () => {
  test("PCAP search, history, detail, manifest, and optional download work against the test server", async ({
    page,
    e2e
  }, testInfo) => {
    const requestIds: string[] = []

    try {
      await login(page, e2e)

      const requestId = await submitTimeRangePcapSearch(page, e2e.sensorName)
      requestIds.push(requestId)

      await page.goto("/pcap/requests")
      await expect(page.getByRole("heading", { name: "PCAP Requests" })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.locator(`a[href="/pcap/requests/${requestId}"]`)).toBeVisible()

      await page.goto(`/pcap/requests/${requestId}`)
      await expect(
        page.getByRole("heading", { name: new RegExp(`${escapeRegex(e2e.sensorName)} PCAP Request`) })
      ).toBeVisible()
      await expect(page.getByText("Search Parameters")).toBeVisible()

      await page.getByRole("link", { name: "Manifest" }).click()
      await expect(page.getByRole("heading", { name: "Chain-of-Custody Manifest" })).toBeVisible()
      await expect(page.getByText(requestId)).toBeVisible()
      await expect(page.getByText("Integrity Hash")).toBeVisible()

      await page.goto(`/pcap/requests/${requestId}`)
      const downloadLink = page.getByRole("link", { name: "Download" })
      if (await downloadLink.isVisible().catch(() => false)) {
        const download = page.waitForEvent("download")
        await downloadLink.click()
        await download
      }
    } finally {
      try {
        await cleanupPcapRequestsByDatabase(e2e, requestIds)
      } catch (error) {
        await testInfo.attach("pcap-cleanup-failure.txt", {
          body: error instanceof Error ? error.message : String(error),
          contentType: "text/plain"
        })
      }
    }
  })
})

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}
