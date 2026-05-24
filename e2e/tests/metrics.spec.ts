import { type Locator, type Page } from "@playwright/test"

import { login, loginAs } from "../support/auth"
import { CleanupRegistry } from "../support/cleanup"
import { createMetricFixture, cleanupMetricFixturesByDatabase, type CreatedMetricFixture } from "../support/metrics"
import { createPool } from "../support/pools"
import { e2eName } from "../support/test-data"
import { test, expect } from "../support/fixtures"
import { expectLiveViewConnected, waitForLiveViewIdle } from "../support/live-view"
import { createUser } from "../support/users"

test.describe("historical metrics workflows @full", () => {
  test("sensor and pool metrics pages render charts, ranges, placeholders, and table fallback", async ({
    page,
    e2e
  }, testInfo) => {
    const cleanup = new CleanupRegistry()
    const fixtures: CreatedMetricFixture[] = []

    try {
      await login(page, e2e)

      const fixture = await createMetricFixture(e2e, e2e.sensorName)
      fixtures.push(fixture)

      await page.goto(`/sensors/${fixture.sensorId}`)
      await expect(page.getByRole("heading", { name: e2e.sensorName })).toBeVisible()
      await expect(page.getByRole("link", { name: "Metrics" })).toBeVisible()

      await page.goto(`/sensors/${fixture.sensorId}/metrics?range=6h`)
      await expect(page.getByRole("heading", { name: `${e2e.sensorName} Metrics` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.locator("#metrics-range")).toHaveValue("6h")
      await expect(page.getByRole("heading", { name: "Drop percent" })).toBeVisible()
      await expect(page.getByText("Data source not yet available").first()).toBeVisible()

      const dropSection = page.locator("section[aria-label*='Drop percent chart']").first()
      await expect(dropSection).toBeVisible()
      await showTableView(dropSection, page)
      await expect(dropSection.getByRole("button", { name: "View chart" })).toBeVisible()
      await expect(dropSection.getByRole("columnheader", { name: "Timestamp" })).toBeVisible()

      await page.locator("#metrics-range").selectOption("1h")
      await expect(page).toHaveURL(/range=1h/)
      await expect(page.locator("#metrics-range")).toHaveValue("1h")

      const pool = await createPool(page, e2eName("metrics-empty-pool"))
      cleanup.trackPool(pool)

      await page.goto(pool.url)
      await expect(page.getByRole("link", { name: "Metrics" })).toBeVisible()

      await page.goto(`${pool.url}/metrics`)
      await expect(page.getByRole("heading", { name: `${pool.name} Metrics` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.getByText("No sensors assigned to this pool")).toBeVisible()

      const viewer = await createUser(
        page,
        e2eName("metrics-viewer"),
        `RavenWireE2E!${Date.now()}`,
        "viewer"
      )
      cleanup.trackUser(viewer)

      await page.getByRole("button", { name: "Logout" }).click()
      await expect(page).toHaveURL(/\/login$/)
      await loginAs(page, viewer.username, viewer.password)

      await page.goto(`/sensors/${fixture.sensorId}/metrics?range=1h`)
      await expect(page.getByRole("heading", { name: `${e2e.sensorName} Metrics` })).toBeVisible()
      await expectLiveViewConnected(page)

      await page.goto(`${pool.url}/metrics`)
      await expect(page.getByRole("heading", { name: `${pool.name} Metrics` })).toBeVisible()
      await expectLiveViewConnected(page)
    } finally {
      await login(page, e2e).catch(() => undefined)
      await cleanup.cleanup(page, testInfo, e2e)

      try {
        await cleanupMetricFixturesByDatabase(e2e, fixtures)
      } catch (error) {
        await testInfo.attach("metrics-cleanup-failure.txt", {
          body: error instanceof Error ? error.message : String(error),
          contentType: "text/plain"
        })
      }
    }
  })
})

async function showTableView(section: Locator, page: Page) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const tableButton = section.getByRole("button", { name: "View as table" })

    if ((await tableButton.count()) === 0) {
      break
    }

    await tableButton.click()
    await waitForLiveViewIdle(page)
    await page.waitForTimeout(250)

    if ((await section.getByRole("button", { name: "View chart" }).count()) > 0) {
      return
    }
  }

  await expect(section.getByRole("button", { name: "View chart" })).toBeVisible()
}
