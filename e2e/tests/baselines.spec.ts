import { login, loginAs } from "../support/auth"
import { cleanupBaselineFixturesByDatabase, createBaselineFixture, type CreatedBaselineFixture } from "../support/baselines"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import { expectLiveViewConnected } from "../support/live-view"
import { createPool } from "../support/pools"
import { e2eName } from "../support/test-data"
import { createUser } from "../support/users"

test.describe("health baselines workflows @full", () => {
  test("sensor and pool baseline pages render learned profiles, placeholders, and viewer access", async ({
    page,
    e2e
  }, testInfo) => {
    const cleanup = new CleanupRegistry()
    const fixtures: CreatedBaselineFixture[] = []

    try {
      await login(page, e2e)

      const fixture = await createBaselineFixture(e2e)
      fixtures.push(fixture)

      await page.goto(`/sensors/${fixture.sensorId}`)
      await expect(page.getByRole("heading", { name: fixture.sensorName })).toBeVisible()
      await expect(page.getByRole("link", { name: "Baselines" })).toBeVisible()

      await page.goto(`/sensors/${fixture.sensorId}/baselines`)
      await expect(page.getByRole("heading", { name: `${fixture.sensorName} Baselines` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.getByRole("heading", { name: "CPU percent" })).toBeVisible()
      await expect(page.getByText("Current value is within the learned baseline.")).toBeVisible()
      await expect(page.getByText("Insufficient data for forecast.")).toBeVisible()
      await expect(page.getByText("Baseline not available. Insufficient data for baseline.").first()).toBeVisible()

      const pool = await createPool(page, e2eName("baselines-empty-pool"))
      cleanup.trackPool(pool)

      await page.goto(pool.url)
      await expect(page.getByRole("link", { name: "Baselines" })).toBeVisible()

      await page.goto(`${pool.url}/baselines`)
      await expect(page.getByRole("heading", { name: `${pool.name} Baselines` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.getByText("No sensors assigned to this pool.")).toBeVisible()

      const viewer = await createUser(
        page,
        e2eName("baselines-viewer"),
        `RavenWireE2E!${Date.now()}`,
        "viewer"
      )
      cleanup.trackUser(viewer)

      await page.getByRole("button", { name: "Logout" }).click()
      await expect(page).toHaveURL(/\/login$/)
      await loginAs(page, viewer.username, viewer.password)

      await page.goto(`/sensors/${fixture.sensorId}/baselines`)
      await expect(page.getByRole("heading", { name: `${fixture.sensorName} Baselines` })).toBeVisible()
      await expectLiveViewConnected(page)

      await page.goto(`${pool.url}/baselines`)
      await expect(page.getByRole("heading", { name: `${pool.name} Baselines` })).toBeVisible()
      await expectLiveViewConnected(page)
    } finally {
      await login(page, e2e).catch(() => undefined)
      await cleanup.cleanup(page, testInfo, e2e)

      try {
        await cleanupBaselineFixturesByDatabase(e2e, fixtures)
      } catch (error) {
        await testInfo.attach("baselines-cleanup-failure.txt", {
          body: error instanceof Error ? error.message : String(error),
          contentType: "text/plain"
        })
      }
    }
  })
})
