import { login } from "../support/auth"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import { expectLiveViewConnected } from "../support/live-view"
import { createPool } from "../support/pools"
import { e2eName } from "../support/test-data"

test.describe("pool management workflows @full", () => {
  test("pool list, detail, config, sensors, deployments, drift, and cleanup", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const pool = await createPool(page, e2eName("pool-full"))
      cleanup.trackPool(pool)

      await page.goto("/pools")
      await expect(page.getByRole("heading", { name: "Sensor Pools" })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.getByRole("link", { name: pool.name })).toBeVisible()

      await page.getByRole("link", { name: pool.name }).click()
      await expect(page.getByRole("heading", { name: pool.name })).toBeVisible()
      await expect(page.getByText("Pool Overview")).toBeVisible()

      await page.locator(`a[href="/pools/${pool.id}/config"]`).click()
      await expect(page.getByRole("heading", { name: `${pool.name} Config` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.locator("#sensor_pool_capture_mode")).toHaveValue("alert_driven")
      await expect(page.getByRole("button", { name: "Save Config" })).toBeVisible()

      await page.locator(`a[href="/pools/${pool.id}/sensors"]`).click()
      await expect(page.getByRole("heading", { name: `${pool.name} Sensors` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.getByRole("region", { name: "Assigned Sensors", exact: true })).toBeVisible()
      await expect(page.getByRole("region", { name: "Assign Unassigned Sensors", exact: true })).toBeVisible()

      await page.locator(`a[href="/pools/${pool.id}/deployments"]`).click()
      await expect(page.getByRole("heading", { name: `${pool.name} Deployments` })).toBeVisible()
      await expectLiveViewConnected(page)

      await page.locator(`a[href="/pools/${pool.id}/drift"]`).click()
      await expect(page.getByRole("heading", { name: `${pool.name} Drift` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.getByText("Total Sensors")).toBeVisible()
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })
})
