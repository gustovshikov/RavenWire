import { login } from "../support/auth"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import { expectLiveViewConnected } from "../support/live-view"
import { createPool } from "../support/pools"
import { e2eName } from "../support/test-data"

test.describe("RavenWire browser smoke @smoke", () => {
  test("login, dashboard sensor visibility, LiveView assets, and pool creation", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)
      await expect(page.getByText("No sensor pods connected.")).toHaveCount(0)
      await expect(page.getByText(e2e.sensorName).first()).toBeVisible()
      await expectLiveViewConnected(page)

      const pool = await createPool(page, e2eName("pool"), "Created by RavenWire E2E smoke test.")
      cleanup.trackPool(pool)
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })
})
