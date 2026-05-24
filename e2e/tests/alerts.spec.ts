import { login, loginAs } from "../support/auth"
import { cleanupAlertFixturesByDatabase, createAlertFixture, type CreatedAlert } from "../support/alerts"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import { expectLiveViewConnected, expectNoPlainPostNavigation } from "../support/live-view"
import { e2eName } from "../support/test-data"
import { createUser } from "../support/users"

test.describe("platform alert center workflows @full", () => {
  test("rules, notification placeholder, alert lifecycle, audit, and read-only role behavior", async ({
    page,
    e2e
  }, testInfo) => {
    const cleanup = new CleanupRegistry()
    const alerts: CreatedAlert[] = []

    try {
      await login(page, e2e)

      await page.goto("/alerts")
      await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible()
      await expectLiveViewConnected(page)
      const alertSubnav = page.locator("main nav").first()
      await expect(alertSubnav.getByRole("link", { name: "Alerts" })).toBeVisible()
      await expect(alertSubnav.getByRole("link", { name: "Notifications" })).toBeVisible()

      await page.goto("/alerts/notifications")
      await expect(page.getByRole("heading", { name: "Alert Notifications" })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.getByText("planned for a future release")).toBeVisible()

      await page.goto("/alerts/rules")
      await expect(page.getByRole("heading", { name: "Alert Rules" })).toBeVisible()
      await expectLiveViewConnected(page)
      const ruleRow = page.locator("tbody tr", { hasText: "Packet drops high" }).first()
      await expect(ruleRow).toBeVisible()
      const thresholdInput = ruleRow.locator('input[name="rule[threshold_value]"]')
      const originalThreshold = await thresholdInput.inputValue()

      await thresholdInput.fill("6")
      await expectNoPlainPostNavigation(page, async () => {
        await ruleRow.getByRole("button", { name: "Save" }).click()
      })
      await expect(page.getByText("Alert rule updated.")).toBeVisible()

      await thresholdInput.fill(originalThreshold)
      await expectNoPlainPostNavigation(page, async () => {
        await ruleRow.getByRole("button", { name: "Save" }).click()
      })
      await expect(page.getByText("Alert rule updated.")).toBeVisible()

      await page.goto("/audit?action=alert_rule_updated")
      await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible()
      await expect(page.locator("tbody tr", { hasText: "alert_rule_updated" }).first()).toBeVisible()

      const fixture = await createAlertFixture(e2e, e2e.sensorName, e2eName("alert-fixture"))
      alerts.push(fixture)

      await page.goto(`/alerts?search=${encodeURIComponent(fixture.message)}`)
      await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible()
      await expectLiveViewConnected(page)
      let row = page.locator("tbody tr", { hasText: fixture.message }).first()
      await expect(row).toBeVisible()
      await expect(row.getByText("firing", { exact: true })).toBeVisible()

      await expectNoPlainPostNavigation(page, async () => {
        await row.getByRole("button", { name: "Acknowledge" }).click()
      })
      await expect(page.getByText("Alert acknowledged.")).toBeVisible()
      row = page.locator("tbody tr", { hasText: fixture.message }).first()
      await expect(row.getByText("acknowledged", { exact: true })).toBeVisible()

      await expectNoPlainPostNavigation(page, async () => {
        await row.getByRole("button", { name: "Resolve" }).click()
      })
      await expect(page.getByText("Alert resolved.")).toBeVisible()
      row = page.locator("tbody tr", { hasText: fixture.message }).first()
      await expect(row.getByText("resolved", { exact: true })).toBeVisible()

      await page.goto("/audit?action=alert_resolved")
      await expect(page.locator("tbody tr", { hasText: "alert_resolved" }).first()).toBeVisible()

      const viewer = await createUser(page, e2eName("alerts-viewer"), `RavenWireE2E!${Date.now()}`, "viewer")
      cleanup.trackUser(viewer)

      await page.getByRole("button", { name: "Logout" }).click()
      await expect(page).toHaveURL(/\/login$/)
      await loginAs(page, viewer.username, viewer.password)

      await page.goto(`/alerts?search=${encodeURIComponent(fixture.message)}`)
      await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.locator("tbody tr", { hasText: fixture.message }).first()).toBeVisible()
      await expect(page.getByRole("button", { name: "Acknowledge" })).toHaveCount(0)
      await expect(page.getByRole("button", { name: "Resolve" })).toHaveCount(0)

      const deniedRules = await page.request.get("/alerts/rules")
      expect(deniedRules.status()).toBe(403)

      await page.getByRole("button", { name: "Logout" }).click()
      await expect(page).toHaveURL(/\/login$/)
      await login(page, e2e)
    } finally {
      await login(page, e2e).catch(() => undefined)
      await cleanup.cleanup(page, testInfo, e2e)

      try {
        await cleanupAlertFixturesByDatabase(e2e, alerts)
      } catch (error) {
        await testInfo.attach("alert-cleanup-failure.txt", {
          body: error instanceof Error ? error.message : String(error),
          contentType: "text/plain"
        })
      }
    }
  })
})
