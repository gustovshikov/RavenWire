import { type Page } from "@playwright/test"

import { login } from "../support/auth"
import { expectAuditEntry } from "../support/audit"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import { expectLiveViewConnected, expectNoPlainPostNavigation, waitForLiveViewIdle } from "../support/live-view"
import { createPool } from "../support/pools"
import { e2eName } from "../support/test-data"

test.describe("extended pool workflows @full", () => {
  test("edit metadata, save config, and delete", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const pool = await createPool(page, e2eName("pool-edit"), "Original E2E pool description.")
      cleanup.trackPool(pool)
      await expectAuditEntry(page, { action: "pool_created", targetType: "pool", targetId: pool.id })

      await page.goto(pool.url)
      await page.getByRole("link", { name: "Edit Pool" }).click()
      await expect(page.getByRole("heading", { name: `Edit ${pool.name}` })).toBeVisible()
      await expectLiveViewConnected(page)

      const updatedDescription = "Updated by RavenWire E2E extended pool test."
      await fillAndSettle(page, "#sensor_pool_description", updatedDescription)

      await expectNoPlainPostNavigation(page, async () => {
        await page.getByRole("button", { name: "Save Pool" }).click()
      })

      await expect(page).toHaveURL(new RegExp(`/pools/${pool.id}$`))
      await expect(page.getByRole("heading", { name: pool.name })).toBeVisible()
      await expect(page.getByText(updatedDescription)).toBeVisible()
      await expectAuditEntry(page, { action: "pool_updated", targetType: "pool", targetId: pool.id })

      await page.goto(`/pools/${pool.id}/config`)
      await expect(page.getByRole("heading", { name: `${pool.name} Config` })).toBeVisible()
      await expectLiveViewConnected(page)
      await page.locator("#sensor_pool_capture_mode").selectOption("full_pcap")
      await page.locator("#sensor_pool_pcap_ring_size_mb").fill("8192")
      await page.locator("#sensor_pool_pre_alert_window_sec").fill("120")
      await page.locator("#sensor_pool_post_alert_window_sec").fill("45")
      await page.locator("#sensor_pool_alert_severity_threshold").selectOption("3")

      await expectNoPlainPostNavigation(page, async () => {
        await page.getByRole("button", { name: "Save Config" }).click()
      })

      await expect(page.getByText("Pool config saved. Deployment remains an explicit action.")).toBeVisible()
      await expect(page.locator("#sensor_pool_capture_mode")).toHaveValue("full_pcap")
      await expect(page.locator("#sensor_pool_pcap_ring_size_mb")).toHaveValue("8192")
      await expect(page.locator("#sensor_pool_pre_alert_window_sec")).toHaveValue("120")
      await expect(page.locator("#sensor_pool_post_alert_window_sec")).toHaveValue("45")
      await expect(page.locator("#sensor_pool_alert_severity_threshold")).toHaveValue("3")
      await expectAuditEntry(page, { action: "pool_config_updated", targetType: "pool", targetId: pool.id })

      await page.goto(pool.url)
      await expect(page.getByRole("heading", { name: pool.name })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.getByText("Full PCAP")).toBeVisible()

      await page.getByRole("button", { name: "Delete Pool" }).click()
      await expect(page.getByRole("button", { name: "Confirm Delete" })).toBeVisible()
      await page.getByRole("button", { name: "Cancel" }).click()
      await expect(page.getByRole("heading", { name: pool.name })).toBeVisible()
      await expect(page.getByRole("button", { name: "Confirm Delete" })).toHaveCount(0)

      await page.getByRole("button", { name: "Delete Pool" }).click()
      await page.getByRole("button", { name: "Confirm Delete" }).click()
      await expect(page).toHaveURL(/\/pools$/)
      await expect(page.getByRole("link", { name: pool.name })).toHaveCount(0)
      await expectAuditEntry(page, { action: "pool_deleted", targetType: "pool", targetId: pool.id })
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })

  test("assign and remove the built-in sensor when it is available", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const pool = await createPool(page, e2eName("pool-sensor"))
      cleanup.trackPool(pool)

      await page.goto(`/pools/${pool.id}/sensors`)
      await expect(page.getByRole("heading", { name: `${pool.name} Sensors` })).toBeVisible()
      await expectLiveViewConnected(page)

      const assignSection = page.getByRole("region", { name: "Assign Unassigned Sensors", exact: true })
      const sensorCheckbox = assignSection.getByLabel(e2e.sensorName, { exact: true })
      test.skip((await sensorCheckbox.count()) === 0, `${e2e.sensorName} is not currently unassigned`)

      await sensorCheckbox.check()
      await expectNoPlainPostNavigation(page, async () => {
        await assignSection.getByRole("button", { name: "Assign selected unassigned sensors" }).click()
      })

      await expect(page.getByText("Assigned 1 sensor(s).")).toBeVisible()
      const assignedSection = page.getByRole("region", { name: "Assigned Sensors", exact: true })
      await expect(assignedSection.getByRole("link", { name: e2e.sensorName })).toBeVisible()
      await expectAuditEntry(page, { action: "sensor_assigned_to_pool", targetType: "pool", targetId: pool.id })

      await page.goto(`/pools/${pool.id}/sensors`)
      await expect(page.getByRole("heading", { name: `${pool.name} Sensors` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(assignedSection.getByRole("button", { name: `Remove ${e2e.sensorName} from pool` })).toBeVisible()
      await assignedSection.getByRole("button", { name: `Remove ${e2e.sensorName} from pool` }).click()
      await expect(page.getByRole("button", { name: `Confirm removal of ${e2e.sensorName}` })).toBeVisible()
      await page.getByRole("button", { name: `Confirm removal of ${e2e.sensorName}` }).click()

      await expect(page.getByText("Sensor removed from pool.")).toBeVisible()
      await expect(assignedSection.getByText("No sensors are assigned to this pool.")).toBeVisible()
      await expectAuditEntry(page, { action: "sensor_removed_from_pool", targetType: "pool", targetId: pool.id })
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })
})

async function fillAndSettle(page: Page, selector: string, value: string) {
  const field = page.locator(selector)

  for (let attempt = 0; attempt < 3; attempt += 1) {
    await field.fill(value)
    await waitForLiveViewIdle(page)
    await expect(field).toHaveValue(value)
    await page.waitForTimeout(250)
    await waitForLiveViewIdle(page)

    if ((await field.inputValue()) === value) {
      return
    }
  }

  await expect(field).toHaveValue(value)
}
