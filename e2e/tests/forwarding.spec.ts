import { login, loginAs } from "../support/auth"
import { expectAuditEntry } from "../support/audit"
import { CleanupRegistry } from "../support/cleanup"
import { createFileSink, forwardingSinkRow } from "../support/forwarding"
import { test, expect } from "../support/fixtures"
import {
  checkAndSettle,
  clickUntilHidden,
  clickUntilVisible,
  expectLiveViewConnected,
  expectNoPlainPostNavigation,
  fillAndSettle,
  selectAndSettle
} from "../support/live-view"
import { createPool } from "../support/pools"
import { e2eName } from "../support/test-data"
import { createUser } from "../support/users"

test.describe("forwarding workflows @full", () => {
  test("create, edit, toggle, delete, schema mode, and audit", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const pool = await createPool(page, e2eName("forwarding-crud"))
      cleanup.trackPool(pool)

      await page.goto(`/pools/${pool.id}/forwarding`)
      await expect(page.getByRole("heading", { name: `${pool.name} Forwarding` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.getByText("No forwarding sinks configured.")).toBeVisible()
      await expect(page.getByText("Saved forwarding changes require an explicit deployment")).toBeVisible()
      await expect(page.getByText("Forwarding telemetry is not yet available")).toBeVisible()
      await expect(page.getByRole("link", { name: "Add Sink" })).toBeVisible()
      await expect(page.getByText("0/0 enabled")).toBeVisible()
      await expect(page.locator("#schema-mode")).toHaveValue("raw")

      await selectAndSettle(page, "#schema-mode", "ecs")
      await expect(page.getByText("Forwarding schema mode updated.")).toBeVisible()
      await expect(page.locator("#schema-mode")).toHaveValue("ecs")
      await expect(page.getByText("Elastic Common Schema").first()).toBeVisible()

      const sink = await createFileSink(
        page,
        pool.id,
        e2eName("file-sink"),
        `/var/sensor/logs/vector/${pool.id}-events.ndjson`
      )

      let row = forwardingSinkRow(page, sink.name)
      await expect(row.getByRole("cell", { name: "File", exact: true })).toBeVisible()
      await expect(row.getByText(sink.pathTemplate)).toBeVisible()
      await expect(row.getByRole("cell", { name: "Enabled", exact: true })).toBeVisible()
      await expect(row.getByText("Not tested")).toBeVisible()
      await expect(row.getByRole("link", { name: "Edit" })).toBeVisible()
      await expect(row.getByRole("button", { name: "Disable" })).toBeVisible()
      await expect(row.getByRole("button", { name: "Test" })).toBeDisabled()
      await expect(page.getByText("1/1 enabled")).toBeVisible()

      const updatedSinkName = `${sink.name}-edited`
      const updatedPath = `/var/sensor/logs/vector/${pool.id}-edited.json`
      await row.getByRole("link", { name: "Edit" }).click()
      await expect(page.getByRole("heading", { name: "Edit Forwarding Sink" })).toBeVisible()
      await expectLiveViewConnected(page)
      await fillAndSettle(page, "#sink-name", updatedSinkName)

      await expectNoPlainPostNavigation(page, async () => {
        await page.getByRole("button", { name: "Save Sink" }).click()
      })

      await expect(page).toHaveURL(new RegExp(`/pools/${pool.id}/forwarding$`))
      await expectLiveViewConnected(page)
      await expect(page.getByText("Forwarding sink saved. Deployment remains an explicit action.")).toBeVisible()
      row = forwardingSinkRow(page, updatedSinkName)
      await expect(row).toBeVisible()

      await row.getByRole("link", { name: "Edit" }).click()
      await expect(page.getByRole("heading", { name: "Edit Forwarding Sink" })).toBeVisible()
      await expectLiveViewConnected(page)
      await fillAndSettle(page, "#sink-path_template", updatedPath)

      await expectNoPlainPostNavigation(page, async () => {
        await page.getByRole("button", { name: "Save Sink" }).click()
      })

      await expect(page).toHaveURL(new RegExp(`/pools/${pool.id}/forwarding$`))
      await expectLiveViewConnected(page)
      await expect(page.getByText("Forwarding sink saved. Deployment remains an explicit action.")).toBeVisible()
      row = forwardingSinkRow(page, updatedSinkName)
      await expect(row).toBeVisible()
      await expect(row.getByText(updatedPath)).toBeVisible()

      await row.getByRole("link", { name: "Edit" }).click()
      await expect(page.getByRole("heading", { name: "Edit Forwarding Sink" })).toBeVisible()
      await expectLiveViewConnected(page)
      await selectAndSettle(page, "#sink-encoding", "json")

      await expectNoPlainPostNavigation(page, async () => {
        await page.getByRole("button", { name: "Save Sink" }).click()
      })

      await expect(page).toHaveURL(new RegExp(`/pools/${pool.id}/forwarding$`))
      await expectLiveViewConnected(page)
      await expect(page.getByText("Forwarding sink saved. Deployment remains an explicit action.")).toBeVisible()
      row = forwardingSinkRow(page, updatedSinkName)
      await expect(row.getByText(updatedPath)).toBeVisible()

      await row.getByRole("link", { name: "Edit" }).click()
      await expect(page.getByRole("heading", { name: "Edit Forwarding Sink" })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(page.locator("#sink-encoding")).toHaveValue("json")
      await page.getByRole("link", { name: "Cancel" }).click()
      await expect(page).toHaveURL(new RegExp(`/pools/${pool.id}/forwarding$`))
      await expectLiveViewConnected(page)
      row = forwardingSinkRow(page, updatedSinkName)
      await expect(row).toBeVisible()

      await clickUntilVisible(
        page,
        row.getByRole("button", { name: "Disable" }),
        row.getByRole("cell", { name: "Disabled", exact: true })
      )
      row = forwardingSinkRow(page, updatedSinkName)
      await expect(row.getByRole("cell", { name: "Disabled", exact: true })).toBeVisible()
      await expect(row.getByRole("button", { name: "Enable" })).toBeVisible()
      await expect(page.getByText("0/1 enabled")).toBeVisible()

      await clickUntilVisible(
        page,
        row.getByRole("button", { name: "Enable" }),
        row.getByRole("cell", { name: "Enabled", exact: true })
      )
      row = forwardingSinkRow(page, updatedSinkName)
      await expect(row.getByRole("cell", { name: "Enabled", exact: true })).toBeVisible()
      await expect(row.getByRole("button", { name: "Disable" })).toBeVisible()

      await clickUntilVisible(
        page,
        row.getByRole("button", { name: "Delete" }),
        page.getByRole("button", { name: "Confirm Delete" })
      )
      await expect(page.getByRole("button", { name: "Confirm Delete" })).toBeVisible()
      await clickUntilHidden(
        page,
        page.getByRole("button", { name: "Cancel" }),
        page.getByRole("button", { name: "Confirm Delete" })
      )
      await expect(page.getByRole("button", { name: "Confirm Delete" })).toHaveCount(0)
      await expect(forwardingSinkRow(page, updatedSinkName)).toBeVisible()

      await clickUntilVisible(
        page,
        forwardingSinkRow(page, updatedSinkName).getByRole("button", { name: "Delete" }),
        page.getByRole("button", { name: "Confirm Delete" })
      )
      await clickUntilHidden(
        page,
        page.getByRole("button", { name: "Confirm Delete" }),
        forwardingSinkRow(page, updatedSinkName)
      )
      await expect(page.getByText("Forwarding sink deleted.")).toBeVisible()
      await expect(forwardingSinkRow(page, updatedSinkName)).toHaveCount(0)
      await expect(page.getByText("No forwarding sinks configured.")).toBeVisible()

      await expectAuditEntry(page, { action: "schema_mode_changed", targetType: "pool", targetId: pool.id })
      await expectAuditEntry(page, { action: "sink_created", targetType: "forwarding_sink", targetId: sink.id })
      await expectAuditEntry(page, { action: "sink_updated", targetType: "forwarding_sink", targetId: sink.id })
      await expectAuditEntry(page, { action: "sink_toggled", targetType: "forwarding_sink", targetId: sink.id })
      await expectAuditEntry(page, { action: "sink_deleted", targetType: "forwarding_sink", targetId: sink.id })
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })

  test("sensor detail shows assigned pool forwarding summary", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const pool = await createPool(page, e2eName("forwarding-sensor"))
      cleanup.trackPool(pool)
      const sink = await createFileSink(
        page,
        pool.id,
        e2eName("sensor-file-sink"),
        `/var/sensor/logs/vector/${pool.id}-sensor.ndjson`
      )

      await page.goto(`/pools/${pool.id}/sensors`)
      await expect(page.getByRole("heading", { name: `${pool.name} Sensors` })).toBeVisible()
      await expectLiveViewConnected(page)

      const assignSection = page.getByRole("region", { name: "Assign Unassigned Sensors", exact: true })
      const sensorCheckbox = assignSection.getByLabel(e2e.sensorName, { exact: true })
      test.skip((await sensorCheckbox.count()) === 0, `${e2e.sensorName} is not currently unassigned`)

      await checkAndSettle(page, sensorCheckbox)
      await expectNoPlainPostNavigation(page, async () => {
        await assignSection.getByRole("button", { name: "Assign selected unassigned sensors" }).click()
      })

      await expect(page.getByText("Assigned 1 sensor(s).")).toBeVisible()
      const assignedSection = page.getByRole("region", { name: "Assigned Sensors", exact: true })
      await assignedSection.getByRole("link", { name: e2e.sensorName }).click()
      await expect(page.getByRole("heading", { name: e2e.sensorName })).toBeVisible()
      await expectLiveViewConnected(page)

      const forwardingSection = page.getByRole("region", { name: "Forwarding" })
      await expect(forwardingSection.getByRole("link", { name: pool.name })).toBeVisible()
      await expect(forwardingSection.getByText("Schema mode: Raw")).toBeVisible()
      await expect(forwardingSection.getByText("1/1 sinks enabled")).toBeVisible()
      await expect(forwardingSection.getByText(sink.name)).toBeVisible()
      await expect(forwardingSection.getByRole("cell", { name: "File", exact: true })).toBeVisible()
      await expect(forwardingSection.getByText("Enabled", { exact: true })).toBeVisible()
      await expect(forwardingSection.getByText("Forwarding telemetry is not yet available")).toBeVisible()
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })

  test("read-only roles can view forwarding but cannot mutate it", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const user = await createUser(
        page,
        e2eName("forwarding-viewer"),
        `RavenWireE2E!${Date.now()}`,
        "viewer"
      )
      cleanup.trackUser(user)

      const pool = await createPool(page, e2eName("forwarding-readonly"))
      cleanup.trackPool(pool)
      const sink = await createFileSink(
        page,
        pool.id,
        e2eName("readonly-file-sink"),
        `/var/sensor/logs/vector/${pool.id}-readonly.ndjson`
      )

      await page.getByRole("button", { name: "Logout" }).click()
      await expect(page).toHaveURL(/\/login$/)
      await loginAs(page, user.username, user.password)

      await page.goto(`/pools/${pool.id}/forwarding`)
      await expect(page.getByRole("heading", { name: `${pool.name} Forwarding` })).toBeVisible()
      await expectLiveViewConnected(page)
      await expect(forwardingSinkRow(page, sink.name)).toBeVisible()
      await expect(page.getByRole("link", { name: "Add Sink" })).toHaveCount(0)
      await expect(page.getByRole("link", { name: "Edit" })).toHaveCount(0)
      await expect(page.getByRole("button", { name: "Disable" })).toHaveCount(0)
      await expect(page.getByRole("button", { name: "Enable" })).toHaveCount(0)
      await expect(page.getByRole("button", { name: "Test" })).toHaveCount(0)
      await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0)
      await expect(page.locator("#schema-mode")).toBeDisabled()

      const deniedResponse = await page.request.get(`/pools/${pool.id}/forwarding/sinks/new`)
      expect(deniedResponse.status()).toBe(403)

      await page.getByRole("button", { name: "Logout" }).click()
      await expect(page).toHaveURL(/\/login$/)
      await login(page, e2e)
    } finally {
      await login(page, e2e).catch(() => undefined)
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })
})
