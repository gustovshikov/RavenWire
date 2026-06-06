import { login, loginAs } from "../support/auth"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import { checkAndSettle, expectLiveViewConnected, expectNoPlainPostNavigation } from "../support/live-view"
import { createPool } from "../support/pools"
import { e2eName } from "../support/test-data"
import { createUser } from "../support/users"

test.describe("pipeline visualization workflows @full", () => {
  test("sensor and pool pipeline routes render topology, links, and viewer access", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const sensorId = await openSensorDetailFromDashboard(page, e2e.sensorName)
      await expect(page.getByRole("link", { name: "Pipeline" })).toBeVisible()
      await page.getByRole("link", { name: "Pipeline" }).click()
      await expect(page).toHaveURL(new RegExp(`/sensors/${sensorId}/pipeline$`))
      await expectSensorPipeline(page, e2e.sensorName)
      await expect(page.getByRole("link", { name: "Back to sensor" })).toHaveAttribute("href", `/sensors/${sensorId}`)

      const viewer = await createUser(page, e2eName("pipeline-viewer"), `RavenWireE2E!${Date.now()}`, "viewer")
      cleanup.trackUser(viewer)

      const pool = await createPool(page, e2eName("pipeline-pool"), "Created by RavenWire pipeline E2E test.")
      cleanup.trackPool(pool)

      await page.goto(pool.url)
      await expect(page.getByRole("heading", { name: pool.name })).toBeVisible()
      await page.locator(`a[href="/pools/${pool.id}/pipeline"]`).click()
      await expect(page).toHaveURL(new RegExp(`/pools/${pool.id}/pipeline$`))
      await expectPoolPipeline(page, pool.name)
      await expect(page.getByText("No Sensors Assigned")).toBeVisible()
      await expect(page.getByText("0 / 0 reporting")).toBeVisible()
      await expect(page.locator(".pipeline-connector-rate", { hasText: "—" }).first()).toBeVisible()

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

      await page.goto(`/pools/${pool.id}/pipeline`)
      await expectPoolPipeline(page, pool.name)
      await expect(page.getByText("1 / 1 reporting")).toBeVisible()
      await expect(page.getByRole("heading", { name: "Member Sensor Pipelines" })).toBeVisible()
      await expect(page.locator(`a[href="/sensors/${sensorId}/pipeline"]`, { hasText: e2e.sensorName })).toBeVisible()

      await page.goto(`/sensors/${sensorId}/pipeline`)
      await expectSensorPipeline(page, e2e.sensorName)
      await expect(page.getByRole("link", { name: "Pool Pipeline" })).toHaveAttribute(
        "href",
        `/pools/${pool.id}/pipeline`
      )

      await page.getByRole("button", { name: "Logout" }).click()
      await expect(page).toHaveURL(/\/login$/)
      await loginAs(page, viewer.username, viewer.password)

      await page.goto(`/sensors/${sensorId}/pipeline`)
      await expectSensorPipeline(page, e2e.sensorName)

      await page.goto(`/pools/${pool.id}/pipeline`)
      await expectPoolPipeline(page, pool.name)
      await expect(page.locator(`a[href="/sensors/${sensorId}/pipeline"]`, { hasText: e2e.sensorName })).toBeVisible()

      await page.getByRole("button", { name: "Logout" }).click()
      await expect(page).toHaveURL(/\/login$/)
      await page.goto(`/sensors/${sensorId}/pipeline`)
      await expect(page).toHaveURL(/\/login$/)
    } finally {
      await ensureAdminSession(page, e2e)
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })
})

async function openSensorDetailFromDashboard(page, sensorName: string): Promise<string> {
  await page.goto("/")
  await expect(page.getByRole("heading", { name: "Sensors" })).toBeVisible()
  await expectLiveViewConnected(page)

  const sensorLink = page.getByRole("link", { name: `View details for ${sensorName}` })
  await expect(sensorLink).toBeVisible()

  const href = await sensorLink.getAttribute("href")
  const sensorId = href?.split("/").filter(Boolean).pop()
  if (!sensorId) throw new Error(`Could not extract sensor ID from ${href}`)

  await sensorLink.click()
  await expect(page).toHaveURL(new RegExp(`/sensors/${sensorId}$`))
  await expect(page.getByRole("heading", { name: sensorName })).toBeVisible()
  await expectLiveViewConnected(page)

  return sensorId
}

async function expectSensorPipeline(page, sensorName: string) {
  await expect(page.getByRole("heading", { name: `${sensorName} Pipeline` })).toBeVisible()
  await expectPipelineShell(page)
  await expect(page.getByText("Current sensor pipeline state from the latest HealthReport.")).toBeVisible()
  await expect(
    page.getByText(/Physical mirror\/SPAN source health is not reported|Capture interface telemetry is not available/).first()
  ).toBeVisible()
  await expect(page.getByText("Alert Driven PCAP flush telemetry is not reported").first()).toBeVisible()
}

async function expectPoolPipeline(page, poolName: string) {
  await expect(page.getByRole("heading", { name: `${poolName} Pipeline` })).toBeVisible()
  await expectPipelineShell(page)
  await expect(page.getByText("Aggregate pipeline health for this pool.")).toBeVisible()
}

async function expectPipelineShell(page) {
  await expectLiveViewConnected(page)
  await expect(page.getByRole("heading", { name: "Live Data Flow" })).toBeVisible()
  await expect(page.getByRole("group", { name: "Pipeline topology" })).toBeVisible()
  await expect(page.locator(".pipeline-connectors")).toBeVisible()
  await expect(page.getByRole("heading", { name: "Pipeline Summary" })).toBeVisible()
  await expect(page.locator(".pipeline-summary table")).toBeVisible()
  await expect(page.locator(".pipeline-connector-rate").first()).toBeVisible()

  for (const segment of ["Mirror Port", "AF_PACKET", "Zeek", "Suricata", "PCAP Ring", "Vector", "Forwarding Sinks"]) {
    await expect(page.getByText(segment, { exact: true }).first()).toBeVisible()
  }
}

async function ensureAdminSession(page, e2e) {
  const logoutButton = page.getByRole("button", { name: "Logout" })
  if (await logoutButton.isVisible().catch(() => false)) {
    await logoutButton.click()
    await expect(page).toHaveURL(/\/login$/)
  }

  await login(page, e2e)
}
