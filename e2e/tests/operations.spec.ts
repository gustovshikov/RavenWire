import { login } from "../support/auth"
import { test, expect } from "../support/fixtures"
import { expectLiveViewConnected } from "../support/live-view"

test.describe("sensor, deployment, PCAP, and support workflows @full", () => {
  test("sensor detail, deployment list, PCAP config, and support bundle pages load with real server data", async ({ page, e2e }) => {
    await login(page, e2e)

    await expect(page.getByRole("link", { name: e2e.sensorName }).first()).toBeVisible()
    await page.getByRole("link", { name: e2e.sensorName }).first().click()
    await expect(page.getByRole("heading", { name: e2e.sensorName })).toBeVisible()
    await expectLiveViewConnected(page)
    await expect(page.getByLabel("Sensor Identity")).toBeVisible()
    await expect(page.getByLabel("Deployment State")).toBeVisible()
    await expect(page.getByLabel("Host Readiness")).toBeVisible()

    await page.goto("/deployments")
    await expect(page.getByRole("heading", { name: "Deployments" })).toBeVisible()
    await expectLiveViewConnected(page)

    await page.goto("/pcap-config")
    await expect(page.getByRole("heading", { name: "Alert-Driven PCAP Configuration" })).toBeVisible()
    await expectLiveViewConnected(page)
    await expect(page.getByText(e2e.sensorName).first()).toBeVisible()

    await page.goto("/support-bundle")
    await expect(page.getByRole("heading", { name: "Support Bundles" })).toBeVisible()
    await expectLiveViewConnected(page)
    await expect(page.getByText(e2e.sensorName).first()).toBeVisible()
  })
})
