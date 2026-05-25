import { login } from "../support/auth"
import { test, expect } from "../support/fixtures"
import { clickUntilVisible, expectLiveViewConnected } from "../support/live-view"

test.describe("admin and audit workflows @full", () => {
  test("admin pages, audit filters, audit detail, and export work", async ({ page, e2e }) => {
    await login(page, e2e)

    await page.goto("/admin/users")
    await expect(page.getByRole("heading", { name: "User Administration" })).toBeVisible()
    await expectLiveViewConnected(page)
    await expect(page.getByText(e2e.adminUser.toLowerCase()).first()).toBeVisible()

    await page.goto("/admin/roles")
    await expect(page.getByRole("heading", { name: "Role Reference" })).toBeVisible()
    await expectLiveViewConnected(page)
    await expect(page.getByText("users:manage").first()).toBeVisible()

    await page.goto("/admin/api-tokens")
    await expect(page.getByRole("heading", { name: "API Tokens" })).toBeVisible()
    await expectLiveViewConnected(page)
    await expect(page.getByText("sensors:view").first()).toBeVisible()

    await page.goto("/audit?action=login")
    await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible()
    await expectLiveViewConnected(page)
    await expect(page.getByText("login").first()).toBeVisible()
    await clickUntilVisible(
      page,
      page.locator("tbody tr", { hasText: "login" }).first().getByRole("button", { name: "Show" }),
      page.getByRole("button", { name: "Hide" }).first()
    )
    await expect(page.locator("pre").first()).toBeVisible()

    await page.goto("/audit/export?action=login")
    await expect(page.getByRole("heading", { name: "Audit Export" })).toBeVisible()
    await expectLiveViewConnected(page)
    await expect(page.getByText("Current filters match").first()).toBeVisible()

    const downloadPromise = page.waitForEvent("download")
    await page.getByRole("button", { name: "Download Export" }).click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toContain("ravenwire-audit")
  })
})
