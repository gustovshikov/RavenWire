import { login } from "../support/auth"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import { expectLiveViewConnected, expectNoPlainPostNavigation } from "../support/live-view"
import { createPool } from "../support/pools"
import { e2eName } from "../support/test-data"

test.describe("BPF editor workflows @full", () => {
  test("create profile, add rule, validate, save, and reset", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const pool = await createPool(page, e2eName("pool-bpf"))
      cleanup.trackPool(pool)

      await page.goto(`/pools/${pool.id}/bpf`)
      await expect(page.getByRole("heading", { name: `${pool.name} BPF Filters` })).toBeVisible()
      await expectLiveViewConnected(page)

      await page.getByRole("button", { name: "Create Profile" }).click()
      await expect(page.getByText("No structured rules.")).toBeVisible()

      await page.getByRole("button", { name: "Add Rule" }).click()
      await expect(page.getByRole("heading", { name: "Add Rule" })).toBeVisible()
      await page.locator('select[name="rule[rule_type]"]').selectOption("port_exclusion")
      await page.locator('input[name="rule[label]"]').fill("E2E HTTPS exclusion")
      await page.locator('select[name="rule[protocol]"]').selectOption("tcp")
      await page.locator('input[name="rule[port]"]').fill("443")

      await expectNoPlainPostNavigation(page, async () => {
        await page.getByRole("button", { name: "Save Rule" }).click()
      })

      await expect(page.getByText("E2E HTTPS exclusion")).toBeVisible()
      await expect(page.getByText("not (port 443 and tcp)")).toBeVisible()

      await page.getByRole("button", { name: "Validate" }).click()
      await expect(page.getByText(/Valid BPF expression\./)).toBeVisible()

      await page.getByRole("button", { name: "Save" }).click()
      await expect(page.getByText("BPF profile saved. Changes are not deployed until deployment runs.")).toBeVisible()
      await expect(page.getByText("Pending deployment")).toBeVisible()

      await page.getByRole("button", { name: "Edit" }).click()
      await expect(page.getByRole("heading", { name: "Edit Rule" })).toBeVisible()
      await page.locator('input[name="rule[label]"]').fill("E2E HTTPS exclusion edited")
      await expectNoPlainPostNavigation(page, async () => {
        await page.getByRole("button", { name: "Save Rule" }).click()
      })
      await expect(page.getByText("E2E HTTPS exclusion edited")).toBeVisible()

      await page.getByRole("button", { name: "Toggle" }).click()
      await expect(page.getByText("Disabled")).toBeVisible()

      await page.getByRole("button", { name: "Delete" }).click()
      await expect(page.getByText("No structured rules.")).toBeVisible()

      await page.getByRole("button", { name: "Reset" }).click()
      await expect(page.getByRole("button", { name: "Confirm Reset" })).toBeVisible()
      await page.getByRole("button", { name: "Confirm Reset" }).click()
      await expect(page.getByText("BPF profile reset.")).toBeVisible()
      await expect(page.getByText("No structured rules.")).toBeVisible()
      await expect(page.getByText("No filter expression is configured.")).toBeVisible()
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })
})
