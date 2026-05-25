import { login } from "../support/auth"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import {
  clickUntilVisible,
  expectLiveViewConnected,
  expectNoPlainPostNavigation,
  fillAndSettle,
  selectAndSettle
} from "../support/live-view"
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

      await clickUntilVisible(
        page,
        page.getByRole("button", { name: "Create Profile" }),
        page.getByText("No structured rules.")
      )
      await expect(page.getByText("No structured rules.")).toBeVisible()

      await clickUntilVisible(
        page,
        page.getByRole("button", { name: "Add Rule" }),
        page.getByRole("heading", { name: "Add Rule" })
      )
      await expect(page.getByRole("heading", { name: "Add Rule" })).toBeVisible()
      await selectAndSettle(page, 'select[name="rule[rule_type]"]', "port_exclusion")
      await fillAndSettle(page, 'input[name="rule[label]"]', "E2E HTTPS exclusion")
      await selectAndSettle(page, 'select[name="rule[protocol]"]', "tcp")
      await fillAndSettle(page, 'input[name="rule[port]"]', "443")

      await expectNoPlainPostNavigation(page, async () => {
        await page.getByRole("button", { name: "Save Rule" }).click()
      })

      await expect(page.getByText("E2E HTTPS exclusion")).toBeVisible()
      await expect(page.getByText("not (port 443 and tcp)")).toBeVisible()

      await clickUntilVisible(
        page,
        page.getByRole("button", { name: "Validate" }),
        page.getByText(/Valid BPF expression\./)
      )
      await expect(page.getByText(/Valid BPF expression\./)).toBeVisible()

      await clickUntilVisible(
        page,
        page.getByRole("button", { name: "Save", exact: true }),
        page.getByText("BPF profile saved. Changes are not deployed until deployment runs.")
      )
      await expect(page.getByText("BPF profile saved. Changes are not deployed until deployment runs.")).toBeVisible()
      await expect(page.getByText("Pending deployment")).toBeVisible()

      await clickUntilVisible(
        page,
        page.getByRole("button", { name: "Edit" }),
        page.getByRole("heading", { name: "Edit Rule" })
      )
      await expect(page.getByRole("heading", { name: "Edit Rule" })).toBeVisible()
      await fillAndSettle(page, 'input[name="rule[label]"]', "E2E HTTPS exclusion edited")
      await expectNoPlainPostNavigation(page, async () => {
        await page.getByRole("button", { name: "Save Rule" }).click()
      })
      await expect(page.getByText("E2E HTTPS exclusion edited")).toBeVisible()

      await clickUntilVisible(
        page,
        page.getByRole("button", { name: "Toggle" }),
        page.getByText("Disabled")
      )
      await expect(page.getByText("Disabled")).toBeVisible()

      await clickUntilVisible(
        page,
        page.getByRole("button", { name: "Delete" }),
        page.getByText("No structured rules.")
      )
      await expect(page.getByText("No structured rules.")).toBeVisible()

      await clickUntilVisible(
        page,
        page.getByRole("button", { name: "Reset" }),
        page.getByRole("button", { name: "Confirm Reset" })
      )
      await expect(page.getByRole("button", { name: "Confirm Reset" })).toBeVisible()
      await clickUntilVisible(
        page,
        page.getByRole("button", { name: "Confirm Reset" }),
        page.getByText("BPF profile reset.")
      )
      await expect(page.getByText("BPF profile reset.")).toBeVisible()
      await expect(page.getByText("No structured rules.")).toBeVisible()
      await expect(page.getByText("No filter expression is configured.")).toBeVisible()
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })
})
