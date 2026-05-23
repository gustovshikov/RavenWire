import { login } from "../support/auth"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import { expectLiveViewConnected } from "../support/live-view"
import { createPool } from "../support/pools"
import { createRuleset } from "../support/rulesets"
import { e2eName } from "../support/test-data"

test.describe("rule store and ruleset workflows @full", () => {
  test("rule pages load and ruleset create, edit form, assignment, and deployment entry point work", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const pool = await createPool(page, e2eName("pool-rules"))
      cleanup.trackPool(pool)

      for (const [path, heading] of [
        ["/rules/store", "Rule Store"],
        ["/rules/categories", "Rule Categories"],
        ["/rules/repositories", "Rule Repositories"],
        ["/rules/deployments", "Rule Deployments"],
        ["/rules/rulesets", "Rulesets"]
      ] as const) {
        await page.goto(path)
        await expect(page.getByRole("heading", { name: heading })).toBeVisible()
        await expectLiveViewConnected(page)
      }

      const ruleset = await createRuleset(page, e2eName("ruleset"))
      cleanup.trackRuleset(ruleset)

      await page.getByRole("link", { name: "Edit", exact: true }).click()
      await expect(page.getByRole("heading", { name: ruleset.name })).toBeVisible()
      await expectLiveViewConnected(page)
      await page.locator('input[name="ruleset[description]"]').fill("Edited by RavenWire E2E full test.")
      await expect(page.locator('input[name="ruleset[description]"]')).toHaveValue("Edited by RavenWire E2E full test.")

      await page.goto(ruleset.url)
      await expect(page.getByRole("heading", { name: ruleset.name })).toBeVisible()
      await expectLiveViewConnected(page)

      const poolRow = page.locator("tr", { hasText: pool.name })
      await expect(poolRow).toBeVisible()
      await poolRow.getByRole("button", { name: "Assign" }).click()
      await expect(poolRow.getByText("This ruleset")).toBeVisible()
      await expect(poolRow.getByRole("button", { name: "Deploy Rules" })).toBeVisible()

      await poolRow.getByRole("button", { name: "Unassign" }).click()
      await expect(poolRow.getByText("No Ruleset")).toBeVisible()
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })
})
