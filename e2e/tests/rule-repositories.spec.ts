import { login } from "../support/auth"
import { CleanupRegistry } from "../support/cleanup"
import { test, expect } from "../support/fixtures"
import { cleanupRepositoryByUi, createRepository, repositoryRow } from "../support/repositories"
import { e2eName } from "../support/test-data"

test.describe("rule repository workflows @full", () => {
  test("create and delete a custom repository", async ({ page, e2e }, testInfo) => {
    const cleanup = new CleanupRegistry()

    try {
      await login(page, e2e)

      const repository = await createRepository(page, e2eName("repo"))
      cleanup.trackRepository(repository)

      const row = repositoryRow(page, repository.name)
      await expect(row).toContainText(repository.url)
      await expect(row).toContainText("custom")
      await expect(row).toContainText("Never Updated")
      await expect(row.getByRole("button", { name: "Update Now" })).toBeVisible()
      await expect(row.getByRole("button", { name: "Delete" })).toBeVisible()

      await cleanupRepositoryByUi(page, repository)
      await expect(repositoryRow(page, repository.name)).toHaveCount(0)
    } finally {
      await cleanup.cleanup(page, testInfo, e2e)
    }
  })
})
