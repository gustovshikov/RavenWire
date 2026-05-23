import { expect, type Page } from "@playwright/test"

import { expectLiveViewConnected, expectNoPlainPostNavigation } from "./live-view"

export type CreatedRepository = {
  name: string
  url: string
}

export async function createRepository(
  page: Page,
  name: string,
  url = `https://example.test/${name}.tar.gz`
): Promise<CreatedRepository> {
  await page.goto("/rules/repositories")
  await expect(page.getByRole("heading", { name: "Rule Repositories" })).toBeVisible()
  await expectLiveViewConnected(page)

  await page.locator('input[name="repository[name]"]').fill(name)
  await page.locator('input[name="repository[url]"]').fill(url)
  await page.locator('select[name="repository[repo_type]"]').selectOption("custom")

  await expectNoPlainPostNavigation(page, async () => {
    await page.getByRole("button", { name: "Add Repository" }).click()
  })

  await expect(page.getByText("Repository added.")).toBeVisible()
  await expect(repositoryRow(page, name)).toBeVisible()

  return { name, url }
}

export async function cleanupRepositoryByUi(page: Page, repository: CreatedRepository) {
  await page.goto("/rules/repositories")
  await expect(page.getByRole("heading", { name: "Rule Repositories" })).toBeVisible()
  await expectLiveViewConnected(page)

  const row = repositoryRow(page, repository.name)
  if ((await row.count()) === 0) return

  page.once("dialog", (dialog) => dialog.accept())
  await row.getByRole("button", { name: "Delete" }).click()
  await expect(repositoryRows(page, repository.name)).toHaveCount(0)
}

export function repositoryRow(page: Page, name: string) {
  return repositoryRows(page, name).first()
}

function repositoryRows(page: Page, name: string) {
  return page.locator("tbody tr", { hasText: name }).filter({ hasText: "custom" })
}
