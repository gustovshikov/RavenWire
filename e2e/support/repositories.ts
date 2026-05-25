import { expect, type Dialog, type Page } from "@playwright/test"

import {
  clickUntilHidden,
  expectLiveViewConnected,
  expectNoPlainPostNavigation,
  fillAndSettle,
  selectAndSettle
} from "./live-view"

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

  await fillAndSettle(page, 'input[name="repository[name]"]', name)
  await fillAndSettle(page, 'input[name="repository[url]"]', url)
  await selectAndSettle(page, 'select[name="repository[repo_type]"]', "custom")

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

  const acceptDialog = (dialog: Dialog) => dialog.accept()
  page.on("dialog", acceptDialog)
  try {
    await clickUntilHidden(page, row.getByRole("button", { name: "Delete" }), repositoryRow(page, repository.name))
  } finally {
    page.off("dialog", acceptDialog)
  }
  await expect(repositoryRow(page, repository.name)).toBeHidden()
}

export function repositoryRow(page: Page, name: string) {
  return repositoryRows(page, name).first()
}

function repositoryRows(page: Page, name: string) {
  return page.locator("tbody tr", { hasText: name }).filter({ hasText: "custom" })
}
