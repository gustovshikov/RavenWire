import { expect, type Page } from "@playwright/test"

import { expectLiveViewConnected, expectNoPlainPostNavigation } from "./live-view"

export type CreatedRuleset = {
  name: string
  url: string
  id: string
}

export async function createRuleset(page: Page, name: string, description = "Created by RavenWire E2E test."): Promise<CreatedRuleset> {
  await page.goto("/rules/rulesets/new")
  await expect(page.getByRole("heading", { name: "New Ruleset" })).toBeVisible()
  await expectLiveViewConnected(page)

  await page.locator('input[name="ruleset[name]"]').fill(name)
  await page.locator('input[name="ruleset[description]"]').fill(description)

  await expectNoPlainPostNavigation(page, async () => {
    await page.getByRole("button", { name: "Save Ruleset" }).click()
  })

  await expect(page).toHaveURL(/\/rules\/rulesets\/[0-9a-f-]+$/i)
  await expect(page.getByRole("heading", { name })).toBeVisible()

  const url = page.url()
  const id = new URL(url).pathname.split("/").filter(Boolean).pop()
  if (!id) throw new Error(`Could not extract ruleset ID from ${url}`)

  return { name, url, id }
}
