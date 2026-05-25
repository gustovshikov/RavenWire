import { expect, type Page } from "@playwright/test"

import { expectLiveViewConnected, expectNoPlainPostNavigation, fillAndSettle } from "./live-view"

export type CreatedPool = {
  name: string
  url: string
  id: string
}

export async function createPool(page: Page, name: string, description = "Created by RavenWire E2E test."): Promise<CreatedPool> {
  await page.goto("/pools/new")
  await expect(page.getByRole("heading", { name: "Create Pool" })).toBeVisible()
  await expectLiveViewConnected(page)

  await fillAndSettle(page, "#sensor_pool_name", name)
  await fillAndSettle(page, "#sensor_pool_description", description)

  await expectNoPlainPostNavigation(page, async () => {
    await page.getByRole("button", { name: "Save Pool" }).click()
  })

  await expect(page).toHaveURL(/\/pools\/[0-9a-f-]+$/i)
  await expect(page.getByRole("heading", { name })).toBeVisible()

  const url = page.url()
  const id = new URL(url).pathname.split("/").filter(Boolean).pop()
  if (!id) throw new Error(`Could not extract pool ID from ${url}`)

  return { name, url, id }
}
