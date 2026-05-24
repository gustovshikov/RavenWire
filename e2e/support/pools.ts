import { expect, type Page } from "@playwright/test"

import { expectLiveViewConnected, expectNoPlainPostNavigation, waitForLiveViewIdle } from "./live-view"

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

async function fillAndSettle(page: Page, selector: string, value: string) {
  const field = page.locator(selector)

  for (let attempt = 0; attempt < 3; attempt += 1) {
    await field.fill(value)
    await waitForLiveViewIdle(page)
    await expect(field).toHaveValue(value)
    await page.waitForTimeout(250)
    await waitForLiveViewIdle(page)

    if ((await field.inputValue()) === value) {
      return
    }
  }

  await expect(field).toHaveValue(value)
}
