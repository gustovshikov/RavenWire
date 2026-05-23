import { expect, type Page } from "@playwright/test"

import { expectLiveViewConnected, expectNoPlainPostNavigation, waitForLiveViewIdle } from "./live-view"

export type CreatedFileSink = {
  name: string
  pathTemplate: string
  url: string
  id: string
}

export async function createFileSink(
  page: Page,
  poolId: string,
  name: string,
  pathTemplate: string
): Promise<CreatedFileSink> {
  await page.goto(`/pools/${poolId}/forwarding/sinks/new`)
  await expect(page.getByRole("heading", { name: "Add Forwarding Sink" })).toBeVisible()
  await expectLiveViewConnected(page)

  await page.locator("#sink-type").selectOption("file")
  await waitForLiveViewIdle(page)
  await expect(page.locator("#sink-type")).toHaveValue("file")
  await page.locator("#sink-encoding").selectOption("ndjson")
  await waitForLiveViewIdle(page)
  await expect(page.locator("#sink-encoding")).toHaveValue("ndjson")
  await page.locator("#sink-name").fill(name)
  await page.locator("#sink-path_template").fill(pathTemplate)
  await waitForLiveViewIdle(page)
  await expect(page.locator("#sink-name")).toHaveValue(name)
  await expect(page.locator("#sink-path_template")).toHaveValue(pathTemplate)
  await expect(page.locator("#sink-encoding")).toHaveValue("ndjson")

  await expectNoPlainPostNavigation(page, async () => {
    await page.getByRole("button", { name: "Create Sink" }).click()
  })

  await expect(page).toHaveURL(new RegExp(`/pools/${poolId}/forwarding$`))
  await expectLiveViewConnected(page)
  await expect(page.getByText("Forwarding sink created. Deployment remains an explicit action.")).toBeVisible()
  const row = forwardingSinkRow(page, name)
  await expect(row).toBeVisible()

  const href = await row.getByRole("link", { name: "Edit" }).getAttribute("href")
  if (!href) throw new Error(`Could not find edit link for forwarding sink ${name}`)
  const parts = href.split("/").filter(Boolean)
  const id = parts[parts.length - 2]
  if (!id) throw new Error(`Could not extract sink ID from ${href}`)

  return { name, pathTemplate, url: href, id }
}

export function forwardingSinkRow(page: Page, name: string) {
  return page.locator("tbody tr").filter({ hasText: name }).first()
}
