import { expect, type Page } from "@playwright/test"

import { expectLiveViewConnected, expectNoPlainPostNavigation, fillAndSettle, selectAndSettle } from "./live-view"

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

  await selectAndSettle(page, "#sink-type", "file")
  await selectAndSettle(page, "#sink-encoding", "ndjson")
  await fillAndSettle(page, "#sink-name", name)
  await fillAndSettle(page, "#sink-path_template", pathTemplate)
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
