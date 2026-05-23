import { expect, type Page } from "@playwright/test"

import { expectLiveViewConnected } from "./live-view"

type AuditExpectation = {
  action: string
  targetType: string
  targetId: string
  result?: string
}

export async function expectAuditEntry(page: Page, expectation: AuditExpectation) {
  await page.goto("/audit")
  await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible()
  await expectLiveViewConnected(page)

  const row = page
    .locator("tbody tr", { hasText: expectation.action })
    .filter({ hasText: `${expectation.targetType}:${expectation.targetId}` })
    .filter({ hasText: expectation.result ?? "success" })
    .first()

  await expect(row).toBeVisible()
}
