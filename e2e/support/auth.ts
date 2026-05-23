import { expect, type Page } from "@playwright/test"

import type { E2EEnv } from "./env"

export async function login(page: Page, env: E2EEnv) {
  await page.goto("/login")
  await expect(page.getByRole("heading", { name: "RavenWire Manager" })).toBeVisible()

  await page.locator("#username").fill(env.adminUser)
  await page.locator("#password").fill(env.adminPassword)

  await Promise.all([
    page.waitForURL((url) => url.pathname === "/" || url.pathname === "/password/change"),
    page.getByRole("button", { name: "Log in" }).click()
  ])

  if (new URL(page.url()).pathname === "/password/change") {
    throw new Error("E2E admin user must not require an interactive password change")
  }

  await expect(page.getByRole("heading", { name: "Sensors" })).toBeVisible()
}
