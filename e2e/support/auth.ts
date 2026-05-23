import { expect, type Page } from "@playwright/test"

import type { E2EEnv } from "./env"

export async function login(page: Page, env: E2EEnv) {
  await loginAs(page, env.adminUser, env.adminPassword)
}

export async function loginAs(page: Page, username: string, password: string) {
  await page.goto("/login")
  await expect(page.getByRole("heading", { name: "RavenWire Manager" })).toBeVisible()

  await page.locator("#username").fill(username)
  await page.locator("#password").fill(password)

  await Promise.all([
    page.waitForURL((url) => url.pathname === "/" || url.pathname === "/password/change"),
    page.getByRole("button", { name: "Log in" }).click()
  ])

  if (new URL(page.url()).pathname === "/password/change") {
    throw new Error("E2E admin user must not require an interactive password change")
  }

  await expect(page.getByRole("heading", { name: "Sensors" })).toBeVisible()
}
