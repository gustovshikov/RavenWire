import { expect, type Page } from "@playwright/test"

import { expectLiveViewConnected, expectNoPlainPostNavigation } from "./live-view"

export type CreatedUser = {
  username: string
  password: string
  role: string
}

export async function createUser(
  page: Page,
  username: string,
  password: string,
  role = "viewer"
): Promise<CreatedUser> {
  await page.goto("/admin/users")
  await expect(page.getByRole("heading", { name: "User Administration" })).toBeVisible()
  await expectLiveViewConnected(page)

  const form = page.locator('form[phx-submit="create_user"]')
  await form.locator('input[name="user[username]"]').fill(username)
  await form.locator('input[name="user[display_name]"]').fill(`E2E ${role}`)
  await form.locator('input[name="user[password]"]').fill(password)
  await form.locator('select[name="user[role]"]').selectOption(role)
  await form.locator('select[name="user[must_change_password]"]').selectOption("false")

  await expectNoPlainPostNavigation(page, async () => {
    await form.getByRole("button", { name: "Create User" }).click()
  })

  await expect(page.getByText("User created.")).toBeVisible()
  await expect(userRow(page, username)).toBeVisible()

  return { username, password, role }
}

export async function deleteUserByUi(page: Page, username: string) {
  await page.goto("/admin/users")
  await expect(page.getByRole("heading", { name: "User Administration" })).toBeVisible()
  await expectLiveViewConnected(page)

  const row = userRow(page, username)
  if ((await row.count()) === 0) return

  page.once("dialog", (dialog) => dialog.accept())
  await row.getByRole("button", { name: "Delete" }).click()
  await expect(page.getByText("User deleted.")).toBeVisible()
  await expect(userRow(page, username)).toHaveCount(0)
}

function userRow(page: Page, username: string) {
  return page.locator("tbody tr").filter({ hasText: username }).first()
}
