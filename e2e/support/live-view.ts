import { expect, type Locator, type Page } from "@playwright/test"

export async function expectLiveViewConnected(page: Page) {
  await expect
    .poll(
      async () =>
        page.evaluate(() => {
          const liveSocket = (window as typeof window & { liveSocket?: { isConnected?: () => boolean } }).liveSocket
          return Boolean(liveSocket?.isConnected?.())
        }),
      { message: "LiveView client should be loaded and connected" }
    )
    .toBe(true)
}

export async function waitForLiveViewReady(page: Page) {
  await expectLiveViewConnected(page)

  await expect
    .poll(
      async () =>
        page
          .evaluate(() => {
            const roots = Array.from(document.querySelectorAll("[data-phx-main], [data-phx-session]"))
            return roots.some((root) => !root.classList.contains("phx-disconnected"))
          })
          .catch(() => false),
      { message: "Current LiveView root should be mounted" }
    )
    .toBe(true)

  await waitForLiveViewIdle(page)
}

export async function waitForLiveViewIdle(page: Page) {
  await expect
    .poll(
      async () =>
        page
          .evaluate(
            () =>
              document.querySelectorAll(
                ".phx-loading, .phx-click-loading, .phx-change-loading, .phx-submit-loading"
              ).length
          )
          .catch(() => 0),
      { message: "LiveView should finish processing client events" }
    )
    .toBe(0)
}

export async function expectNoPlainPostNavigation(page: Page, action: () => Promise<void>) {
  const before = new URL(page.url())

  await waitForLiveViewReady(page)
  await action()
  await page.waitForLoadState("domcontentloaded").catch(() => undefined)
  await waitForLiveViewIdle(page).catch(() => undefined)

  const after = new URL(page.url())
  expect(
    after.pathname === before.pathname && /%5B|sensor_pool|ruleset|repository|rule%5B|rule\[/.test(after.search),
    "LiveView form submit should not perform native query-string navigation"
  ).toBe(false)
  await expect(page.getByText("Phoenix.Router.NoRouteError")).toHaveCount(0)
  await expect(page.getByText(/no route found for POST/i)).toHaveCount(0)
}

export async function fillAndSettle(page: Page, target: string | Locator, value: string) {
  const field = resolveLocator(page, target)

  await waitForLiveViewReady(page)

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

export async function selectAndSettle(page: Page, target: string | Locator, value: string) {
  const field = resolveLocator(page, target)

  await waitForLiveViewReady(page)

  for (let attempt = 0; attempt < 3; attempt += 1) {
    await field.selectOption(value)
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

export async function checkAndSettle(page: Page, target: string | Locator) {
  const checkbox = resolveLocator(page, target)

  await waitForLiveViewReady(page)

  for (let attempt = 0; attempt < 3; attempt += 1) {
    await checkbox.check()
    await waitForLiveViewIdle(page)
    await expect(checkbox).toBeChecked()
    await page.waitForTimeout(250)
    await waitForLiveViewIdle(page)

    if (await checkbox.isChecked()) {
      return
    }
  }

  await expect(checkbox).toBeChecked()
}

export async function clickAndSettle(page: Page, target: Locator) {
  await waitForLiveViewReady(page)
  await target.scrollIntoViewIfNeeded()
  await expect(target).toBeVisible()
  await expect(target).toBeEnabled()
  await target.click()
  await page.waitForLoadState("domcontentloaded").catch(() => undefined)
  await waitForLiveViewIdle(page)
}

export async function clickUntilVisible(page: Page, target: Locator, expected: Locator) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (await isVisible(expected)) return

    await clickAndSettle(page, target).catch(() => undefined)
    await page.waitForTimeout(250)
    await waitForLiveViewIdle(page)

    if (await isVisible(expected)) return

    await domClickAndSettle(page, target)
    await page.waitForTimeout(250)

    if (await isVisible(expected)) return
  }

  await expect(expected).toBeVisible()
}

export async function clickUntilHidden(page: Page, target: Locator, expectedHidden: Locator) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (await isHidden(expectedHidden)) return

    await clickAndSettle(page, target).catch(() => undefined)
    await page.waitForTimeout(250)
    await waitForLiveViewIdle(page)

    if (await isHidden(expectedHidden)) return

    await domClickAndSettle(page, target)
    await page.waitForTimeout(250)

    if (await isHidden(expectedHidden)) return
  }

  await expect(expectedHidden).toBeHidden()
}

export async function clickUntilURL(page: Page, target: Locator, expected: RegExp) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (expected.test(page.url())) return

    await clickAndSettle(page, target).catch(() => undefined)
    await page.waitForTimeout(250)
    await waitForLiveViewIdle(page).catch(() => undefined)

    if (expected.test(page.url())) return

    await domClickAndSettle(page, target)
    await page.waitForTimeout(250)

    if (expected.test(page.url())) return
  }

  await expect(page).toHaveURL(expected)
}

function resolveLocator(page: Page, target: string | Locator): Locator {
  return typeof target === "string" ? page.locator(target) : target
}

async function domClickAndSettle(page: Page, target: Locator) {
  await waitForLiveViewReady(page).catch(() => undefined)
  await target.evaluate((element) => (element as HTMLElement).click()).catch(() => undefined)
  await page.waitForLoadState("domcontentloaded").catch(() => undefined)
  await waitForLiveViewIdle(page).catch(() => undefined)
}

async function isVisible(locator: Locator): Promise<boolean> {
  return locator.isVisible().catch(() => false)
}

async function isHidden(locator: Locator): Promise<boolean> {
  return locator.isHidden().catch(() => true)
}
