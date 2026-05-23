import { expect, type Page } from "@playwright/test"

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

export async function waitForLiveViewIdle(page: Page) {
  await expect
    .poll(
      async () =>
        page
          .evaluate(
            () =>
              document.querySelectorAll(
                ".phx-click-loading, .phx-change-loading, .phx-submit-loading"
              ).length
          )
          .catch(() => 0),
      { message: "LiveView should finish processing client events" }
    )
    .toBe(0)
}

export async function expectNoPlainPostNavigation(page: Page, action: () => Promise<void>) {
  const before = new URL(page.url())

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
