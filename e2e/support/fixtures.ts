import { test as base, expect } from "@playwright/test"

import { type E2EEnv, loadE2EEnv, redactSecrets } from "./env"

type Fixtures = {
  e2e: E2EEnv
}

export const test = base.extend<Fixtures>({
  e2e: async ({}, use) => {
    await use(loadE2EEnv())
  },

  page: async ({ page, e2e }, use, testInfo) => {
    const failures: string[] = []

    page.on("console", (message) => {
      if (message.type() === "error") {
        failures.push(`console error: ${message.text()}`)
      }
    })

    page.on("pageerror", (error) => {
      failures.push(`page error: ${error.message}`)
    })

    page.on("response", (response) => {
      if (response.status() >= 500) {
        failures.push(`HTTP ${response.status()}: ${response.url()}`)
      }
    })

    await use(page)

    if (failures.length > 0) {
      const body = redactSecrets(failures.join("\n"), e2e)
      await testInfo.attach("browser-errors.txt", {
        body,
        contentType: "text/plain"
      })
      expect(failures, body).toEqual([])
    }
  }
})

export { expect }
