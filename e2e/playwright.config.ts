import { defineConfig, devices } from "@playwright/test"

import { loadE2EEnv } from "./support/env"

const env = loadE2EEnv({ requireCredentials: false })

export default defineConfig({
  testDir: "./tests",
  globalSetup: "./support/global-setup",
  outputDir: "./test-results/artifacts",
  timeout: 60_000,
  expect: {
    timeout: 10_000
  },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  grep: env.profile === "smoke" ? /@smoke/ : undefined,
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
    ["json", { outputFile: "test-results/results.json" }]
  ],
  use: {
    baseURL: env.baseUrl,
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure"
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
})
