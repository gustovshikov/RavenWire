import { test, expect } from "@playwright/test"
import { readFile } from "node:fs/promises"
import path from "node:path"

test("server preflight passes @smoke", async () => {
  const summary = JSON.parse(
    await readFile(path.join(process.cwd(), "test-results", "preflight.json"), "utf8")
  )

  expect(summary.ok).toBe(true)
})
