import { expect, type Page, type TestInfo } from "@playwright/test"

import type { E2EEnv } from "./env"
import { expectLiveViewConnected } from "./live-view"
import { cleanupRepositoryByUi, type CreatedRepository } from "./repositories"
import { runSsh, shellQuote } from "./ssh"

type PoolRecord = {
  name: string
  url: string
}

type RulesetRecord = {
  name: string
  url: string
}

export class CleanupRegistry {
  private pools: PoolRecord[] = []
  private rulesets: RulesetRecord[] = []
  private repositories: CreatedRepository[] = []

  trackPool(pool: PoolRecord) {
    this.pools.push(pool)
  }

  trackRuleset(ruleset: RulesetRecord) {
    this.rulesets.push(ruleset)
  }

  trackRepository(repository: CreatedRepository) {
    this.repositories.push(repository)
  }

  async cleanup(page: Page, testInfo: TestInfo, env: E2EEnv) {
    const failures: string[] = []

    for (const repository of [...this.repositories].reverse()) {
      try {
        await cleanupRepositoryByUi(page, repository)
      } catch (error) {
        failures.push(
          `UI cleanup failed for repository ${repository.name}: ${error instanceof Error ? error.message : String(error)}`
        )
      }
    }

    for (const ruleset of [...this.rulesets].reverse()) {
      try {
        await cleanupRulesetByUi(page, ruleset)
      } catch (error) {
        failures.push(
          `UI cleanup failed for ruleset ${ruleset.name}: ${error instanceof Error ? error.message : String(error)}`
        )

        if (env.allowDbCleanup) {
          try {
            await cleanupRulesetByDatabase(env, ruleset.name)
          } catch (dbError) {
            failures.push(
              `DB cleanup failed for ruleset ${ruleset.name}: ${dbError instanceof Error ? dbError.message : String(dbError)}`
            )
          }
        }
      }
    }

    for (const pool of [...this.pools].reverse()) {
      try {
        await cleanupPoolByUi(page, pool)
      } catch (error) {
        failures.push(`UI cleanup failed for pool ${pool.name}: ${error instanceof Error ? error.message : String(error)}`)

        if (env.allowDbCleanup) {
          try {
            await cleanupPoolByDatabase(env, pool.name)
          } catch (dbError) {
            failures.push(
              `DB cleanup failed for pool ${pool.name}: ${dbError instanceof Error ? dbError.message : String(dbError)}`
            )
          }
        }
      }
    }

    if (failures.length > 0) {
      await testInfo.attach("cleanup-failures.txt", {
        body: failures.join("\n"),
        contentType: "text/plain"
      })
    }
  }
}

export async function cleanupPoolByUi(page: Page, pool: PoolRecord) {
  await page.goto(pool.url)

  if (await page.getByRole("heading", { name: "Pool Not Found" }).isVisible().catch(() => false)) {
    return
  }

  await expect(page.getByRole("heading", { name: pool.name })).toBeVisible()
  await expectLiveViewConnected(page)

  const deleteButton = page.getByRole("button", { name: "Delete Pool" })
  await expect(deleteButton).toBeVisible()
  await deleteButton.click()

  const confirmButton = page.getByRole("button", { name: "Confirm Delete" })
  await expect(confirmButton).toBeVisible()
  await confirmButton.click()

  await expect(page).toHaveURL(/\/pools$/)
  await expect(page.getByRole("link", { name: pool.name })).toHaveCount(0)
}

export async function cleanupRulesetByUi(page: Page, ruleset: RulesetRecord) {
  await page.goto(ruleset.url)

  if (await page.getByRole("heading", { name: "Ruleset Not Found" }).isVisible().catch(() => false)) {
    return
  }

  await expect(page.getByRole("heading", { name: ruleset.name })).toBeVisible()
  await expectLiveViewConnected(page)

  page.once("dialog", (dialog) => dialog.accept())
  const deleteButton = page.getByRole("button", { name: "Delete" })
  await expect(deleteButton).toBeVisible()
  await deleteButton.click()

  await expect(page).toHaveURL(/\/rules\/rulesets$/)
  await expect(page.getByRole("link", { name: ruleset.name })).toHaveCount(0)
}

export async function cleanupPoolByDatabase(env: E2EEnv, poolName: string) {
  if (!env.allowDbCleanup) {
    throw new Error("Direct database cleanup requires E2E_ALLOW_DB_CLEANUP=true")
  }

  if (!poolName.startsWith("e2e-")) {
    throw new Error(`Refusing to delete non-E2E pool: ${poolName}`)
  }

  const query = `delete from sensor_pools where name = ${sqlString(poolName)} and name like 'e2e-%';`
  await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(query)}`)
}

export async function cleanupRulesetByDatabase(env: E2EEnv, rulesetName: string) {
  if (!env.allowDbCleanup) {
    throw new Error("Direct database cleanup requires E2E_ALLOW_DB_CLEANUP=true")
  }

  if (!rulesetName.startsWith("e2e-")) {
    throw new Error(`Refusing to delete non-E2E ruleset: ${rulesetName}`)
  }

  const query = `delete from rulesets where name = ${sqlString(rulesetName)} and name like 'e2e-%';`
  await runSsh(env, `sudo sqlite3 ${shellQuote(env.managerDbPath)} ${shellQuote(query)}`)
}

function sqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}
