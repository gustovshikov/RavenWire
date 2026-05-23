import { loadE2EEnv } from "./env"
import { runPreflight } from "./preflight"

export default async function globalSetup() {
  const env = loadE2EEnv({ requireCredentials: !isPreflightOnlyRun() })
  await runPreflight(env)
}

function isPreflightOnlyRun(): boolean {
  return process.argv.some((arg) => arg.includes("preflight.spec"))
}
