import { execFile } from "node:child_process"
import { promisify } from "node:util"

import type { E2EEnv } from "./env"

const execFileAsync = promisify(execFile)

export type SshResult = {
  stdout: string
  stderr: string
}

export async function runSsh(env: E2EEnv, command: string, timeoutMs = 15_000): Promise<SshResult> {
  const target = `${env.sshUser}@${env.sshHost}`
  const { stdout, stderr } = await execFileAsync(
    "ssh",
    ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", target, command],
    { timeout: timeoutMs }
  )

  return {
    stdout: String(stdout).trim(),
    stderr: String(stderr).trim()
  }
}

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}
