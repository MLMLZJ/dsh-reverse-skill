import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SKILL_NAME = 'reverse-engineering'
const SKILL_DIR = join(dirname(fileURLToPath(import.meta.url)), 'skills', SKILL_NAME)

/**
 * Embedded skill provider: registering through `ctx.skills` puts the skill into
 * the profile-global skill layer, so every agent sees it in its catalog while
 * this row is enabled. Disabling the row disposes the registration and the
 * tool-skill consumer appends a replacement catalog without it.
 */
export const inject = ['skills']

export function apply(ctx) {
  const content = readFileSync(join(SKILL_DIR, 'SKILL.md'), 'utf8')

  ctx.effect(() =>
    ctx.skills.register({
      name: SKILL_NAME,
      description:
        'Reverse-engineer and decompile local software artifacts — APK/AAB, JAR/class, native SO/DLL/EXE, .NET assemblies, firmware. ' +
        'Probes which decompilers are installed (jadx, apktool, adb, Frida, Ghidra, rizin, ILSpy), classifies the artifact, ' +
        'and works an authorized target to readable source with a gated, evidence-first workflow. 反编译/逆向/解包/脱壳/分析 APK、JAR、so、DLL、exe、.NET。',
      whenToUse:
        'The user asks to reverse-engineer, decompile, unpack, or statically analyze an app, binary, .NET assembly or firmware, ' +
        'or asks how a local program works internally.',
      source: 'runtime',
      resourceBase: { kind: 'directory', path: SKILL_DIR },
      content,
    }),
  )
}
