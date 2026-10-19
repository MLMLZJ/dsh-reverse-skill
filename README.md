# Reverse Engineering Toolkit — a switchable DSH skill plugin

A DeepSeek Harness **bundle** that registers one model-invocable skill,
`reverse-engineering`, in the profile-global skill layer. Disable the plugin row
(or the whole bundle) in Plugin Manager and the skill disappears from the session
catalog; enable it again and it comes back.

Inspired by the viral "REA — Reverse Engineer Anything" project
(<https://github.com/morluto/rea>), which popularized agent-driven reverse
engineering after adding Android/APK analysis in October 2026. This plugin is an
independent implementation: it ships instructions plus a local toolchain probe,
not REA's engine or MCP server.

## What it does

- Adds a `skill` catalog entry that the agent loads on demand, then follows to
  classify an artifact, probe installed decompilers, work an authorized target,
  and report evidence-backed findings.
- Bundles `scripts/probe-tools.ps1` (32 tools across Android/Java/.NET/native/
  support, PATH + common install dirs + Android SDK, ~1.5 s, read-only).
- Enforces a blocking authorization gate and an explicit refusal list before any
  tool call, and degrades honestly when a decompiler is missing.

## Install (once)

From a DSH session with Full access or approval:

```
plugin_manager action=install_bundle target=<absolute path to this directory>
```

Then confirm the row is active with `plugin_manager list_plugins` (look for
`reverse-skill`) or approval-free `cordis_inspect_query` on the `Config`
provider filtered by `@local/dsh-reverse-skill`.

## On / off

- `plugin_manager action=set_plugin target=reverse-skill enabled=false` — unregisters
  the skill; the next turn receives a replacement catalog without it.
- `enabled=true` — re-registers it (the SKILL.md body is re-read on activation,
  so content edits take effect after a toggle, without restarting DSH).
- `action=remove_bundle target=@local/dsh-reverse-skill` — uninstalls completely.

## Layout

```
package.json              bundle manifest (dsh.bundle.patch)
cordis.patch.yml          inserts row id `reverse-skill`
index.js                  registers the skill via ctx.skills.register()
locale/en.json, zh.json   Plugin Manager title/description
icon.svg                  original icon
skills/reverse-engineering/
  SKILL.md                the instructions the model loads
  references/tool-recipes.md
scripts/probe-tools.ps1   read-only toolchain probe
```

## Safety

The skill refuses DRM/licence/anti-cheat bypass, credential theft, unauthorized
targets, live-service interaction, and redistribution of decompiled material. It
never executes a target on the host; dynamic analysis is limited to a disposable
device/VM the user authorizes. Decompiling a client never reveals server-side
logic — the skill states that limit instead of overselling.
