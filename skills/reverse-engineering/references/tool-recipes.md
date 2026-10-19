# Tool recipes, failure modes, and install hints

Read this only when the commands in `SKILL.md` fail or when you need a tool that is not covered there. Flags drift between releases — when a flag is rejected, run `<tool> --help` and adapt.

## jadx (DEX/APK/JAR → Java)

```powershell
jadx --version
jadx -d <out> --no-res <input.apk>              # sources only
jadx -d <out> --no-src <input.apk>              # resources only
jadx -d <out> --single-class com.example.Foo <input.apk>
jadx -d <out> --show-bad-code <input.apk>       # surface failed methods
jadx -d <out> --deobf <input.apk>               # built-in deobfuscator
jadx -d <out> --log-level ERROR -j 3 <input.apk>   # quiet, bounded threads
```

Failure modes: `JAVA_HOME`/`java` missing (jadx cannot start); OutOfMemory on huge apps (`-j 1`, raise heap via `JAVA_OPTS`); unreadable output on obfuscated/optimized code (retry with `--show-bad-code`, accept fallback pseudocode). Zig-zag control flow is a sign of obfuscation, not a bug. Install: <https://github.com/skylot/jadx/releases> (needs a JRE 17+), or a package manager if the user has one.

## apktool (resources + smali round-trip)

```powershell
apktool --version
apktool d -f -s -o <out> <app.apk>        # resources + manifest, no smali (-s)
apktool d -f -o <out> <app.apk>           # full decode incl. smali
apktool d -f -o <out> --only-manifest <app.apk>
apktool b <decoded-dir> -o <repacked.apk> # authorized targets only
```

Failure modes: `aapt2` not found (install Android SDK build-tools and point `--aapt2`/`ANDROID_AAPT2`); framework mismatch on OEM ROM APKs (`-p <frame-path>` after `apktool if framework-res.apk`); apktool cannot build some protected APKs. Check the version against published advisories before decoding untrusted APKs. Install: <https://apktool.org/docs/install>.

## Android SDK tools

```powershell
aapt2 dump badging <app.apk>
aapt2 dump permissions <app.apk>
aapt2 dump xmltree --file AndroidManifest.xml <app.apk>
apksigner verify --print-certs --verbose <app.apk>
apksigner sign --ks <ks> --ks-key-alias <alias> --out <signed.apk> <apk>
adb devices -l
adb shell pm list packages -f | Select-String <name>
adb shell dumpsys package <pkg>
adb install-multiple <split1.apk> <split2.apk>
```

Install: platform-tools <https://developer.android.com/tools/releases/platform-tools>; build-tools via Android Studio SDK Manager. `adb` "unauthorized" means accept the USB-debugging prompt on the device; "no devices" means drivers/authorization, not a code problem.

## Frida / objection (dynamic, authorized devices only)

```powershell
pip install frida-tools objection
frida-ls-devices
frida-ps -Uai
frida -U -f <pkg> -l <script.js>     # spawn paused; resume explicitly
frida-trace -U -f <pkg> -i "*open*"
objection -g <pkg> explore
```

Frida version must match `frida-server` on the device (install the same version, run as root). Never run a hook you have not read; it executes with the target's authority. `frida-ps -U` failing means no device or no server.

## rizin / radare2 (fast static triage)

```powershell
rizin -N -q -c "ij" -c "q" <bin>                 # file info (JSON)
rizin -N -q -c "aaa" -c "afl" -c "q" <bin>       # analyze + functions
rizin -N -q -c "aaa" -c "s main" -c "pdf" -c "q" <bin>
rizin -N -q -c "aaa" -c "axt @ sym.main" -c "q" <bin>
rizin -N -q -c "izz" -c "q" <bin>                # strings in data sections
```

`-N` skips user config for reproducibility; drop it if the build rejects it. Install: <https://rizin.re/download>. radare2: <https://rada.re/n/>.

## Ghidra headless (full decompile)

```powershell
& "<ghidra>\support\analyzeHeadless.bat" <proj-dir> <proj-name> `
    -import <bin> -scriptPath <scripts> -postScript <Decompile.java> -deleteProject
```

- First run on a large binary can take many minutes; warn the user and set a generous timeout.
- Windows support is less tested than Linux — for quick questions prefer rizin/objdump.
- Never parse GUI stdout; export text/JSON from the postScript.
- Install: <https://github.com/NationalSecurityAgency/ghidra/releases> (needs a JDK 17+; set `JAVA_HOME`).

## objdump / strings / binutils

```powershell
objdump -x <bin>              # all headers; PE imports/exports live here
objdump -p <bin>              # private headers
objdump -d -M intel <bin>     # disassemble
objdump -t <bin>; objdump -T <bin>
readelf -a <bin>              # ELF
nm -D <bin>
strings -n 8 <bin>            # WinLibs/MSYS2; Windows itself ships no strings
```

Windows-native alternatives without MinGW: `dumpbin /headers|/imports|/exports` from Visual Studio Build Tools; Sysinternals `strings64.exe`. `strings`/`objdump` output is huge — always write to `evidence\` and grep, never dump to chat.

## .NET

```powershell
dotnet tool install --global ilspycmd
ilspycmd -p -o <out> <asm.dll>       # project
ilspycmd -t Namespace.Type <asm.dll>
ilspycmd --help                      # confirm flags for the installed version
de4dot <asm.dll> -o <deobf.dll>      # authorized samples only
monodis --assembly <asm.dll>
```

`dnSpy` is GUI-only — not useful to an agent. Check the CLR data directory in the PE header before assuming a `.dll` is managed.

## Packing / firmware / containers

```powershell
upx -t <bin>; upx -d <bin> -o <unpacked>
7z l <archive>; 7z x <archive> -o<dir>
binwalk <fw>; binwalk -e <fw>        # POSIX/WSL; unblob is a modern alternative
```

Microsoft's `Expand-Archive` only accepts `.zip`; for APK/AAB/JAR use the `ZipFile` snippet in `SKILL.md` instead of copying/renaming. Treat any "decrypted" or "deobfuscated" output as a new derived artifact and hash it.

## Install policy

The probe prints hints, not commands to run. Before installing anything: name the tool and version, the exact package manager command, and wait for the user's approval. Prefer official releases with checksums; never use cracked IDA/Hopper/Binary Ninja builds, and do not fetch tools from random mirrors.

## POSIX equivalents

`sha256sum` (hash), `unzip -l` (list), `file`/`xxd -l 16` (identify), `apktool`/`jadx` (same CLIs), `rizin`/`radare2` (same), `gdb` (Linux-only debugging), `binwalk`/`unblob` (firmware). Ghidra and apktool scripts differ only in path separators.
