# AgentScan

**English** | [Español](README.es.md)

A mini scanner for the Minecraft process (Java Edition, HotSpot JVM on Windows x64). It looks
for **traces of JVMTI agents, Java agents (`java.lang.instrument`) and tampering with the
virtual machine environment**. It finds both an agent that is running right now and an agent
that has already detached.

The main idea: attaching an agent changes the state of the virtual machine irreversibly. The
agent code can be unloaded, the transformer removed, the JVMTI environment disposed. But the
VM still remembers that the agent was there:

- an entry in its own agent list;
- a JVMTI environment with the «disposed» magic number;
- a flag set by the attach mechanism;
- a class redefinition entry in a ring log;
- a redefinition counter in the class mirror.

AgentScan reads these records from process memory without stopping the game and without
attaching a debugger to it.

---

## Contents

- [Quick start](#quick-start)
- [Output](#output)
- [What it finds](#what-it-finds)
  - [1. JVMTI environments](#1-jvmti-environments)
  - [2. Java agents and the attach mechanism](#2-java-agents-and-the-attach-mechanism)
  - [3. VM black box and class redefinition](#3-vm-black-box-and-class-redefinition)
  - [4. Java environment](#4-java-environment)
  - [5. Signatures in memory](#5-signatures-in-memory)
- [How it works](#how-it-works)
- [Limitations](#limitations)
- [Positive test](#positive-test)
- [Building](#building)

---

## Quick start

### Window

Run `AgentScan.exe` with a double click, preferably **as administrator**.

1. The list immediately shows `javaw.exe` and `java.exe` processes as
   `PID Window title - memory in GB`, for example `4992 Minecraft* 1.21.10 - 1.17 GB`.
   Minecraft windows are at the top and preselected. If the game was started later, press
   «Refresh».
2. «Scan»: the bar shows the scan progress, with the current step below it (the full memory
   scan also shows a percentage).
3. At the end you see the verdict (red, yellow or green) and the finding counters. Two buttons:
   - **«Result»** opens the `reports` folder and selects the HTML report;
   - **«In browser»** opens the report in the default browser. The browser is taken from the
     `http` link handler, not from the `.html` file association: that one often points to an
     editor.

If you close the window during a scan, the scanner asks for confirmation and closes after the
current step.

Without administrator rights a warning is shown at the bottom of the window: only processes of
the current user are available then.

### Console

Any argument switches to console mode (same output and exit codes):

```bat
AgentScan.exe --console
AgentScan.exe --pid 1234
AgentScan.exe --list
```

With `--console` the Minecraft process is found automatically. If there are several matching
processes, specify `--pid`. The exe is built as a windowed program, so in `cmd` the prompt
returns before the output ends. To wait for the end and get the exit code, run it through
`start /wait AgentScan.exe --pid 1234`. In PowerShell, waiting happens automatically when the
output is redirected (`| ...`, `> file`).

The checked machine does not need .NET if you use the full `AgentScan.exe` (self-contained,
single file). The lite `AgentScan-lite.exe` (~1 MB) needs the .NET 8 Desktop Runtime — see
[Building](#building).

| Option | What it does |
|---|---|
| `--pid, -p <N>` | game process PID (found automatically by default) |
| `--list, -l` | list Java processes and exit |
| `--console, -c` | console mode with automatic process discovery |
| `--out, -o <dir>` | report directory (default: `reports` next to the exe) |
| `--dump-dir <dir>` | directory for dumps of found residues |
| `--verbose, -v` | verbose console output |
| `--max-dump <MB>` | limit for one dump (default 256 MB) |
| `--no-strings` | skip the full memory scan: fast, but some checks will have no data |
| `--no-dump` | do not save dumps |
| `--fast` | same as `--no-strings --no-dump` |
| `--only <part,...>` | run only steps whose name contains a substring (scanner debugging; the report is marked incomplete) |
| `--skip <part,...>` | skip such steps |

---

## Output

1. **Console** (in the window — verdict and counters): findings grouped by severity
   (CRITICAL → HIGH → MEDIUM → LOW). At the bottom: totals, time and a one-line verdict.
2. **`reports/agentscan-<pid>-<time>.html`**: the report for reading. It has the verdict,
   counters, severity and category filters, search, dark and light themes, and an
   **EN / ES language switch** (English by default, the choice is remembered). Every finding
   has an explanation of the mechanics and the raw data. The «Full data» tab holds the full
   sections: JVMTI environments, VM flags, event logs, runtime properties.
3. **`agentscan-<pid>-<time>.txt`**: the same report as full text (English).
4. **`agentscan-<pid>-<time>.json`**: for automated processing (English).
5. **`reports/agentscan-dumps-<time>/`**: dumps of found residues (environments, agent
   records, JPLIS structures), if any.

Finding severity:

| Level | Meaning |
|---|---|
| **CRITICAL** | practically unambiguous evidence |
| **HIGH** | a strong sign that needs an explanation |
| **MEDIUM** | needs manual review |
| **LOW** | a weak anomaly, also seen in clean processes |
| **INFO** | reference, not evidence |

Exit codes: `10` — CRITICAL found, `9` — HIGH found, `8` — MEDIUM found, `0` — clean,
`2` — process not found, `3` — fatal error.

---

## What it finds

All checks by group are listed below. The severity is the one the scanner assigns.

### 1. JVMTI environments

A JVMTI environment (`JvmtiEnvBase`) is the object the VM creates for each agent on a
`GetEnv(JVMTI_VERSION)` call. It stores everything the agent asked the machine for. **When the
agent detaches, the object is not deleted**: HotSpot only changes the magic number from
`0x71EE` (active) to `0xDEFC` (disposed via `DisposeEnvironment`).

| Check | What is searched for | Severity |
|---|---|---|
| **VM environment list** (walk of `JvmtiEnvBase::_head_environment` via live VMStructs) | all environments, including disposed ones; magic number and state | CRITICAL |
| **Environments outside the list** | environment objects found in memory but unlinked from the VM list | CRITICAL |
| **`ClassFileLoadHook` subscription** | the agent receives the bytecode of every loaded class and can rewrite it | CRITICAL |
| **Event callbacks leading nowhere** | event handlers lead to memory outside loaded modules: the agent library is unloaded, but the environment remembers its addresses | CRITICAL |
| **Agent capabilities** (`jvmtiCapabilities`) | 45 named capabilities the agent requested: `can_redefine_classes`, `can_retransform_classes`, `can_generate_breakpoint_events`, `can_tag_objects`… They stay recorded forever | part of the finding |
| **Object tag map** | the agent tagged heap objects; the classes of tagged objects are recovered | CRITICAL |
| **Native method prefixes** (`SetNativeMethodPrefix`) | strings set by the agent author | CRITICAL |
| **Agent's own data** (`_env_local_storage`) | a pointer to the agent structure, its dump and strings | CRITICAL |
| **Static `JvmtiExport` flags** | `_can_hotswap_or_post_breakpoint`, `_can_access_local_variables`, `_can_post_on_exceptions`, `_can_walk_any_space`. The VM sets them when an agent requests the corresponding capabilities | CRITICAL |
| **JVMTI breakpoints** | a non-zero `InstanceKlass::_breakpoints` or a method breakpoint counter. Only `SetBreakpoint` fills them | CRITICAL |
| **`JvmtiAgentThread`, `JvmtiBreakpoint` objects** | search by the exact vtable address from `jvm.dll` exports | CRITICAL |
| **Independent magic number search** | environments are searched by `0x71EE/0xDEFC/0xDEAD` with structural verification (JVMTI version, `_next`, 37 callback slots, tag map back reference). Wiping the vtable pointer does not help | CRITICAL |
| **Structures holding an environment** | who stores a `jvmtiEnv` pointer: `JPLISAgent` (the native part of `java.lang.instrument`) or the native agent's own structures | HIGH / CRITICAL |
| **`jvmtiInterface_1_` / `JNINativeInterface_` tables** | function table slots in `jvm.dll` redirected outside it (hook) | CRITICAL |
| **`JavaVM` table** (`JNIInvokeInterface_`) | `AttachCurrentThread`/`GetEnv` redirected outside `jvm.dll` | CRITICAL |

An environment whose handlers all lead into `jvm.dll` itself is considered internal (this is
how Flight Recorder creates its environment) and is not reported as a foreign agent.

### 2. Java agents and the attach mechanism

| Check | What is searched for | Severity |
|---|---|---|
| **HotSpot agent list** (`JvmtiAgentList` in JDK 21, `AgentLibrary` in JDK 8–17) | An agent record is not deleted even after `Agent_OnUnload`. It yields the name, options (for a Java agent — the path to its jar), library path, library handle (whether it is unloaded) and JPLIS pointer. On JDK 21+ the «attached to a running VM» flag is read too | CRITICAL (attach or unknown agent), HIGH (known agent at startup) |
| **Attach mechanism objects** (`AttachOperation`, `Win32AttachOperation`, `JVMTIAgentLoadDCmd`) | an object with a **filled** command name (`load`, `jcmd`, `setflag`…): external commands came to the running VM | CRITICAL |
| **VM flags: `ATTACH_ON_DEMAND` origin** | a flag changed through attach on the running VM. The origin bits live in `jvm.dll` static data and cannot be erased | CRITICAL |
| **VM flags: `MANAGEMENT` origin** | a setting changed from inside the process via `HotSpotDiagnosticMXBean`. The game does not do this | HIGH |
| **Agent arguments in the VM copy** | `-javaagent`, `-agentlib`, `-agentpath`, `-Xbootclasspath` in the VM's own argument copy (`Arguments::_jvm_args_array`) | CRITICAL |
| **Reconciliation of three command line copies** | the VM copy, the process parameter block (PEB), the hsperfdata counters. An argument in the VM but not in the PEB came from `JAVA_TOOL_OPTIONS` or the PEB was cleaned. A flag marked as set on the command line but missing from the argument copy was written bypassing argument parsing | HIGH / CRITICAL |
| **Attach-related flags** | `EnableDynamicAgentLoading`, `DisableAttachMechanism`, `StartAttachListener`, `AllowRedefinitionToAddDeleteMethods`, `UnlockDiagnosticVMOptions` and others set explicitly | MEDIUM / HIGH |
| **Environment variables** | `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`. With an agent flag — CRITICAL; non-empty without an agent — MEDIUM (TLauncher sets an empty `_JAVA_OPTIONS=`, which is INFO) | CRITICAL / MEDIUM |
| **Agent modules** | loaded `instrument.dll`, `jdwp.dll` (CRITICAL), `attach.dll` (HIGH); any module exporting `Agent_OnLoad` / `Agent_OnAttach` / `Agent_OnUnload` (CRITICAL) | CRITICAL / HIGH |
| **Agent threads** | `JVMTI Agent Thread` (CRITICAL), `JDWP…` and `Java Debug…` (HIGH). The `Attach Listener` thread is always created on Windows and is not evidence | CRITICAL / HIGH |
| **`InstrumentationImpl` object** | live or in the heap dead zone. **A clean Fabric client has none at all.** The native agent address, negotiated capabilities and both transformer lists are read | CRITICAL |
| **`ClassFileTransformer` objects** | all objects of classes implementing a transformer, even those removed with `removeTransformer`, marked with whether the class is in the game archives | CRITICAL |
| **Agent mechanism classes** | `sun/instrument/*`, `java/lang/instrument/*` loaded (the VM loads them only when an agent attaches and never unloads them) | HIGH |
| **Agent class bytecode in memory** | `sun/instrument/InstrumentationImpl`, `java/lang/instrument/*`, `sun/tools/attach/*`, `com/sun/tools/attach/VirtualMachine` (CRITICAL), `jdk/internal/agent/` (MEDIUM) | CRITICAL / MEDIUM |
| **Agent in hsperfdata counters** | an agent flag in `java.rt.vmArgs` / `sun.rt.javaCommand`: what the VM recorded about itself at startup, independent of the PEB | CRITICAL |
| **hsperfdata area not found** | disabled with `-XX:-UsePerfData` / `-XX:+PerfDisableSharedMem` so that the launch cannot be verified | HIGH (MEDIUM if the flag is visible) |

### 3. VM black box and class redefinition

HotSpot writes ring event logs for the crash report (`Events::log`). They survive the agent
detaching and its classes being unloaded.

| Check | What is searched for | Severity |
|---|---|---|
| **`Classes redefined` log** | any entry: names of redefined classes and the time of redefinition. Written only by `RedefineClasses` / `RetransformClasses` | CRITICAL |
| **Native library unloading** (`Unloaded dll`) | the Minecraft client never unloads its libraries | CRITICAL |
| **Libraries from the log missing from the process** | the VM remembers the load, but the module is gone | CRITICAL |
| **Late-loaded libraries** | loaded much later than the others | HIGH |
| **Classes from the load/unload logs missing from the game archives** | | HIGH / CRITICAL |
| **Empty logs after more than a minute of running** | the content was wiped: the VM itself never resets the entry counter | CRITICAL |
| **`-XX:-LogEvents` / reduced `LogEventsBufferEntries`** | the flight recorder was switched off deliberately | HIGH |
| **Agent operations in the `VM Operations` ring** | `RedefineClasses`, `ChangeBreakpoints`, `GetOrSetLocal`, `HeapWalkOperation`, `GetAllStackTraces`, `ForceEarlyReturn`… The game never calls them | HIGH |
| **Redefinition flags on methods** | `IS_OLD`, `IS_OBSOLETE`, `IS_DELETED`, `IS_PREFIXED_NATIVE` on `Method` objects. Set only by `RedefineClasses`, `RetransformClasses` and `SetNativeMethodPrefix` | CRITICAL |
| **Orphaned metadata** | `Klass`/`Method`/`ConstantPool` objects unreachable from the loader graph, with meaningful (non-runtime) names: residues of old versions of redefined classes | MEDIUM |
| **Redefinition counter in the class mirror** (`Class.classRedefinedCount`) | an exact per-class count of redefinitions for the whole process lifetime, including classes the 20-entry log has already pushed out | CRITICAL |
| **Several bytecode copies of one class** | a trace of transformation (original and modified bytes) | INFO |
| **Reconciliation of four sources** (log, method flags, invalid compiled code, mirror counters) | mismatches: flags present but the log empty (the log was wiped); log present but no flags; dead code in the code cache without flush entries. Also contiguous bands of invalid code by compile number (a whole class knocked out) and dense deoptimization bursts | CRITICAL / HIGH / MEDIUM |

### 4. Java environment

| Check | What is searched for | Severity |
|---|---|---|
| **`jdk.attach.allowAttachSelf=true`** | the process is allowed to attach to itself through the attach mechanism: this is how code already running inside the game injects an agent without an external loader | CRITICAL |
| **`System.props` versus the `VM.savedProps` snapshot** | properties added by already running code; rewritten key properties (`java.class.path`, `java.library.path`, `sun.boot.library.path`, `java.home`, `java.system.class.loader`…); properties removed with `System.clearProperty` | HIGH / MEDIUM |
| **Opened `java.base` packages** | `--add-opens` or `Modules.addOpens` at runtime. The opens map is never cleared; a clean client has zero `java.base` opens | HIGH |
| **Native libraries as seen by Java** (`NativeLibraries`) | a library listed as loaded by Java but whose module is not in the process (unloaded); a library loaded by a class that is in no game archive | HIGH / CRITICAL |
| **Classes in privileged loaders** | a non-JDK class in the bootstrap or platform loader. This is how `-Xbootclasspath/a`, `Instrumentation.appendToBootstrapClassLoaderSearch` and JNI `DefineClass` with a null loader work | CRITICAL |
| **A loader that is itself a hidden class** | code loaded by a loader whose name cannot be found | CRITICAL |
| **Extra null loader** | more than one `ClassLoaderData` without a loader object and without the hidden class flag | HIGH |

### 5. Signatures in memory

A full scan of the entire process memory in one pass. The string set covers only the JVMTI,
`java.lang.instrument` and attach mechanisms. Each string is searched only where a clean VM
cannot have it (for example, only in private executable memory: `jvm.dll` and `lib/modules`
always contain these strings).

| String | Where it is searched | Severity |
|---|---|---|
| `Agent_OnAttach`, `Agent_OnUnload` | private executable | HIGH |
| JVMTI function names: `RetransformClasses`, `RedefineClasses`, `GetLoadedClasses`, `SetEventNotificationMode`, `AddCapabilities`, `IterateOverInstancesOfClass`, `GetObjectsWithTags`, `FollowReferences`, `DisposeEnvironment` | private executable | HIGH |
| `SetJNIFunctionTable`, `GetJNIFunctionTable` | private executable | CRITICAL |
| `JNI_GetCreatedJavaVMs`, `AttachCurrentThread` | private executable | HIGH |
| `\\.\pipe\javatool` (Dynamic Attach pipe) | private | CRITICAL |
| `JPLISAgent`, `loadAgentLibrary`, `loadClassAndCallPremain`, `loadClassAndCallAgentmain` | private | HIGH |
| `appendToSystemClassLoaderSearch`, `appendToBootstrapClassLoaderSearch` | private | CRITICAL |
| `net/bytebuddy/agent`, `net/bytebuddy/` | private | HIGH |
| `javassist/`, `redefineModule` | private | MEDIUM |
| `sun/instrument/InstrumentationImpl`, `TransformerManager`, `addTransformer`, `retransformClasses`, `defineAnonymousClass` | private | LOW: single occurrences also happen in a clean VM, only the structural check is conclusive |

The set can be extended with a `signatures.json` file next to the exe (an array of
`{name, category, text, severity, scope, utf16, wholeWord, note}` objects).

---

## How it works

1. **Basics.** Memory map, modules, threads, JNI/JVMTI tables in `jvm.dll` data.
2. **Live VMStructs.** `gHotSpotVMStructs` is read from the `jvm.dll` exports: the table of
   real field offsets of this HotSpot build. It is used to walk the class loader graph, the
   JVMTI environment list, the VM flag table and the argument copy. Offsets are not hardcoded,
   so the scanner is portable across JDK releases.
3. **Full memory scan.** One pass over all readable memory. It finds signatures, Java class
   files, metaspace objects by exact vtable addresses, VM event log objects and references to
   the JNI/JVMTI tables.
4. **Java heap.** Objects are read by platform field names: `InstrumentationImpl`,
   transformers, properties, modules, native libraries, class mirrors. The heap dead zone,
   i.e. the remains of collected objects, is read too.
5. **Service steps** (module list, thread names, code cache blocks) collect only what the
   checks above need.

The scanner **only reads** process memory: it does not attach agents, does not perform an
attach, does not write into the process and does not stop game threads.

---

## Limitations

- **Windows x64 and HotSpot only** (Oracle/OpenJDK/Temurin etc.). OpenJ9 is not supported.
- **The «attached to a running VM» flag in the agent record** is read only on JDK 21+. The
  `AgentLibrary` record in JDK 8–17 has no such field; there the attach method is determined
  from other traces: arguments, attach objects, VM flags.
- **A zero background proves nothing.** A careful author will bypass any single sign. The
  strength is in the set of independent records of one fact: forging all of them consistently
  at once (agent list, environment, flags, log, mirror counters) is much harder.
- **A native cheat without JVMTI and without attach** (direct memory reads and writes) leaves
  almost none of the traces AgentScan looks for.
- **Run time** grows with the heap size: the full scan and the metaspace walk read all process
  memory.
- The scanner checks the process at the moment it runs. VM event logs are rings: the oldest
  entries are pushed out by new ones.

---

## Positive test

`tests/positive/` contains a target and a test Java agent: a transformer plus
`retransformClasses`. `run-test.cmd` starts three JVMs: without an agent, with `-javaagent`
and with an agent attached through `VirtualMachine.loadAgent`. Then it runs AgentScan on each.
JDK 21 is required.

```bat
tests\positive\run-test.cmd
```

Result on JDK 21.0 (Windows 10):

| Process | CRITICAL | HIGH | MEDIUM | Code | Key findings |
|---|---|---|---|---|---|
| no agent | 0 | 0 | 0 | 0 | — |
| `-javaagent` | 25 | 8 | 2 | 10 | agent record «instrument» with the jar path and the «at startup» flag, two JVMTI environments, `ClassFileLoadHook`, `InstrumentationImpl` and a transformer in the heap, the agent flag in the VM argument copy and in hsperfdata |
| attach | 27–29 | 8 | 2 | 10 | agent record with the «to a running VM» flag, `Win32AttachOperation` with the `load` command, an entry in the `Classes redefined` log, the `RedefineClasses` operation in the VM Operations ring, the redefinition counter in the mirror of the `Target` class |

The same on a real game: Minecraft 1.21.10 (TLauncher, Fabric Loader 0.19.3, JDK 21), working
set 1.4 GB.

| Process | CRITICAL | HIGH | MEDIUM | LOW | Time | Code |
|---|---|---|---|---|---|---|
| clean game | 0 | 0 | 0 | 3 | 67 s | 0 |
| the same game after attaching the test agent | 26 | 7 | 2 | 6 | 77 s | 10 |

The three LOW findings of the clean game are normal: single `InstrumentationImpl` strings (the
`java.instrument` module descriptor that the VM parses at startup) and «28 VM arguments are
missing from the process command line»: TLauncher passes them in an `@args` file.

---

## Building

.NET SDK 8.0 is required (on the build machine only).

```bat
build.cmd
```

Two variants of the same scanner are built:

| File | Size | What the checked machine needs |
|---|---|---|
| `dist\AgentScan.exe` | ~70 MB | nothing: the .NET 8 runtime and WinForms are embedded (self-contained) |
| `dist\AgentScan-lite.exe` | ~1 MB | [.NET 8 Desktop Runtime x64](https://dotnet.microsoft.com/download/dotnet/8.0) |

If `AgentScan-lite.exe` finds no .NET, the .NET loader shows the «You must install or update
.NET to run this application» window. The «Download it now» button leads to the Microsoft
site (`aka.ms/dotnet-core-applaunch`). Install the **.NET Desktop Runtime 8 (x64)**: it already
includes the base .NET Runtime. If only the base runtime is installed, the next launch will ask
for the Desktop Runtime as well.

Manually:

```bat
dotnet publish src -c Release -o out-full
dotnet publish src -c Release -o out-lite -p:SelfContained=false -p:EnableCompressionInSingleFile=false -p:PublishReadyToRun=false
```

ReadyToRun is disabled for the lite variant on purpose. In the «single file + no runtime»
combination an exe with ReadyToRun crashed at startup inside `coreclr.dll` (`0xC0000602`,
verified on .NET 8.0.27). This affects only the startup time, not the scanner itself.

Layout:

```
AgentScan/
  README.md            this description (English)
  README.es.md         this description (Spanish)
  build.cmd            build: full dist\AgentScan.exe and lite dist\AgentScan-lite.exe
  src/
    Program.cs         argument parsing, console mode, scan run and report writing
    Gui/MainForm.cs    window: process list, progress bar, report buttons
    Analysis/          checks and the pipeline (Scanner.cs)
    Core/              process reading, memory map, VMStructs, Java heap, jar index
    Native/            ntdll/kernel32 calls
    Report/            console, HTML (EN/ES), TXT, JSON
  tests/positive/      target and test agent
```
