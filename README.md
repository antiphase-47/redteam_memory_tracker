# Red Team Memory Tracker

A real-time memory behavior analysis tool for security research and red team exercises on Windows x64.

## Overview

The Red Team Memory Tracker instruments memory allocations and runs periodic security checks against the current process. It records every allocation/free with detailed metadata, and scans for common offensive techniques: syscall hooking, ROP gadget chains, ret2libc vectors, RWX memory regions, and high-entropy (potentially encrypted) content.

## Features

1. **Allocation Tracking** - Records every tracked allocation and free with address, size, permissions, entropy, call-stack hash, and lifetime.
2. **Syscall Hook Detection** - Checks the first 5 bytes of critical `ntdll.dll` syscalls for inline hooks (`JMP 0xE9`).
3. **ROP Gadget Scanning** - Scans tracked memory blocks against a database of known gadget byte patterns.
4. **ret2libc Analysis** - Enumerates addresses of dangerous functions (`WinExec`, `CreateProcessA/W`, `LoadLibraryA/W`, `system`).
5. **RWX Warnings** - Flags `PAGE_EXECUTE_READWRITE` regions, the classic signature of injected shellcode.
6. **Entropy Calculation** - Computes Shannon entropy of block content to detect encrypted or obfuscated payloads.
7. **Background Scanning** - A worker thread runs a full scan at startup and then every 30 seconds.

## Compilation

```bash
# Windows x64 (MinGW-w64)
gcc red_team_memory_tracker.c -o tracker.exe -lpsapi -Wall -O2

# Windows x64 cross-compile from Linux
x86_64-w64-mingw32-gcc red_team_memory_tracker.c -o tracker.exe -lpsapi -Wall -O2
```

> Note: MSVC-only SEH (`__try`/`__except`) is wrapped in `SEH_TRY`/`SEH_EXCEPT` macros. Under MSVC the code uses real exception handling; under GCC the exception branches compile as dead code.

## Usage

Run the executable. It will:

1. Initialize the ROP gadget database.
2. Start the background scanner (first scan after 1 second).
3. Create test allocations (normal, high-entropy, and RWX blocks containing gadgets).
4. Wait for Enter, then stop the scanner and release resources.

```
Press Enter to stop tracking and exit...
```

Events are printed to the console with color coding and appended to `red_team_memory_tracker.log`.

## Event Types

| Tag | Type | Meaning |
|-----|------|---------|
| `[ALLOC]` | `ETYPE_ALLOC` | Memory allocation recorded |
| `[FREE]` | `ETYPE_FREE` | Memory freed (with lifetime) |
| `[HOOK]` | `ETYPE_HOOK_DETECT` | Syscall hook scan result |
| `[ROP]` | `ETYPE_ROP_DETECT` | ROP gadget found in tracked memory |
| `[RET2LIBC]` | `ETYPE_RET2LIBC` | Dangerous function address listed |
| `[RWX]` | `ETYPE_RWX_ALERT` | Read-write-execute memory detected |
| `[HIGH_ENTROPY]` | `ETYPE_HIGH_ENTROPY` | Content entropy above threshold |

Console colors: red for hook/ROP/ret2libc/RWX alerts, yellow for high entropy, white for normal events. The log file stores plain text without color codes.

## Data Structures

### BlockRecord

| Field | Type | Description |
|-------|------|-------------|
| `ptr` | `void*` | Block start address |
| `size` | `size_t` | Block size in bytes |
| `permissions` | `DWORD` | Memory protection flags (`VirtualQuery`) |
| `call_stack_hash` | `DWORD64` | FNV-1a fingerprint of the allocation call stack |
| `entropy` | `double` | Shannon entropy of the first 4 KB (0-8) |
| `alloc_time` | `time_t` | Allocation timestamp |
| `is_suspicious` | `BOOL` | Set when RWX, high entropy, or gadgets are found |
| `tag` | `char[64]` | Comma-separated tags, e.g. `RWX,ROP(2)` |

### RopGadget

| Field | Type | Description |
|-------|------|-------------|
| `pattern` | `BYTE[16]` | Machine-code byte sequence |
| `pattern_len` | `size_t` | Number of valid bytes |
| `description` | `char[128]` | Human-readable gadget name |

## ROP Gadget Database

| Gadget | Bytes | Purpose |
|--------|-------|---------|
| `pop rax; ret` | `58 C3` | Load value into rax |
| `pop rbx; ret` | `5B C3` | Load value into rbx |
| `pop rcx; ret` | `59 C3` | First argument (Windows x64) |
| `pop rdx; ret` | `5A C3` | Second argument (Windows x64) |
| `pop rdi; ret` | `5F C3` | First argument (System V) |
| `pop rsi; ret` | `5E C3` | Second argument (System V) |
| `xchg rax, rsp; ret` | `48 94 C3` | Stack pivot (bypass DEP/ASLR) |
| `syscall; ret` | `0F 05 C3` | Direct system call |

## Detection Details

### Syscall Hook Detection

Normal ntdll stubs begin with `4C 8B D1 B8 ...` (`mov r10, rcx; mov eax, syscall_number`). An inline hook replaces the first 5 bytes with `E9 xx xx xx xx` (relative JMP). The scanner reads the first 5 bytes of:

- `NtAllocateVirtualMemory`
- `NtProtectVirtualMemory`
- `NtCreateThreadEx`
- `NtWriteVirtualMemory`
- `NtReadVirtualMemory`

If a JMP is found, the hook target address is computed (`func + 5 + offset`) and the first 16 bytes are dumped.

### Entropy Analysis

Shannon entropy is computed over the byte-frequency distribution:

```
H = -Σ p(i) * log2(p(i))
```

- 0 = fully repetitive content
- ~4 = ordinary text or code
- 8 = fully random (strong encryption)

Blocks with entropy above `ENTROPY_THRESHOLD` (7.5) are tagged `HIGH_ENTROPY`.

### Stack Hash

The call stack is captured with `CaptureStackBackTrace` and hashed with FNV-1a (64-bit). Identical allocation paths produce identical hashes, providing a fingerprint of the code path that requested the memory.

### RWX Detection

`VirtualQuery` protection flags are checked for `PAGE_EXECUTE_READWRITE`. RWX memory is the typical signature of shellcode injection and triggers an immediate alert.

## Configuration Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_BLOCKS` | 10000 | Maximum tracked blocks |
| `MAX_STACK_DEPTH` | 32 | Max call-stack frames captured |
| `SCAN_INTERVAL_SEC` | 30 | Background scan interval |
| `RECORD_DURATION_SEC` | 3 | Recording window before each periodic scan |
| `ROP_GADGET_MAX` | 1024 | Gadget database capacity |
| `ENTROPY_THRESHOLD` | 7.5 | High-entropy alert threshold |

## Program Flow

1. Set console code page to UTF-8 (`SetConsoleOutputCP`).
2. Initialize the critical section.
3. Open `red_team_memory_tracker.log`.
4. Load ROP gadget signatures.
5. Start the background scanner thread.
6. Create test allocations:
   - 1 KB filled with `0x41` (low entropy, normal permissions)
   - 2 KB of random bytes (high entropy simulation)
   - 4 KB `PAGE_EXECUTE_READWRITE` region containing gadget bytes
7. Wait for Enter.
8. Stop the scanner, release RWX regions, close the log.

## Log Format

```
2026-10-02 04:12:40 [ALLOC] Allocated memory @ 0x000001, size: 1024 bytes, perms: 0x4, entropy: 0.00, stack hash: 0x2DCEB1CD9384BBE9
2026-10-02 04:12:40 [RWX] Warning: RWX memory allocated @ 0x000002, size: 4096 bytes
2026-10-02 04:12:40 [ROP] ROP gadget found: pop rax; ret @ 0x000003
```

## Project Layout

```
red_team_memory_tracker.c      Windows x64 source (this document)
red_team_memory_tracker_linux.c  Linux x64 port (/proc/self/maps, pthread, dlsym)
```

Linux build:

```bash
gcc red_team_memory_tracker_linux.c -o memory_tracker_linux -Wall -O2 -lm -lpthread -ldl
```

## Disclaimer

For authorized security research and red team exercises only. The tool inspects and reports on its own process memory; it does not attack other systems.
