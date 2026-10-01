#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <psapi.h>
#include <stdarg.h>

#define MAX_BLOCKS 10000
#define MAX_STACK_DEPTH 32
#define SCAN_INTERVAL_SEC 30
#define RECORD_DURATION_SEC 3
#define ROP_GADGET_MAX 1024
#define ENTROPY_THRESHOLD 7.5

#ifdef _MSC_VER
#define SEH_TRY __try
#define SEH_EXCEPT __except(EXCEPTION_EXECUTE_HANDLER)
#else
#define SEH_TRY if (1)
#define SEH_EXCEPT else if (0)
#endif

typedef enum {
    ETYPE_ALLOC = 1,
    ETYPE_FREE = 2,
    ETYPE_HOOK_DETECT = 3,
    ETYPE_ROP_DETECT = 4,
    ETYPE_RET2LIBC = 5,
    ETYPE_RWX_ALERT = 6,
    ETYPE_HIGH_ENTROPY = 7
} EventType;

typedef struct BlockRecord {
    void* ptr;
    size_t size;
    DWORD permissions;
    DWORD64 call_stack_hash;
    double entropy;
    time_t alloc_time;
    BOOL is_suspicious;
    char tag[64];
} BlockRecord;

typedef struct RopGadget {
    void* address;
    BYTE pattern[16];
    size_t pattern_len;
    char description[128];
} RopGadget;

static BlockRecord g_blocks[MAX_BLOCKS];
static int g_block_count = 0;
static CRITICAL_SECTION g_cs;
static HANDLE g_scan_thread = NULL;
static BOOL g_running = TRUE;
static BOOL g_first_scan_done = FALSE;
static FILE* g_log_file = NULL;
static RopGadget g_rop_gadgets[ROP_GADGET_MAX];
static int g_rop_count = 0;

void get_timestamp(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", t);
}

void log_event(EventType event_type, const char* format, ...) {
    char timestamp[64];
    char message[1024];

    const char* event_names[] = {
        "",
        "[ALLOC]",
        "[FREE]",
        "[HOOK]",
        "[ROP]",
        "[RET2LIBC]",
        "[RWX]",
        "[HIGH_ENTROPY]"
    };

    get_timestamp(timestamp, sizeof(timestamp));

    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    if (event_type == ETYPE_HOOK_DETECT ||
        event_type == ETYPE_ROP_DETECT ||
        event_type == ETYPE_RET2LIBC ||
        event_type == ETYPE_RWX_ALERT) {
        color = FOREGROUND_RED | FOREGROUND_INTENSITY;
    } else if (event_type == ETYPE_HIGH_ENTROPY) {
        color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    }

    SetConsoleTextAttribute(hConsole, color);
    printf("%s %s %s\n", timestamp, event_names[event_type], message);
    SetConsoleTextAttribute(hConsole,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    if (g_log_file) {
        fprintf(g_log_file, "%s %s %s\n",
                timestamp, event_names[event_type], message);
        fflush(g_log_file);
    }
}

double calculate_entropy(const BYTE* data, size_t size) {
    if (!data || size == 0) return 0.0;

    int frequency[256] = {0};

    for (size_t i = 0; i < size; i++) {
        frequency[data[i]]++;
    }

    double entropy = 0.0;

    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double probability = (double)frequency[i] / size;
            entropy -= probability * log2(probability);
        }
    }

    return entropy;
}

DWORD64 calculate_stack_hash() {
    void* stack[MAX_STACK_DEPTH];

    WORD frames = CaptureStackBackTrace(
        1,
        MAX_STACK_DEPTH,
        stack,
        NULL
    );

    DWORD64 hash = 14695981039346656037ULL;

    for (WORD i = 0; i < frames; i++) {
        hash ^= (DWORD64)stack[i];
        hash *= 1099511628211ULL;
    }

    return hash;
}

DWORD get_memory_permissions(void* address) {
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        return mbi.Protect;
    }

    return 0;
}

BOOL is_rwx_memory(DWORD permissions) {
    return (permissions & PAGE_EXECUTE_READWRITE) != 0;
}

void hex_dump(const BYTE* data, size_t size, int max_lines) {
    if (!data) return;

    int lines = 0;

    for (size_t i = 0; i < size && lines < max_lines; i += 16) {
        printf("  %08zX: ", i);

        for (int j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" | ");

        for (int j = 0; j < 16 && i + j < size; j++) {
            BYTE c = data[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }

        printf("\n");
        lines++;
    }
}

void init_rop_gadgets() {
    g_rop_gadgets[g_rop_count].pattern[0] = 0x58;
    g_rop_gadgets[g_rop_count].pattern[1] = 0xC3;
    g_rop_gadgets[g_rop_count].pattern_len = 2;
    strcpy(g_rop_gadgets[g_rop_count].description, "pop rax; ret");
    g_rop_count++;

    g_rop_gadgets[g_rop_count].pattern[0] = 0x5B;
    g_rop_gadgets[g_rop_count].pattern[1] = 0xC3;
    g_rop_gadgets[g_rop_count].pattern_len = 2;
    strcpy(g_rop_gadgets[g_rop_count].description, "pop rbx; ret");
    g_rop_count++;

    g_rop_gadgets[g_rop_count].pattern[0] = 0x59;
    g_rop_gadgets[g_rop_count].pattern[1] = 0xC3;
    g_rop_gadgets[g_rop_count].pattern_len = 2;
    strcpy(g_rop_gadgets[g_rop_count].description, "pop rcx; ret");
    g_rop_count++;

    g_rop_gadgets[g_rop_count].pattern[0] = 0x5A;
    g_rop_gadgets[g_rop_count].pattern[1] = 0xC3;
    g_rop_gadgets[g_rop_count].pattern_len = 2;
    strcpy(g_rop_gadgets[g_rop_count].description, "pop rdx; ret");
    g_rop_count++;

    g_rop_gadgets[g_rop_count].pattern[0] = 0x5F;
    g_rop_gadgets[g_rop_count].pattern[1] = 0xC3;
    g_rop_gadgets[g_rop_count].pattern_len = 2;
    strcpy(g_rop_gadgets[g_rop_count].description, "pop rdi; ret");
    g_rop_count++;

    g_rop_gadgets[g_rop_count].pattern[0] = 0x5E;
    g_rop_gadgets[g_rop_count].pattern[1] = 0xC3;
    g_rop_gadgets[g_rop_count].pattern_len = 2;
    strcpy(g_rop_gadgets[g_rop_count].description, "pop rsi; ret");
    g_rop_count++;

    g_rop_gadgets[g_rop_count].pattern[0] = 0x48;
    g_rop_gadgets[g_rop_count].pattern[1] = 0x94;
    g_rop_gadgets[g_rop_count].pattern[2] = 0xC3;
    g_rop_gadgets[g_rop_count].pattern_len = 3;
    strcpy(g_rop_gadgets[g_rop_count].description, "xchg rax, rsp; ret");
    g_rop_count++;

    g_rop_gadgets[g_rop_count].pattern[0] = 0x0F;
    g_rop_gadgets[g_rop_count].pattern[1] = 0x05;
    g_rop_gadgets[g_rop_count].pattern[2] = 0xC3;
    g_rop_gadgets[g_rop_count].pattern_len = 3;
    strcpy(g_rop_gadgets[g_rop_count].description, "syscall; ret");
    g_rop_count++;

    log_event(ETYPE_ALLOC, "Loaded %d ROP gadget signatures", g_rop_count);
}

int search_rop_gadgets(const BYTE* data, size_t size, void* base_addr) {
    int found_count = 0;

    if (size <= 16) return 0;

    for (size_t i = 0; i < size - 16; i++) {
        for (int g = 0; g < g_rop_count; g++) {
            BOOL match = TRUE;

            for (size_t j = 0; j < g_rop_gadgets[g].pattern_len; j++) {
                if (data[i + j] != g_rop_gadgets[g].pattern[j]) {
                    match = FALSE;
                    break;
                }
            }

            if (match) {
                void* gadget_addr = (BYTE*)base_addr + i;

                log_event(ETYPE_ROP_DETECT,
                         "ROP gadget found: %s @ %p",
                         g_rop_gadgets[g].description,
                         gadget_addr);

                found_count++;
            }
        }
    }

    return found_count;
}

void check_syscall_hooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!ntdll) {
        log_event(ETYPE_HOOK_DETECT, "Unable to load ntdll.dll");
        return;
    }

    const char* syscalls[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory"
    };

    log_event(ETYPE_HOOK_DETECT, "Starting syscall hook scan...");

    for (int i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
        void* func_addr = GetProcAddress(ntdll, syscalls[i]);
        if (!func_addr) continue;

        BYTE first_bytes[5];
        memcpy(first_bytes, func_addr, 5);

        if (first_bytes[0] == 0xE9) {
            DWORD offset = *(DWORD*)(first_bytes + 1);
            void* target = (BYTE*)func_addr + 5 + offset;

            log_event(ETYPE_HOOK_DETECT,
                     "*** HOOK DETECTED: %s @ %p -> %p ***",
                     syscalls[i],
                     func_addr,
                     target);

            printf("  First 16 bytes at original address: ");
            for (int j = 0; j < 16; j++) {
                printf("%02X ", ((BYTE*)func_addr)[j]);
            }
            printf("\n");
        } else {
            log_event(ETYPE_HOOK_DETECT,
                     "%s: clean (first 5 bytes: %02X %02X %02X %02X %02X)",
                     syscalls[i],
                     first_bytes[0], first_bytes[1], first_bytes[2],
                     first_bytes[3], first_bytes[4]);
        }
    }

    log_event(ETYPE_HOOK_DETECT, "Syscall hook scan complete");
}

void check_ret2libc() {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE msvcrt = GetModuleHandleA("msvcrt.dll");

    if (!kernel32) return;

    const char* dangerous_funcs[] = {
        "WinExec",
        "CreateProcessA",
        "CreateProcessW",
        "LoadLibraryA",
        "LoadLibraryW"
    };

    log_event(ETYPE_RET2LIBC, "Checking ret2libc attack vectors...");

    for (int i = 0; i < sizeof(dangerous_funcs) / sizeof(dangerous_funcs[0]); i++) {
        void* func_addr = GetProcAddress(kernel32, dangerous_funcs[i]);

        if (func_addr) {
            log_event(ETYPE_RET2LIBC,
                     "System function address: %s @ %p",
                     dangerous_funcs[i], func_addr);
        }
    }

    if (msvcrt) {
        void* system_addr = GetProcAddress(msvcrt, "system");

        if (system_addr) {
            log_event(ETYPE_RET2LIBC,
                     "*** WARNING: system() available @ %p ***",
                     system_addr);
        }
    }
}

void track_allocation(void* ptr, size_t size) {
    if (!ptr || g_block_count >= MAX_BLOCKS) return;

    EnterCriticalSection(&g_cs);

    BlockRecord* block = &g_blocks[g_block_count++];

    block->ptr = ptr;
    block->size = size;
    block->permissions = get_memory_permissions(ptr);
    block->call_stack_hash = calculate_stack_hash();
    block->alloc_time = time(NULL);
    block->is_suspicious = FALSE;
    block->tag[0] = '\0';

    SEH_TRY {
        block->entropy = calculate_entropy(
            (BYTE*)ptr,
            min(size, 4096)
        );
    } SEH_EXCEPT {
        block->entropy = 0.0;
    }

    if (is_rwx_memory(block->permissions)) {
        block->is_suspicious = TRUE;
        strcpy(block->tag, "RWX");

        log_event(ETYPE_RWX_ALERT,
                 "Warning: RWX memory allocated @ %p, size: %zu bytes",
                 ptr, size);
    }

    if (block->entropy > ENTROPY_THRESHOLD) {
        block->is_suspicious = TRUE;

        strcat(block->tag, block->tag[0] ? ",HIGH_ENTROPY" : "HIGH_ENTROPY");

        log_event(ETYPE_HIGH_ENTROPY,
                 "Warning: high entropy content @ %p, entropy: %.2f",
                 ptr, block->entropy);
    }

    log_event(ETYPE_ALLOC,
             "Allocated memory @ %p, size: %zu bytes, perms: 0x%X, entropy: %.2f, stack hash: 0x%llX",
             ptr,
             size,
             block->permissions,
             block->entropy,
             block->call_stack_hash);

    LeaveCriticalSection(&g_cs);
}

void track_free(void* ptr) {
    if (!ptr) return;

    EnterCriticalSection(&g_cs);

    for (int i = 0; i < g_block_count; i++) {
        if (g_blocks[i].ptr == ptr) {
            time_t lifetime = time(NULL) - g_blocks[i].alloc_time;

            log_event(ETYPE_FREE,
                     "Freed memory @ %p, lifetime: %lld seconds",
                     ptr, (long long)lifetime);

            if (i < g_block_count - 1) {
                g_blocks[i] = g_blocks[g_block_count - 1];
            }
            g_block_count--;

            break;
        }
    }

    LeaveCriticalSection(&g_cs);
}

void perform_full_scan() {
    log_event(ETYPE_ALLOC, "======================================");
    log_event(ETYPE_ALLOC, "Starting full memory scan");
    log_event(ETYPE_ALLOC, "======================================");

    check_syscall_hooks();
    check_ret2libc();

    EnterCriticalSection(&g_cs);

    log_event(ETYPE_ALLOC, "Scanning %d tracked memory blocks...", g_block_count);

    for (int i = 0; i < g_block_count; i++) {
        BlockRecord* block = &g_blocks[i];

        SEH_TRY {
            if (block->size > 16) {
                int gadget_count = search_rop_gadgets(
                    (BYTE*)block->ptr,
                    min(block->size, 4096),
                    block->ptr
                );

                if (gadget_count > 0) {
                    block->is_suspicious = TRUE;

                    char temp[32];
                    snprintf(temp, sizeof(temp), "%sROP(%d)",
                            block->tag[0] ? "," : "",
                            gadget_count);
                    strcat(block->tag, temp);
                }
            }
        } SEH_EXCEPT {
            log_event(ETYPE_ALLOC, "Unable to read memory @ %p", block->ptr);
        }
    }

    int suspicious_count = 0;
    for (int i = 0; i < g_block_count; i++) {
        if (g_blocks[i].is_suspicious) {
            suspicious_count++;
        }
    }

    if (suspicious_count > 0) {
        log_event(ETYPE_ALLOC, "");
        log_event(ETYPE_ALLOC, "*** %d suspicious memory blocks found ***", suspicious_count);
        log_event(ETYPE_ALLOC, "");

        for (int i = 0; i < g_block_count; i++) {
            if (g_blocks[i].is_suspicious) {
                BlockRecord* block = &g_blocks[i];

                printf("  [%d] Address: %p, Size: %zu, Tags: %s\n",
                       i + 1,
                       block->ptr,
                       block->size,
                       block->tag);

                printf("      Perms: 0x%lX, Entropy: %.2f, Stack hash: 0x%llX\n",
                       (unsigned long)block->permissions,
                       block->entropy,
                       block->call_stack_hash);

                SEH_TRY {
                    hex_dump((BYTE*)block->ptr, block->size, 4);
                } SEH_EXCEPT {
                    printf("      (unable to read memory contents)\n");
                }

                printf("\n");
            }
        }
    }

    LeaveCriticalSection(&g_cs);

    log_event(ETYPE_ALLOC, "======================================");
    log_event(ETYPE_ALLOC, "Scan complete");
    log_event(ETYPE_ALLOC, "======================================");
    log_event(ETYPE_ALLOC, "");
}

DWORD WINAPI scan_thread_proc(LPVOID param) {
    log_event(ETYPE_ALLOC, "Scanner thread started");

    if (!g_first_scan_done) {
        Sleep(1000);
        perform_full_scan();
        g_first_scan_done = TRUE;
    }

    while (g_running) {
        Sleep(SCAN_INTERVAL_SEC * 1000);

        if (!g_running) break;

        log_event(ETYPE_ALLOC, "[Periodic scan] Starting %d second recording window...", RECORD_DURATION_SEC);

        for (int i = 0; i < RECORD_DURATION_SEC && g_running; i++) {
            Sleep(1000);
            log_event(ETYPE_ALLOC, "  Recording... (%d/%d seconds)", i + 1, RECORD_DURATION_SEC);
        }

        if (g_running) {
            perform_full_scan();
        }
    }

    log_event(ETYPE_ALLOC, "Scanner thread stopped");
    return 0;
}

void* tmalloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr) {
        track_allocation(ptr, size);
    }
    return ptr;
}

void tfree(void* ptr) {
    track_free(ptr);
    free(ptr);
}

void create_test_allocations() {
    log_event(ETYPE_ALLOC, "Creating test memory allocations...");

    void* p1 = tmalloc(1024);
    memset(p1, 0x41, 1024);

    void* p2 = tmalloc(2048);
    BYTE* random_data = (BYTE*)p2;

    for (int i = 0; i < 2048; i++) {
        random_data[i] = (BYTE)(rand() & 0xFF);
    }

    void* p3 = VirtualAlloc(
        NULL,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (p3) {
        track_allocation(p3, 4096);

        BYTE* code = (BYTE*)p3;

        code[0] = 0x58;
        code[1] = 0xC3;

        code[100] = 0x5B;
        code[101] = 0xC3;
    }

    log_event(ETYPE_ALLOC, "Test allocations complete");
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    InitializeCriticalSection(&g_cs);

    g_log_file = fopen("red_team_memory_tracker.log", "w");

    if (g_log_file) {
        fprintf(g_log_file, "Red Team Memory Tracker - Log File\n");
        fprintf(g_log_file, "======================================\n\n");
    }

    printf("\n");
    printf("+======================================================+\n");
    printf("|       Red Team Memory Tracker v1.0                   |\n");
    printf("|       For security research and red team exercises    |\n");
    printf("+======================================================+\n");
    printf("\n");

    log_event(ETYPE_ALLOC, "Initializing system...");

    init_rop_gadgets();

    g_scan_thread = CreateThread(
        NULL,
        0,
        scan_thread_proc,
        NULL,
        0,
        NULL
    );

    if (!g_scan_thread) {
        log_event(ETYPE_ALLOC, "Error: failed to create scan thread");
        return 1;
    }

    create_test_allocations();

    printf("\nPress Enter to stop tracking and exit...\n");
    getchar();

    g_running = FALSE;

    if (g_scan_thread) {
        WaitForSingleObject(g_scan_thread, 5000);
        CloseHandle(g_scan_thread);
    }

    log_event(ETYPE_ALLOC, "Cleaning up resources...");

    EnterCriticalSection(&g_cs);

    for (int i = 0; i < g_block_count; i++) {
        if (g_blocks[i].permissions & PAGE_EXECUTE_READWRITE) {
            VirtualFree(
                g_blocks[i].ptr,
                0,
                MEM_RELEASE
            );
        }
    }

    LeaveCriticalSection(&g_cs);

    DeleteCriticalSection(&g_cs);

    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    log_event(ETYPE_ALLOC, "Program exited");

    return 0;
}
