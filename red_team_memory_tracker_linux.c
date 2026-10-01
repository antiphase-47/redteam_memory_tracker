#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MAX_BLOCKS 10000
#define MAX_STACK_DEPTH 32
#define SCAN_INTERVAL_SEC 30
#define RECORD_DURATION_SEC 3
#define ROP_GADGET_MAX 1024
#define ENTROPY_THRESHOLD 7.5

#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40

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
    unsigned int permissions;
    unsigned long long call_stack_hash;
    double entropy;
    time_t alloc_time;
    int is_suspicious;
    char tag[64];
} BlockRecord;

typedef struct RopGadget {
    void* address;
    unsigned char pattern[16];
    size_t pattern_len;
    char description[128];
} RopGadget;

static BlockRecord g_blocks[MAX_BLOCKS];
static int g_block_count = 0;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_scan_thread;
static int g_scan_thread_valid = 0;
static atomic_int g_running = 1;
static int g_first_scan_done = 0;
static FILE* g_log_file = NULL;
static RopGadget g_rop_gadgets[ROP_GADGET_MAX];
static int g_rop_count = 0;

static const char* g_color_red = "\033[91m";
static const char* g_color_yellow = "\033[93m";
static const char* g_color_reset = "\033[0m";

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

    const char* color = "";
    if (event_type == ETYPE_HOOK_DETECT ||
        event_type == ETYPE_ROP_DETECT ||
        event_type == ETYPE_RET2LIBC ||
        event_type == ETYPE_RWX_ALERT) {
        color = g_color_red;
    } else if (event_type == ETYPE_HIGH_ENTROPY) {
        color = g_color_yellow;
    }

    printf("%s%s %s %s%s\n", color, timestamp, event_names[event_type], message, g_color_reset);

    if (g_log_file) {
        fprintf(g_log_file, "%s %s %s\n",
                timestamp, event_names[event_type], message);
        fflush(g_log_file);
    }
}

double calculate_entropy(const unsigned char* data, size_t size) {
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

unsigned long long calculate_stack_hash() {
    void* stack[MAX_STACK_DEPTH];

    int frames = backtrace(stack, MAX_STACK_DEPTH);

    unsigned long long hash = 14695981039346656037ULL;

    for (int i = 1; i < frames; i++) {
        hash ^= (unsigned long long)(uintptr_t)stack[i];
        hash *= 1099511628211ULL;
    }

    return hash;
}

unsigned int get_memory_permissions(void* address) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    unsigned long long addr = (unsigned long long)(uintptr_t)address;
    unsigned int result = 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end;
        char perms[8];

        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) {
            continue;
        }

        if (addr >= start && addr < end) {
            if (perms[0] == 'r') result |= PAGE_READONLY;
            if (perms[1] == 'w') result |= PAGE_READWRITE;
            if (perms[2] == 'x') result |= PAGE_EXECUTE;

            if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                result = PAGE_EXECUTE_READWRITE;
            } else if (perms[0] == 'r' && perms[2] == 'x') {
                result = PAGE_EXECUTE_READ;
            }
            break;
        }
    }

    fclose(fp);
    return result;
}

int is_rwx_memory(unsigned int permissions) {
    return (permissions & PAGE_EXECUTE_READWRITE) != 0;
}

void hex_dump(const unsigned char* data, size_t size, int max_lines) {
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
            unsigned char c = data[i + j];
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

int search_rop_gadgets(const unsigned char* data, size_t size, void* base_addr) {
    int found_count = 0;

    if (size <= 16) return 0;

    for (size_t i = 0; i < size - 16; i++) {
        for (int g = 0; g < g_rop_count; g++) {
            int match = 1;

            for (size_t j = 0; j < g_rop_gadgets[g].pattern_len; j++) {
                if (data[i + j] != g_rop_gadgets[g].pattern[j]) {
                    match = 0;
                    break;
                }
            }

            if (match) {
                void* gadget_addr = (unsigned char*)base_addr + i;

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
    const char* syscalls[] = {
        "mmap",
        "mprotect",
        "open",
        "read",
        "write",
        "execve"
    };

    log_event(ETYPE_HOOK_DETECT, "Starting syscall hook scan...");

    for (int i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
        void* func_addr = dlsym(RTLD_DEFAULT, syscalls[i]);
        if (!func_addr) {
            log_event(ETYPE_HOOK_DETECT, "%s: not found", syscalls[i]);
            continue;
        }

        unsigned char first_bytes[16];
        memcpy(first_bytes, func_addr, sizeof(first_bytes));

        if (first_bytes[0] == 0xE9 || first_bytes[0] == 0xCC) {
            unsigned int offset = *(unsigned int*)(first_bytes + 1);
            void* target = (unsigned char*)func_addr + 5 + offset;

            log_event(ETYPE_HOOK_DETECT,
                     "*** HOOK DETECTED: %s @ %p -> %p ***",
                     syscalls[i],
                     func_addr,
                     first_bytes[0] == 0xE9 ? target : NULL);

            printf("  First 16 bytes at address: ");
            for (int j = 0; j < 16; j++) {
                printf("%02X ", first_bytes[j]);
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
    const char* dangerous_funcs[] = {
        "system",
        "execve",
        "execv",
        "popen",
        "mprotect"
    };

    log_event(ETYPE_RET2LIBC, "Checking ret2libc attack vectors...");

    for (int i = 0; i < sizeof(dangerous_funcs) / sizeof(dangerous_funcs[0]); i++) {
        void* func_addr = dlsym(RTLD_DEFAULT, dangerous_funcs[i]);

        if (func_addr) {
            log_event(ETYPE_RET2LIBC,
                     "System function address: %s @ %p",
                     dangerous_funcs[i], func_addr);
        }
    }

    void* system_addr = dlsym(RTLD_DEFAULT, "system");
    if (system_addr) {
        log_event(ETYPE_RET2LIBC,
                 "*** WARNING: system() available @ %p ***",
                 system_addr);
    }
}

void track_allocation(void* ptr, size_t size) {
    if (!ptr || g_block_count >= MAX_BLOCKS) return;

    pthread_mutex_lock(&g_mutex);

    BlockRecord* block = &g_blocks[g_block_count++];

    block->ptr = ptr;
    block->size = size;
    block->permissions = get_memory_permissions(ptr);
    block->call_stack_hash = calculate_stack_hash();
    block->alloc_time = time(NULL);
    block->is_suspicious = 0;
    block->tag[0] = '\0';

    block->entropy = calculate_entropy(
        (unsigned char*)ptr,
        size < 4096 ? size : 4096
    );

    if (is_rwx_memory(block->permissions)) {
        block->is_suspicious = 1;
        strcpy(block->tag, "RWX");

        log_event(ETYPE_RWX_ALERT,
                 "Warning: RWX memory allocated @ %p, size: %zu bytes",
                 ptr, size);
    }

    if (block->entropy > ENTROPY_THRESHOLD) {
        block->is_suspicious = 1;

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

    pthread_mutex_unlock(&g_mutex);
}

void track_free(void* ptr) {
    if (!ptr) return;

    pthread_mutex_lock(&g_mutex);

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

    pthread_mutex_unlock(&g_mutex);
}

void perform_full_scan() {
    log_event(ETYPE_ALLOC, "======================================");
    log_event(ETYPE_ALLOC, "Starting full memory scan");
    log_event(ETYPE_ALLOC, "======================================");

    check_syscall_hooks();
    check_ret2libc();

    pthread_mutex_lock(&g_mutex);

    log_event(ETYPE_ALLOC, "Scanning %d tracked memory blocks...", g_block_count);

    for (int i = 0; i < g_block_count; i++) {
        BlockRecord* block = &g_blocks[i];

        if (block->size > 16) {
            size_t scan_size = block->size < 4096 ? block->size : 4096;

            int gadget_count = search_rop_gadgets(
                (unsigned char*)block->ptr,
                scan_size,
                block->ptr
            );

            if (gadget_count > 0) {
                block->is_suspicious = 1;

                char temp[32];
                snprintf(temp, sizeof(temp), "%sROP(%d)",
                        block->tag[0] ? "," : "",
                        gadget_count);
                strcat(block->tag, temp);
            }
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

                printf("      Perms: 0x%X, Entropy: %.2f, Stack hash: 0x%llX\n",
                       block->permissions,
                       block->entropy,
                       block->call_stack_hash);

                hex_dump((unsigned char*)block->ptr, block->size, 4);

                printf("\n");
            }
        }
    }

    pthread_mutex_unlock(&g_mutex);

    log_event(ETYPE_ALLOC, "======================================");
    log_event(ETYPE_ALLOC, "Scan complete");
    log_event(ETYPE_ALLOC, "======================================");
    log_event(ETYPE_ALLOC, "");
}

void* scan_thread_proc(void* param) {
    (void)param;
    log_event(ETYPE_ALLOC, "Scanner thread started");

    if (!g_first_scan_done) {
        sleep(1);
        perform_full_scan();
        g_first_scan_done = 1;
    }

    while (atomic_load(&g_running)) {
        sleep(SCAN_INTERVAL_SEC);

        if (!atomic_load(&g_running)) break;

        log_event(ETYPE_ALLOC, "[Periodic scan] Starting %d second recording window...", RECORD_DURATION_SEC);

        for (int i = 0; i < RECORD_DURATION_SEC && atomic_load(&g_running); i++) {
            sleep(1);
            log_event(ETYPE_ALLOC, "  Recording... (%d/%d seconds)", i + 1, RECORD_DURATION_SEC);
        }

        if (atomic_load(&g_running)) {
            perform_full_scan();
        }
    }

    log_event(ETYPE_ALLOC, "Scanner thread stopped");
    return NULL;
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
    unsigned char* random_data = (unsigned char*)p2;

    for (int i = 0; i < 2048; i++) {
        random_data[i] = (unsigned char)(rand() & 0xFF);
    }

    void* p3 = mmap(
        NULL,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (p3 != MAP_FAILED) {
        track_allocation(p3, 4096);

        unsigned char* code = (unsigned char*)p3;

        code[0] = 0x58;
        code[1] = 0xC3;

        code[100] = 0x5B;
        code[101] = 0xC3;
    } else {
        log_event(ETYPE_ALLOC, "mmap RWX failed (possibly blocked by W^X policy)");
    }

    log_event(ETYPE_ALLOC, "Test allocations complete");
}

int main() {
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

    int rc = pthread_create(&g_scan_thread, NULL, scan_thread_proc, NULL);
    if (rc != 0) {
        log_event(ETYPE_ALLOC, "Error: failed to create scan thread");
        return 1;
    }
    g_scan_thread_valid = 1;

    create_test_allocations();

    printf("\nPress Enter to stop tracking and exit...\n");
    getchar();

    atomic_store(&g_running, 0);

    if (g_scan_thread_valid) {
        pthread_join(g_scan_thread, NULL);
        g_scan_thread_valid = 0;
    }

    log_event(ETYPE_ALLOC, "Cleaning up resources...");

    pthread_mutex_lock(&g_mutex);

    for (int i = 0; i < g_block_count; i++) {
        if (g_blocks[i].permissions & PAGE_EXECUTE_READWRITE) {
            munmap(g_blocks[i].ptr, g_blocks[i].size);
        }
    }

    pthread_mutex_unlock(&g_mutex);

    pthread_mutex_destroy(&g_mutex);

    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    log_event(ETYPE_ALLOC, "Program exited");

    return 0;
}
