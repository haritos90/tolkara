#include "DebuggerArena.h"
#include "HostDiagnostics.h"
#include <TargetConditionals.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

// The trap means something only on a device.
#if defined(__aarch64__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
#define DA_PROTOCOL 1
#else
#define DA_PROTOCOL 0
#endif

bool da_debugger_present(void) { return hd_may_run_unsigned_code(); }

bool da_plausible_region(const void *address) {
    uintptr_t value = (uintptr_t)address;
    if (!value || value == (uintptr_t)-1) return false;
    // Leftovers of an unserviced breakpoint rather than an address.
    if (value == 0x690000e0ull || value == 0xcccccccc690000e0ull) return false;
    return (value & ((uintptr_t)getpagesize() - 1)) == 0;
}

#if DA_PROTOCOL
// x16 selects the command; naked, the protocol names registers.
__attribute__((noinline, optnone, naked))
static void *jit26_prepare_region(void *address __attribute__((unused)),
                                  size_t length __attribute__((unused))) {
    __asm__ volatile("mov x16, #1\n"
                     "brk #0xf00d\n"
                     "ret\n");
}
__attribute__((noinline, optnone, naked))
static void jit26_detach(void) {
    __asm__ volatile("mov x16, #0\n"
                     "brk #0xf00d\n"
                     "ret\n");
}
#endif

bool da_request_arena(NativeCodeMemory *memory, size_t size, FILE *log) {
#if !DA_PROTOCOL
    (void)memory; (void)size;
    if (log) fprintf(log, "[debugger] the breakpoint protocol exists only on an arm64 device\n");
    return false;
#else
    if (!da_debugger_present()) {
        if (log) fprintf(log, "[debugger] nothing has prepared this process; not trapping\n");
        return false;
    }
    void *executable = NULL;
    for (unsigned attempt = 0; attempt < 3 && !executable; attempt++) {
        if (attempt) usleep(50 * 1000);   // the script can be busy for a moment
        if (log) { fprintf(log, "[debugger] requesting %zu bytes, attempt %u\n", size, attempt + 1); fflush(log); }
        // Null selects the debugger's own allocation; ours stays unexecutable.
        void *candidate = jit26_prepare_region(NULL, size);
        if (da_plausible_region(candidate)) executable = candidate;
        else if (log) fprintf(log, "[debugger] attempt %u answered %p\n", attempt + 1, candidate);
    }
    if (!executable) {
        if (log) fprintf(log, "[debugger] no executable region was provided\n");
        return false;
    }
    // What comes back is execute-only; the writable view is ours.
    if (!nc_adopt(memory, executable, size)) {
        if (log) fprintf(log, "[debugger] cannot alias the region for writing errno=%d\n", errno);
        return false;
    }
    if (log) fprintf(log, "[debugger] arena rx=%p rw=%p size=%zu protection=%#x\n",
                     memory->executable, memory->writable, memory->size,
                     hd_protection(memory->executable));
    return true;
#endif
}

bool da_release_debugger(const NativeCodeMemory *memory, FILE *log) {
#if !DA_PROTOCOL
    (void)memory; (void)log;
    return false;
#else
    if (!memory || !memory->executable) return false;
    if (!da_debugger_present()) return hd_is_executable(memory->executable);
    jit26_detach();
    // Whether execute survives the detach is the device's answer.
    bool executable = hd_is_executable(memory->executable);
    if (log) fprintf(log, "[debugger] asked to detach; the arena %s executable (protection %#x)\n",
                     executable ? "is still" : "is no longer", hd_protection(memory->executable));
    return executable;
#endif
}
