#include "DebuggerArena.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    size_t page = (size_t)getpagesize();
    // An unserviced request leaves the breakpoint encoding, not a null.
    assert(!da_plausible_region(NULL));
    assert(!da_plausible_region((const void *)(uintptr_t)-1));
    assert(!da_plausible_region((const void *)(uintptr_t)0x690000e0ull));
    assert(!da_plausible_region((const void *)(uintptr_t)0xcccccccc690000e0ull));
    assert(!da_plausible_region((const void *)(uintptr_t)(page + 8)));
    assert(da_plausible_region((const void *)(uintptr_t)(page * 4)));

    // With nothing attached the protocol must refuse, not trap.
    NativeCodeMemory arena = {0};
    assert(!da_request_arena(&arena, page, NULL));
    assert(!arena.executable && !arena.writable && !arena.published);
    assert(!da_release_debugger(&arena, NULL));

    puts("PASS: debugger region validation, request refused with nothing attached (no breakpoint executed)");
}
