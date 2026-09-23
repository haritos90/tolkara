#include "DebuggerArena.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned asked;
// Attached and staying: the launch has no way in.
static bool holds_on(void) { asked++; return true; }
// Attached, then gone once asked.
static bool lets_go(void) { return asked++ == 0; }

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
    assert(!da_entry_allowed(&arena, NULL));

    // What the external path falls back to.
    void *mapped = mmap(NULL, page, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    void *runs = mapped == MAP_FAILED ? (void *)(uintptr_t)&main : mapped;
    NativeCodeMemory fallback = {.executable = runs, .size = page, .published = true};
    void *writable = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(writable != MAP_FAILED);
    NativeCodeMemory unexecutable = {.executable = writable, .size = page, .published = true};
    assert(da_entry_allowed(&fallback, NULL));
    assert(!da_entry_allowed(&unexecutable, NULL));

    // A refused request, with a debugger that holds on.
    asked = 0; da_attachment_probe(holds_on);
    NativeCodeMemory refused = {0};
    assert(!da_request_arena(&refused, page, NULL));
    assert(!da_entry_allowed(&fallback, NULL));
    assert(asked >= 2);   // asked to let go, then asked again
    assert(!da_release_debugger(&unexecutable, NULL));

    // One that lets go: the mapping decides on its own.
    asked = 0; da_attachment_probe(lets_go);
    assert(da_entry_allowed(&fallback, NULL));
    assert(asked == 2);
    da_attachment_probe(NULL);
    assert(munmap(writable, page) == 0);
    if (mapped != MAP_FAILED) assert(munmap(mapped, page) == 0);

    puts("PASS: debugger region validation, refused request with nothing attached (no breakpoint executed),"
         " no entry while a debugger holds on");
}
