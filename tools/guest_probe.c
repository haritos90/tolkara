#include "GuestImage.h"
#include "GuestFixups.h"
#include "GuestLink.h"
#include <string.h>
// Only the application's own libraries answer; the rest is zero.
static struct { size_t answered, missing; } imports;
static bool inspect_import(const char *s, int o, bool w, uint64_t *v, void *c) {
    (void)o; (void)w;
    GuestLinkSet *set = c;
    if (set && gl_export(set, s, v)) { imports.answered++; return true; }
    imports.missing++; *v=0; return true;
}
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: guest_probe <original Mach-O> [--library] [--carried-libraries] [--validate-fixups] [--export symbol ...]\n"); return 2; }
    bool library = false, fixups = false, carried = false;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--library")) library = true;
        else if (!strcmp(argv[i], "--validate-fixups")) fixups = true;
        else if (!strcmp(argv[i], "--carried-libraries")) carried = true;
        else if (!strcmp(argv[i], "--export") && i + 1 < argc) i++;
        else { fprintf(stderr, "invalid probe option\n"); return 2; }
    }
    GuestImage image = {0}; char error[1024];
    bool loaded = library ? gi_load_library(argv[1], &image, error, sizeof error) : gi_load(argv[1], &image, error, sizeof error);
    if (!loaded) { fprintf(stderr, "%s\n", error); return 1; }
    gi_report(&image, stdout);
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--export")) continue;
        const char *symbol = argv[++i]; uint64_t address; bool absolute;
        GIExportResult result = gi_export(&image, symbol, &address, &absolute, error, sizeof error);
        if (result != GI_EXPORT_FOUND) {
            fprintf(stderr, "export %s: %s\n", symbol, result == GI_EXPORT_MISSING ? "not found" : error);
            gi_destroy(&image); return 1;
        }
        printf("[export] %s=%#llx absolute=%d\n", symbol, (unsigned long long)address, absolute);
    }
    GuestLinkSet set = {0};
    if (carried) {
        if (!gl_load(&set, &image, argv[1], error, sizeof error)) {
            fprintf(stderr, "%s\n", error); gi_destroy(&image); return 1;
        }
        gl_report(&set, stdout);
    }
    if (fixups) {
        GFStats stats;
        // Carried libraries bind first: a miss here is real.
        for (size_t i = 0; i < set.count; i++) {
            if (!gf_apply(&set.libraries[i].image, 0x200000, inspect_import, &set, &stats, error, sizeof error)) {
                fprintf(stderr, "%s: %s\n", set.libraries[i].install_name, error);
                gl_destroy(&set); gi_destroy(&image); return 1;
            }
            printf("[fixups] %s rebases=%zu binds=%zu\n", set.libraries[i].install_name, stats.rebases, stats.binds);
        }
        if (!gf_apply(&image, 0x200000, inspect_import, &set, &stats, error, sizeof error)) {
            fprintf(stderr, "%s\n", error); gl_destroy(&set); gi_destroy(&image); return 1;
        }
        printf("[fixups] validated rebases=%zu binds=%zu (diagnostic addresses only; no execution)\n", stats.rebases, stats.binds);
        printf("[fixups] imports from carried libraries=%zu elsewhere=%zu\n", imports.answered, imports.missing);
    }
    gl_destroy(&set);
    gi_destroy(&image);
    return 0;
}
