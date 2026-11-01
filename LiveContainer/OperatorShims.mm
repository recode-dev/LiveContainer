//
//  OperatorShims.mm
//  LiveContainer
//
//  Fix: guest apps that export *strong* C++ operator new/delete (games with
//  custom allocators, e.g. Black Russia / blackrussia-client.framework) hijack
//  dyld's weak-def coalescing. System dylibs from the shared cache (most notably
//  /usr/lib/libprotobuf.dylib) import the C++ operators as weak lookups; dyld
//  coalesces them to ANY strong definition found in the loaded images
//  ("non-weak wins over previous weak-def", dyld4 Loader.cpp). When such a
//  strong definition comes from the guest, system libraries start allocating
//  with one allocator and freeing with another, which aborts at launch with:
//      malloc: *** error for object ...: pointer being freed was not allocated
//      → SIGABRT inside protobuf_AddDesc_... (libprotobuf initializer)
//
//  This file defines a strong, malloc/free-based operator family in the *main
//  executable*. The main executable is always the FIRST entry of dyld's
//  coalescing scan list (state.loaded) and cannot be hidden from flat lookups,
//  so it always wins coalescing against any guest framework. Result: every
//  weak operator lookup from system libraries resolves to a consistent
//  malloc/free pair, while guest apps keep using their own custom allocators
//  through direct (strong, self) bindings — nobody is broken.
//
//  Follow-up crash (2nd bug, Black Russia + injected tweak dylibs):
//  guest *tweak* dylibs (Documents/Tweaks/*.dylib, loaded by TweakLoader)
//  import operator new/delete as WEAK symbols. With the shims above in place
//  those weak imports bind to the shim pair (plain malloc/free, no headers),
//  while the guest engine's own operators are its custom header-based pair
//  (blackrussia-client: 16-byte header, delete == free(*(p-0x10)), mode is
//  picked by a __builtin_available check). A buffer created on the tweak side
//  and destroyed by the engine then goes through the engine's header-aware
//  delete with a non-header pointer → free(garbage) →
//  "pointer being freed was not allocated" → SIGABRT in the engine's
//  MainThread (SetGetSerializedSettingsCallback settings pipeline).
//
//  Mitigation: interpose free() from the main executable with a guard that
//  silently ignores frees of pointers which are NOT the start of a live
//  malloc allocation (exactly the condition libmalloc aborts on). Valid frees
//  are forwarded unchanged, so behavior is identical except that allocator
//  mismatches turn into a small leak instead of a crash.
//

#include <cstdlib>
#include <malloc/malloc.h>
#include <new>
#include <stddef.h>

// dyld only scans images whose Mach-O header has MH_WEAK_DEFINES set when it
// looks for coalescing candidates. A plain ObjC app binary has no weak defs,
// so provide one to make sure our exports are considered.
__attribute__((used, visibility("default"))) __attribute__((weak))
int __lc_operator_shim_weak_anchor = 0;

static inline void* lc_alloc(std::size_t size) {
    if (size == 0) size = 1;
    for (;;) {
        void* p = malloc(size);
        if (p) return p;
        std::new_handler h = std::get_new_handler();
        if (!h) throw std::bad_alloc();
        h();
    }
}

static inline void* lc_alloc_aligned(std::size_t size, std::size_t alignment) {
    if (size == 0) size = 1;
    if (alignment < sizeof(void*)) alignment = sizeof(void*);
    for (;;) {
        void* p = nullptr;
        if (posix_memalign(&p, alignment, size) == 0) return p;
        std::new_handler h = std::get_new_handler();
        if (!h) throw std::bad_alloc();
        h();
    }
}

static inline void* lc_alloc_nothrow(std::size_t size) noexcept {
    if (size == 0) size = 1;
    return malloc(size);
}

static inline void* lc_alloc_aligned_nothrow(std::size_t size, std::size_t alignment) noexcept {
    if (size == 0) size = 1;
    if (alignment < sizeof(void*)) alignment = sizeof(void*);
    void* p = nullptr;
    if (posix_memalign(&p, alignment, size) != 0) return nullptr;
    return p;
}

#define LC_SHIM_EXPORT __attribute__((used, visibility("default")))

// free() with an allocator-mismatch guard: ignores pointers that are not the
// start of a live malloc allocation (wild pointers AND interior pointers).
// malloc_size()/malloc_zone_from_ptr()/malloc_zone_free() are pure libmalloc
// queries/entries that are NOT interposed here, so there is no recursion and
// no lazy-initialization reentry risk.
static inline void lc_free_guarded(void* p) {
    if (!p) return;
    if (malloc_size(p) == 0) return; // not a live allocation start: ignore
    malloc_zone_t* zone = malloc_zone_from_ptr(p);
    malloc_zone_free(zone ? zone : malloc_default_zone(), p);
}

// Interposed free(): identical to free() except that pointers which are not
// the start of a live malloc allocation are silently ignored (leak) instead
// of aborting with "pointer being freed was not allocated".
static void lc_interposed_free(void* p) { lc_free_guarded(p); }

struct lc_interpose_pair { const void* replacement; const void* replacee; };
__attribute__((used)) static const struct lc_interpose_pair lc_free_interposer
    __attribute__((section("__DATA,__interpose"), used)) = {
        (const void*)&lc_interposed_free,
        (const void*)&free,
    };

// --- operator new (throwing) ---
LC_SHIM_EXPORT void* operator new(std::size_t size) { return lc_alloc(size); }
LC_SHIM_EXPORT void* operator new[](std::size_t size) { return lc_alloc(size); }
LC_SHIM_EXPORT void* operator new(std::size_t size, const std::nothrow_t&) noexcept { return lc_alloc_nothrow(size); }
LC_SHIM_EXPORT void* operator new[](std::size_t size, const std::nothrow_t&) noexcept { return lc_alloc_nothrow(size); }
LC_SHIM_EXPORT void* operator new(std::size_t size, std::align_val_t al) { return lc_alloc_aligned(size, (std::size_t)al); }
LC_SHIM_EXPORT void* operator new[](std::size_t size, std::align_val_t al) { return lc_alloc_aligned(size, (std::size_t)al); }
LC_SHIM_EXPORT void* operator new(std::size_t size, std::align_val_t al, const std::nothrow_t&) noexcept { return lc_alloc_aligned_nothrow(size, (std::size_t)al); }
LC_SHIM_EXPORT void* operator new[](std::size_t size, std::align_val_t al, const std::nothrow_t&) noexcept { return lc_alloc_aligned_nothrow(size, (std::size_t)al); }

// --- operator delete ---
LC_SHIM_EXPORT void operator delete(void* p) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete[](void* p) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::size_t) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::size_t) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete(void* p, const std::nothrow_t&) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete[](void* p, const std::nothrow_t&) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::align_val_t) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::align_val_t) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::size_t, std::align_val_t) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { lc_free_guarded(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { lc_free_guarded(p); }