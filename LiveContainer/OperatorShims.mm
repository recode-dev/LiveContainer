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

#include <cstdlib>
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
LC_SHIM_EXPORT void operator delete(void* p) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete[](void* p) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::size_t) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::size_t) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete(void* p, const std::nothrow_t&) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete[](void* p, const std::nothrow_t&) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::align_val_t) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::align_val_t) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::size_t, std::align_val_t) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { free(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { free(p); }