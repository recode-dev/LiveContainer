//
//  OperatorShims.mm
//  LiveContainer
//
//  Fix #1 (launch crash): guest apps that export *strong* C++ operator
//  new/delete (games with custom allocators, e.g. Black Russia /
//  blackrussia-client.framework) hijack dyld's weak-def coalescing. System
//  dylibs from the shared cache (most notably /usr/lib/libprotobuf.dylib)
//  import the C++ operators as weak lookups; dyld coalesces them to ANY strong
//  definition found in the loaded images ("non-weak wins over previous
//  weak-def", dyld4 Loader.cpp). When such a strong definition comes from the
//  guest, system libraries start allocating with one allocator and freeing
//  with another, which aborts at launch with:
//      malloc: *** error for object ...: pointer being freed was not allocated
//      → SIGABRT inside protobuf_AddDesc_... (libprotobuf initializer)
//  Mitigation: a strong malloc/free-based operator family in the *main
//  executable*. The main executable is always the FIRST entry of dyld's
//  coalescing scan list, so every weak operator lookup from system libraries
//  (and from tweak dylibs) resolves to this pair. operator_shims.exp +
//  -Wl,-exported_symbols_list keep the definitions alive and exported.
//
//  WHY THE SHIM ALLOCATIONS MUST BE PLAIN MALLOC (crash #4): the shim's weak
//  clients include guest frameworks whose std::string buffers end up freed by
//  the out-of-line std::string code INSIDE the shared-cache libc++.1.dylib.
//  libc++'s operator delete is a *strong two-level bind prebound inside the
//  shared cache* (libc++ → libc++abi) — it cannot be coalesced, interposed or
//  redirected, and it requires p to be a plain malloc block start. Any
//  interior-pointer format (e.g. the guest engine's 16-byte header layout)
//  aborts there with "pointer being freed was not allocated" — observed in
//  std::string::__grow_by_and_replace ← UpdateManagerSystemCallbacks::Configure.
//  So the format that EVERY unhookable deallocator accepts is plain malloc.
//
//  Crash #2/#3 (engine's own header allocator): blackrussia-client on iOS>=17
//  allocates with a 16-byte self-pointer header (new: malloc(size+0x10),
//  *(void**)base = base, return base+0x10; delete: free(*(void**)(p-0x10))).
//  A pointer allocated by plain malloc has no header, so the engine reads
//  garbage from *(p-0x10) and free()s it. That free goes through the engine's
//  GOT slot for `free` — TweakLoader installs a guarded `free` /
//  `malloc_zone_free` into every guest image's GOT (fishhook, see
//  TweakLoader.m), which turns that mismatch into a small leak instead of an
//  abort. The __interpose entry below is the equivalent backstop for images
//  that are present at launch.
//

#include <cstdlib>
#include <malloc/malloc.h>
#include <new>
#include <stddef.h>
#include <stdint.h>

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

static inline void* lc_alloc_nothrow(std::size_t size) noexcept {
    if (size == 0) size = 1;
    return malloc(size);
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

// The universal shim delete: frees pointers produced by this shim (plain
// malloc), pointers produced by a guest's header-based allocator (interior
// pointer with a self-pointer header), and plain foreign pointers; swallows
// everything else (leak instead of abort).
static inline void lc_shim_delete(void* p) noexcept {
    if (!p) return;
    // 1) p is the start of a live malloc block (plain pointer, or a header
    //    allocator's base handed back directly).
    if (malloc_size(p) != 0) {
        malloc_zone_t* zone = malloc_zone_from_ptr(p);
        malloc_zone_free(zone ? zone : malloc_default_zone(), p);
        return;
    }
    // 2) header-format pointer: base = *(p - 0x10). Only free it when the
    //    block start exists AND carries the self-pointer signature
    //    (*(base) == base) used by guest header allocators.
    if ((uintptr_t)p > 0x10) {
        void* base = *(void**)((char*)p - 0x10);
        if (base && malloc_size(base) != 0 && *(void**)base == base) {
            malloc_zone_t* zone = malloc_zone_from_ptr(base);
            malloc_zone_free(zone ? zone : malloc_default_zone(), base);
            return;
        }
    }
    // 3) unknown pointer: ignore (small leak instead of process death).
}

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
LC_SHIM_EXPORT void operator delete(void* p) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete[](void* p) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::size_t) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::size_t) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete(void* p, const std::nothrow_t&) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete[](void* p, const std::nothrow_t&) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::align_val_t) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::align_val_t) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::size_t, std::align_val_t) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { lc_shim_delete(p); }
LC_SHIM_EXPORT void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { lc_shim_delete(p); }
