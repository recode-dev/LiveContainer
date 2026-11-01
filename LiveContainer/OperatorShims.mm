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
//  Mitigation: strong malloc/free-based operator family in the *main
//  executable*. The main executable is always the FIRST entry of dyld's
//  coalescing scan list, so every weak operator lookup from system libraries
//  (and from tweak dylibs) resolves to this pair. operator_shims.exp +
//  -Wl,-exported_symbols_list keep the definitions alive and exported.
//
//  Fix #3 (heap crash in guest MainThread / RakNet pipeline, "pointer being
//  freed was not allocated" inside blackrussia-client `operator delete(void*)`
//  at +88): the engine's allocator is FORMAT-INCOMPATIBLE with plain malloc.
//  Disassembly of the on-device build (symtab: __ZdlPv=0xf1060, __Znwm=0xf1200):
//
//    operator new(ulong), mode 0 (iOS >= 17 path, mode byte @0x1b0c599 set by
//    __isPlatformVersionAtLeast(ios 17) → 0 == "modern"):
//        base = malloc(requested + 0x10);
//        base[0xC] = size_class;
//        *(void**)base = base;            // self-pointer header
//        return base + 0x10;
//    operator delete(void*):
//        if (p) { void* base = *(void**)(p - 0x10); free(base); }
//        (free() resolves two-level to libsystem_malloc — main-executable
//        exports/interposing do NOT catch it: __interpose does not reach
//        images dlopen'ed after launch, and two-level binds ignore them too.)
//
//  A pointer allocated by plain malloc (i.e. by a tweak whose weak operator
//  imports bind to this shim) has NO header, so the engine reads *(p-0x10) =
//  heap garbage G and calls free(G) → SIGABRT in libmalloc. This was crash #2
//  (mitigated by the free() interposer below) and crash #3, where even the
//  interposer does not help because it never reaches the guest image.
//
//  Real fix: allocate shim memory in the ENGINE'S OWN FORMAT. Every shim
//  `operator new` returns base+0x10 with *(void**)base == base, so when the
//  engine (or any other header-based allocator) deletes such a pointer it
//  reads a valid base and frees it cleanly — no abort, no leak, regardless of
//  which image crosses the object over. The shim `operator delete` mirror-wise
//  understands both formats:
//      1) p is itself the start of a live malloc block  → free(p)
//         (foreign plain-malloc pointers, engine "mode 1" allocations);
//      2) *(p-0x10) is a live malloc block whose first word points to itself
//         (the engine/shim header signature)            → free(*(p-0x10));
//      3) anything else is silently ignored (leak instead of crash).
//  malloc_size()/malloc_zone_from_ptr()/malloc_zone_free() are pure libmalloc
//  queries/entries that are NOT interposed here, so there is no recursion and
//  no lazy-initialization reentry risk.
//
//  The free() interposer from fix #2 is kept as a backstop for frees that
//  bypass operator delete entirely (it is harmless if dyld ignores it for
//  late-loaded images).
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

// Header size used by the guest engine's custom allocator (see file comment).
static const std::size_t kLcHeaderSize = 0x10;

static inline void* lc_alloc(std::size_t size) {
    if (size == 0) size = 1;
    std::size_t total;
    if (__builtin_add_overflow(size, kLcHeaderSize, &total)) throw std::bad_alloc();
    for (;;) {
        void* base = malloc(total);
        if (base) {
            *(void**)base = base; // engine-compatible self-pointer header
            return (char*)base + kLcHeaderSize;
        }
        std::new_handler h = std::get_new_handler();
        if (!h) throw std::bad_alloc();
        h();
    }
}

static inline void* lc_alloc_nothrow(std::size_t size) noexcept {
    if (size == 0) size = 1;
    std::size_t total;
    if (__builtin_add_overflow(size, kLcHeaderSize, &total)) return nullptr;
    void* base = malloc(total);
    if (!base) return nullptr;
    *(void**)base = base;
    return (char*)base + kLcHeaderSize;
}

// Aligned allocation keeps the same header layout: [base] = base, returned
// pointer = (aligned position inside the block). For alignment > 16 the
// header word lives at returned-0x10 inside the block, and the block start
// still carries the self-pointer so the delete path can recognize it.
static inline void* lc_alloc_aligned(std::size_t size, std::size_t alignment) {
    if (alignment < 16) alignment = 16;
    if (size == 0) size = 1;
    std::size_t total;
    if (__builtin_add_overflow(size, kLcHeaderSize, &total) ||
        __builtin_add_overflow(total, alignment, &total)) throw std::bad_alloc();
    for (;;) {
        void* raw = nullptr;
        if (posix_memalign(&raw, alignment, total) == 0 && raw) {
            char* p = (char*)raw + kLcHeaderSize;
            p = (char*)(((uintptr_t)p + alignment - 1) & ~(uintptr_t)(alignment - 1));
            ((void**)p)[-1] = raw;
            *(void**)raw = raw;
            return p;
        }
        std::new_handler h = std::get_new_handler();
        if (!h) throw std::bad_alloc();
        h();
    }
}

static inline void* lc_alloc_aligned_nothrow(std::size_t size, std::size_t alignment) noexcept {
    if (alignment < 16) alignment = 16;
    if (size == 0) size = 1;
    std::size_t total;
    if (__builtin_add_overflow(size, kLcHeaderSize, &total) ||
        __builtin_add_overflow(total, alignment, &total)) return nullptr;
    void* raw = nullptr;
    if (posix_memalign(&raw, alignment, total) != 0 || !raw) return nullptr;
    char* p = (char*)raw + kLcHeaderSize;
    p = (char*)(((uintptr_t)p + alignment - 1) & ~(uintptr_t)(alignment - 1));
    ((void**)p)[-1] = raw;
    *(void**)raw = raw;
    return p;
}

#define LC_SHIM_EXPORT __attribute__((used, visibility("default")))

// free() with an allocator-mismatch guard: ignores pointers that are not the
// start of a live malloc allocation. Backstop only (see file comment).
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

// The universal shim delete: frees pointers produced by this shim, by the
// guest engine's header allocator, or by plain malloc; swallows everything
// else (leak instead of abort).
static inline void lc_shim_delete(void* p) noexcept {
    if (!p) return;
    // 1) p is the start of a live malloc block (plain foreign pointer, or a
    //    base pointer handed back directly). Header-format pointers are
    //    interior (base+0x10), so malloc_size(p) == 0 for them.
    if (malloc_size(p) != 0) {
        malloc_zone_t* zone = malloc_zone_from_ptr(p);
        malloc_zone_free(zone ? zone : malloc_default_zone(), p);
        return;
    }
    // 2) header-format pointer: base = *(p - 0x10). Only free it when the
    //    block start exists AND carries the self-pointer signature
    //    (*(base) == base) shared by the engine allocator and this shim.
    if ((uintptr_t)p > kLcHeaderSize) {
        void* base = *(void**)((char*)p - kLcHeaderSize);
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
