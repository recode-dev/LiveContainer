#import "FoundationPrivate.h"
#import "LCMachOUtils.h"
#import "LCSharedUtils.h"
#import "UIKitPrivate.h"
#import "utils.h"

#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>

#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <malloc/malloc.h>
#include "../litehook/src/litehook.h"
#import "Tweaks/Tweaks.h"
#include <mach-o/ldsyms.h>

extern char **environ;
static int (*appMain)(int, char**, char**);
NSUserDefaults *lcUserDefaults;
NSUserDefaults *lcSharedDefaults;
NSString *lcAppGroupPath;
NSString* lcAppUrlScheme;
NSBundle* lcMainBundle;
NSDictionary* guestAppInfo;
NSDictionary* guestContainerInfo;
NSString* lcGuestAppId;
NSString* lcLaunchURL;
bool isLiveProcess = false;
bool isSharedBundle = false;
bool isSideStore = false;
bool sideStoreExist = false;

@implementation NSUserDefaults(LiveContainer)
+ (instancetype)lcUserDefaults {
    return lcUserDefaults;
}
+ (instancetype)lcSharedDefaults {
    if(!lcUserDefaults) {
        lcSharedDefaults = [[NSUserDefaults alloc] initWithSuiteName: [LCSharedUtils appGroupID]];
    }
    return lcSharedDefaults;
}
+ (NSString *)lcAppGroupPath {
    return lcAppGroupPath;
}
+ (NSString *)lcAppUrlScheme {
    return lcAppUrlScheme;
}
+ (NSBundle *)lcMainBundle {
    return lcMainBundle;
}
+ (NSDictionary *)guestAppInfo {
    return guestAppInfo;
}

+ (NSDictionary *)guestContainerInfo {
    return guestContainerInfo;
}

+ (bool)isLiveProcess {
    return isLiveProcess;
}
+ (bool)isSharedApp {
    return isSharedBundle;
}
+ (bool)isSideStore {
    return isSideStore;
}
+ (bool)sideStoreExist {
    return sideStoreExist;
}

+ (NSString*)lcGuestAppId {
    return lcGuestAppId;
}
+ (NSString*)lcLaunchURL {
    return lcLaunchURL;
}
@end

static BOOL checkJITEnabled() {
#if TARGET_OS_MACCATALYST || TARGET_OS_SIMULATOR
    return YES;
#else
    if([lcUserDefaults boolForKey:@"LCIgnoreJITOnLaunch"]) {
        return NO;
    }
    // check if jailbroken
    if (access("/usr/lib/systemhook.dylib", R_OK) == 0) {
        return YES;
    }
    
    // check csflags
    int flags;
    csops(getpid(), 0, &flags, sizeof(flags));
    return (flags & CS_DEBUGGED) != 0;
#endif
}

static uint64_t rnd64(uint64_t v, uint64_t r) {
    r--;
    return (v + r) & ~r;
}

void overwriteMainCFBundle(void) {
    // Overwrite CFBundleGetMainBundle
    uint32_t *pc = (uint32_t *)CFBundleGetMainBundle;
    void **mainBundleAddr = 0;
    
#if !TARGET_OS_SIMULATOR
    if(@available(iOS 27.0, *)) {
        // at least in iOS 27.0 db1, the logic is inversed and the __mainBundle is right after the first tbz instruction
        while (true) {
            bool isTbz = ((*pc) & 0x7F000000) == 0x36000000;
            if (isTbz) {
                // adrp <- pc-1
                // tbz <- pc
                // ldr  <- addr
                mainBundleAddr = (void **)aarch64_emulate_adrp_ldr(*(pc-1), *(uint32_t *)(pc+1), (uint64_t)(pc-1));
                break;
            }
            ++pc;
        }
    } else {
#endif
        while (true) {
            uint64_t addr = aarch64_get_tbnz_jump_address(*pc, (uint64_t)pc);
            if (addr) {
                // adrp <- pc-1
                // tbnz <- pc
                // ...
                // ldr  <- addr
                mainBundleAddr = (void **)aarch64_emulate_adrp_ldr(*(pc-1), *(uint32_t *)addr, (uint64_t)(pc-1));
                break;
            }
            ++pc;
        }
#if !TARGET_OS_SIMULATOR
    }
#endif
    assert(mainBundleAddr != NULL);
    *mainBundleAddr = (__bridge void *)NSBundle.mainBundle._cfBundle;
}

void overwriteMainNSBundle(NSBundle *newBundle) {
    // Overwrite NSBundle.mainBundle
    // iOS 16: x19 is _MergedGlobals
    // iOS 17: x19 is _MergedGlobals+4

    NSString *oldPath = NSBundle.mainBundle.executablePath;
    uint32_t *mainBundleImpl = (uint32_t *)method_getImplementation(class_getClassMethod(NSBundle.class, @selector(mainBundle)));
    for (int i = 0; i < 20; i++) {
        void **_MergedGlobals = (void **)aarch64_emulate_adrp_add(mainBundleImpl[i], mainBundleImpl[i+1], (uint64_t)&mainBundleImpl[i]);
        if (!_MergedGlobals) continue;

        // In iOS 17, adrp+add gives _MergedGlobals+4, so it uses ldur instruction instead of ldr
        if ((mainBundleImpl[i+4] & 0xFF000000) == 0xF8000000) {
            uint64_t ptr = (uint64_t)_MergedGlobals - 4;
            _MergedGlobals = (void **)ptr;
        }

        for (int mgIdx = 0; mgIdx < 20; mgIdx++) {
            if (_MergedGlobals[mgIdx] == (__bridge void *)NSBundle.mainBundle) {
                _MergedGlobals[mgIdx] = (__bridge void *)newBundle;
                break;
            }
        }
    }

    assert(![NSBundle.mainBundle.executablePath isEqualToString:oldPath]);
}

typedef struct {
    void *gap_0x0[2];                  // 0x00, 0x08
    char *mainExecutablePath_old;      // 0x10
    void *gap_0x18;                    // 0x18
    char *mainExecutablePath_18_4;     // 0x20
    size_t mainExecutablePathLen_27_0; // 0x28
} DyldConfig;
typedef struct {
    void *gap_0x0;
    DyldConfig *dyldConfig;
} DyldAPI;

int hook__NSGetExecutablePath_overwriteExecPath(DyldAPI* dyldApiInstancePtr, char* newPath, uint32_t* bufsize) {
    assert(dyldApiInstancePtr != 0);
    DyldConfig* dyldConfig = dyldApiInstancePtr->dyldConfig;
    assert(dyldConfig != 0);
    
    char** mainExecutablePathPtr = 0;
    // mainExecutablePath is at 0x10 for iOS 15~18.3.2, 0x20 for iOS 18.4+
    if(dyldConfig->mainExecutablePath_old != 0 && dyldConfig->mainExecutablePath_old[0] == '/') {
        mainExecutablePathPtr = &(dyldConfig->mainExecutablePath_old);
    } else if (dyldConfig->mainExecutablePath_18_4 != 0 && dyldConfig->mainExecutablePath_18_4[0] == '/') {
        mainExecutablePathPtr = &(dyldConfig->mainExecutablePath_18_4);
    } else {
        assert(mainExecutablePathPtr != 0);
    }

    kern_return_t ret = builtin_vm_protect(mach_task_self(), (mach_vm_address_t)dyldConfig, sizeof(dyldConfig), false, PROT_READ | PROT_WRITE);
    if(ret != KERN_SUCCESS) {
        assert(os_tpro_is_supported());
        os_thread_self_restrict_tpro_to_rw();
    }
    *mainExecutablePathPtr = newPath;
    
    // in iOS 27, the length is also cached, it's at +0x28
    if(@available(iOS 27.0, *)) {
        dyldConfig->mainExecutablePathLen_27_0 = strlen(newPath);
    }
    
    if(ret != KERN_SUCCESS) {
        os_thread_self_restrict_tpro_to_ro();
    }

    return 0;
}

void overwriteExecPath(const char *newExecPath) {
    // dyld4 stores executable path in a different place (iOS 15.0 +)
    // https://github.com/apple-oss-distributions/dyld/blob/ce1cc2088ef390df1c48a1648075bbd51c5bbc6a/dyld/DyldAPIs.cpp#L802
    int (*orig__NSGetExecutablePath)(void* dyldPtr, char* buf, uint32_t* bufsize);
    performHookDyldApi("_NSGetExecutablePath", 2, (void**)&orig__NSGetExecutablePath, hook__NSGetExecutablePath_overwriteExecPath);
    _NSGetExecutablePath((char*)newExecPath, NULL);
    // put the original function back
    performHookDyldApi("_NSGetExecutablePath", 2, (void**)&orig__NSGetExecutablePath, orig__NSGetExecutablePath);
}

static void *getAppEntryPoint(void *handle) {
    uint32_t entryoff = 0;
    const struct mach_header_64 *header = (struct mach_header_64 *)getGuestAppHeader();
    uint8_t *imageHeaderPtr = (uint8_t*)header + sizeof(struct mach_header_64);
    struct load_command *command = (struct load_command *)imageHeaderPtr;
    for(int i = 0; i < header->ncmds; ++i) {
        if(command->cmd == LC_MAIN) {
            struct entry_point_command ucmd = *(struct entry_point_command *)imageHeaderPtr;
            entryoff = ucmd.entryoff;
            break;
        }
        imageHeaderPtr += command->cmdsize;
        command = (struct load_command *)imageHeaderPtr;
    }
    assert(entryoff > 0);
    return (void *)header + entryoff;
}

// --- Guest allocator-mode guard (crashes #2-#6, Black Russia) ---------------
//
// Crash #6 (build 8af6ca3) proved that the availability_version_check rebind
// added to TweakLoader can never work, for two independent reasons:
//
// 1. TIMING: TweakLoader is injected as the guest executable's LAST
//    LC_LOAD_DYLIB, so its constructor runs after every guest initializer.
//    The engine's allocator mode is decided lazily at the first allocation,
//    which happens inside guest static initializers - before TweakLoader
//    even gets a chance to register its rebind.
//
// 2. EMPTY INDIRECT SYMBOL TABLE: modern chained-fixups guest binaries have
//    dysymtab->nindirectsyms == 0 (verified for blackrussia-client:
//    indirectsymoff=0x0, nindirectsyms=0), so the vendored fishhook returns
//    immediately and rebinds NOTHING, silently.
//
// Fix, installed here in LiveContainerShared BEFORE the guest dlopen:
//   - dyld fires add-image handlers for a dlopen'ed image after its fixups
//     and before any of its initializers, giving us a pre-init window;
//   - instead of symbol tables, GOT slots are matched by their RESOLVED
//     value: at add-image time every non-lazy GOT slot already holds the
//     final address, which equals dlsym(symbol), regardless of chained
//     fixups;
//   - availability_version_check in guest images is redirected to a stub
//     returning 0 ("requirement not met"). On a normal install the guest IS
//     the main executable, so a request beyond its own SDK legitimately
//     fails; under LiveContainer the answer would be based on LiveContainer's
//     fresh SDK instead. Returning 0 puts guests on their legacy,
//     battle-tested code paths - for Black Russia's engine that is the plain
//     malloc/free allocator (mode 1) instead of the 16-byte-header pool
//     (mode 0) whose buffers abort when shared-cache libc++ std::string code
//     frees them ("pointer being freed was not allocated");
//   - additionally the engine's allocator mode byte is forced directly, so the
//     fix does not depend on the availability path at all. The two globals are
//     discovered from the engine's own operator new/delete (see the pin block
//     below), not from a UUID or fixed offsets;
//   - the inline availability path (__isPlatformVersionAtLeast) is redirected
//     only for images that carry no Swift metadata: a Swift guest must keep
//     truthful answers, a C/C++ engine is the one that needs the legacy mode.

static int LCLegacyAvailabilityCheck(uint32_t count, void *versions) {
    return 0;
}

static void LCGuardedFreeEarly(void *p) {
    if (!p) return;
    if (malloc_size(p) == 0) return; // not a live allocation start: leak instead of abort
    malloc_zone_t *zone = malloc_zone_from_ptr(p);
    malloc_zone_free(zone ? zone : malloc_default_zone(), p);
}

static void LCGuardedZoneFreeEarly(malloc_zone_t *zone, void *p) {
    if (!p) return;
    if (malloc_size(p) == 0) return;
    malloc_zone_free(zone ? zone : malloc_default_zone(), p);
}

// Overwrite every GOT slot of the image whose resolved value equals
// dlsym(symbolName) with replacement. Needs no symbol tables, therefore
// works for chained-fixups binaries where fishhook's classic pass no-ops.
void LCOverwriteGotSlotsInImage(const struct mach_header *mh, intptr_t slide,
                                const char *symbolName, void *replacement) {
    if (mh->magic != MH_MAGIC_64) return;
    void *target = dlsym(RTLD_DEFAULT, symbolName);
    if (!target) return;
    const uint8_t *cursor = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            const struct section_64 *sections = (const struct section_64 *)(cursor + sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < seg->nsects; s++) {
                const struct section_64 *sect = &sections[s];
                // ptrauth-signed slots never compare equal to a plain address,
                // and writing a raw pointer into one traps on the next
                // authenticated branch: leave them alone.
                if (strncmp(sect->sectname, "__auth", 6) == 0) continue;
                uint8_t type = sect->flags & SECTION_TYPE;
                // Match by section type as before, and also by name: some
                // linkers file bindings in a __got whose section type is not
                // one of the symbol-pointer kinds, and a missed section means a
                // silent no-op rebind.
                bool isGot = (type == S_NON_LAZY_SYMBOL_POINTERS ||
                              type == S_LAZY_SYMBOL_POINTERS ||
                              strncmp(sect->sectname, "__got", 5) == 0 ||
                              strncmp(sect->sectname, "__nl_symbol_ptr", 15) == 0 ||
                              strncmp(sect->sectname, "__la_symbol_ptr", 15) == 0);
                if (!isGot) continue;
                if (sect->size == 0 || sect->size > 0x100000) continue;
                void **slots = (void **)(uintptr_t)(sect->addr + slide);
                kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)(uintptr_t)slots,
                                              (vm_size_t)sect->size, 0,
                                              VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                if (kr != KERN_SUCCESS) continue;
                for (uintptr_t k = 0; k < sect->size / sizeof(void *); k++) {
                    if (slots[k] == target) {
                        slots[k] = replacement;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }
}

// --- Allocator-mode pin, discovered instead of hardcoded -------------------
//
// An engine that decides its allocator at first use picks a 16-byte-header
// pool when it believes it is on a new OS. Buffers from that pool are then
// freed by shared-cache libc++ and abort with "pointer being freed was not
// allocated". Setting the engine's own "allocator mode" byte to 1 (plain
// malloc/free) and pre-marking its lazy-init guard before any initializer runs
// makes it behave exactly like on a stock install, which is the fix.
//
// This used to be pinned to one build: LC_UUID == 855846c3 plus two hardcoded
// offsets (0x1B0C5D8 / 0x1B0C599, functions at 0xF1200 / 0xF1060). Every app
// update changes the UUID and moves everything, so the pin silently stopped
// applying and the crash came back.
//
// The globals are now found from the code that reads them. operator new and
// operator delete of that engine both contain
//
//     ldarb w8, [guard]     ; Itanium __cxa_guard
//     tbz   w8, #0, slow    ; bit0 == 0 -> run the lazy config ctor
//     ldrb  w9, [mode]      ; allocator mode
//     cmp   w9, #1
//     b.ne  pool            ; != 1 -> pool allocator
//
// so __text is walked for that shape, the adrp(+add) behind each load is
// decoded to recover the global it touches, and the pair is only accepted when
// two independent functions agree on the same two globals. Nothing is pinned
// to a manifest, a UUID or an offset.

static inline bool lcIsLdarb(uint32_t insn) {
    return (insn & 0xFFFFFC00) == 0x08DFFC00; // LDARB Wt, [Xn]
}

static inline bool lcIsTbz(uint32_t insn) {
    // TBZ (b5 == 0), i.e. test bit 0..31
    return (insn & 0x7F000000) == 0x36000000 && ((insn >> 24) & 1) == 0;
}

static inline bool lcIsLdrbImm(uint32_t insn) {
    return (insn & 0xFFC00000) == 0x39400000; // LDRB Wt, [Xn, #imm]
}

static inline bool lcIsCmpImm(uint32_t insn, uint32_t imm) {
    // SUBS WZR, Wn, #imm
    return (insn & 0xFFC00000) == 0x71000000 &&
           (insn & 0x1F) == 0x1F &&
           ((insn >> 10) & 0xFFF) == imm;
}

static inline bool lcIsBCond(uint32_t insn) {
    return (insn & 0xFF000010) == 0x54000000;
}

static inline bool lcIsAdrp(uint32_t insn) {
    return (insn & 0x9F000000) == 0x90000000;
}

static inline bool lcIsAddImm(uint32_t insn) {
    return (insn & 0xFF800000) == 0x91000000; // ADD Xd, Xn, #imm{, lsl #12}
}

static inline uint32_t lcInsnRd(uint32_t insn) { return insn & 0x1F; }
static inline uint32_t lcInsnRn(uint32_t insn) { return (insn >> 5) & 0x1F; }

// Recover the global a load instruction touches: find the adrp that formed its
// base register within a short window, add the load's imm12.
static void *lcResolveLoadTarget(const uint32_t *code, uint32_t count, uint32_t idx,
                                 uint64_t codeVA, uint32_t baseReg) {
    if (idx >= count) return NULL;
    // LDARB carries no immediate (bits 21:10 are part of its opcode), only
    // LDRB's imm12 is an offset.
    uint32_t offset = lcIsLdrbImm(code[idx]) ? ((code[idx] >> 10) & 0xFFF) : 0;
    for (uint32_t back = 1; back <= 12 && idx >= back; back++) {
        uint32_t insn = code[idx - back];
        if (!lcIsAdrp(insn) || lcInsnRd(insn) != baseReg) continue;
        uint64_t page = aarch64_emulate_adrp(insn, codeVA + (uint64_t)(idx - back) * 4);
        if (!page) return NULL;
        // optional add between the adrp and the load
        for (uint32_t mid = back - 1; mid >= 1; mid--) {
            uint32_t add = code[idx - mid];
            if (!lcIsAddImm(add)) continue;
            if (lcInsnRd(add) != baseReg || lcInsnRn(add) != baseReg) continue;
            uint64_t imm = (add >> 10) & 0xFFF;
            if ((add >> 22) & 1) imm <<= 12;
            return (void *)(uintptr_t)(page + imm + offset);
        }
        return (void *)(uintptr_t)(page + offset);
    }
    return NULL;
}

static bool lcAddressWritableInImage(const struct mach_header *mh, intptr_t slide, const void *addr) {
    uintptr_t target = (uintptr_t)addr;
    const uint8_t *cursor = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            uintptr_t start = (uintptr_t)(seg->vmaddr + (uint64_t)slide);
            if (target >= start && target < start + (uintptr_t)seg->vmsize) {
                return (seg->initprot & VM_PROT_WRITE) != 0;
            }
        }
        cursor += lc->cmdsize;
    }
    return false;
}

// Looser second pass, used only when the exact shape above is not found: a
// byte load from a global that is still 0 followed by a tbz on bit 0 (the
// Itanium lazy guard), then any byte load from a nearby global that is still 0
// or 1 (the allocator mode), within the next 20 instructions. The compare is
// not required here, because that is the instruction a rebuild is most likely
// to change (cmp #1 vs cbz vs cmp #2). Two independent functions still have to
// agree on the same pair, which is what keeps a lookalike from being patched.
static bool lcFindAllocatorModeGlobalsLoose(const uint32_t *text, uint64_t count, uint64_t textVA,
                                            const struct mach_header *mh, intptr_t slide,
                                            void **guardOut, void **modeOut) {
    void *firstGuard = NULL, *firstMode = NULL;
    for (uint64_t i = 0; i + 24 < count; i++) {
        if (!lcIsLdarb(text[i]) && !lcIsLdrbImm(text[i])) continue;

        uint64_t tbz = 0;
        for (uint64_t k = i + 1; k <= i + 8 && k < count; k++) {
            if (lcIsTbz(text[k])) { tbz = k; break; }
        }
        if (!tbz) continue;

        void *guard = lcResolveLoadTarget(text, (uint32_t)count, (uint32_t)i, textVA, lcInsnRn(text[i]));
        if (!guard) continue;
        if (!lcAddressWritableInImage(mh, slide, guard)) continue;
        if (*(volatile uint64_t *)guard != 0) continue;

        for (uint64_t k = tbz + 1; k <= tbz + 20 && k < count; k++) {
            if (!lcIsLdarb(text[k]) && !lcIsLdrbImm(text[k])) continue;
            void *mode = lcResolveLoadTarget(text, (uint32_t)count, (uint32_t)k, textVA, lcInsnRn(text[k]));
            if (!mode || mode == guard) continue;
            if (!lcAddressWritableInImage(mh, slide, mode)) continue;
            if (*(volatile uint8_t *)mode > 1) continue;

            uintptr_t a = (uintptr_t)guard, b = (uintptr_t)mode;
            uintptr_t delta = a > b ? a - b : b - a;
            if (delta > 0x10000) continue;

            if (!firstGuard) {
                firstGuard = guard;
                firstMode = mode;
            } else if (firstGuard == guard && firstMode == mode) {
                *guardOut = guard;
                *modeOut = mode;
                return true;
            }
            break;
        }
    }
    return false;
}

// Walk __text for the lazy-init + mode-check shape above. Two functions must
// resolve to the same pair of globals before anything is written.
// A launch has a finite budget for this walk: every guest image is scanned,
// and a bundle can hold dozens of frameworks.
static uint64_t gLCAllocatorScanBudget = 0x2000000ULL; // 32 M dwords = 128 MB of code

static bool lcFindAllocatorModeGlobals(const struct mach_header *mh, intptr_t slide,
                                       void **guardOut, void **modeOut,
                                       uint64_t *textSizeOut) {
    const uint32_t *text = NULL;
    uint64_t textVA = 0, textBytes = 0;
    const uint8_t *cursor = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds && !text; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (strcmp(seg->segname, "__TEXT") == 0 || strcmp(seg->segname, "__TEXT_EXEC") == 0) {
                const struct section_64 *sections = (const struct section_64 *)(cursor + sizeof(struct segment_command_64));
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (strcmp(sections[s].sectname, "__text") == 0 && sections[s].size > 0x100) {
                        text = (const uint32_t *)(uintptr_t)(sections[s].addr + (uint64_t)slide);
                        textVA = sections[s].addr + (uint64_t)slide;
                        textBytes = sections[s].size;
                        break;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }
    if (!text || textBytes < 0x100) return false;

    if (textSizeOut) *textSizeOut = textBytes;
    uint64_t count = textBytes / sizeof(uint32_t);
    if (count > 0x1000000) count = 0x1000000; // cap: 64 MB of code per image
    if (count > gLCAllocatorScanBudget) count = gLCAllocatorScanBudget;
    gLCAllocatorScanBudget -= count;

    void *firstGuard = NULL, *firstMode = NULL;
    void *tightGuard = NULL, *tightMode = NULL;
    int seen = 0;
    for (uint64_t i = 0; i + 24 < count; i++) {
        // The guard load is an acquire byte load in the known builds; a rebuild
        // may emit a plain one, so both anchor the search.
        if (!lcIsLdarb(text[i]) && !lcIsLdrbImm(text[i])) continue;

        uint64_t tbz = 0;
        for (uint64_t k = i + 1; k <= i + 4; k++) {
            if (lcIsTbz(text[k])) { tbz = k; break; }
        }
        if (!tbz) continue;

        uint64_t ldrb = 0, cmp = 0, bne = 0;
        for (uint64_t k = tbz + 1; k <= tbz + 16; k++) {
            if (!ldrb && lcIsLdrbImm(text[k])) { ldrb = k; continue; }
            if (ldrb && !cmp && lcIsCmpImm(text[k], 1)) { cmp = k; continue; }
            if (cmp && !bne && lcIsBCond(text[k])) { bne = k; break; }
        }
        if (!ldrb || !cmp || !bne) continue;

        void *guard = lcResolveLoadTarget(text, (uint32_t)count, (uint32_t)i, textVA, lcInsnRn(text[i]));
        void *mode = lcResolveLoadTarget(text, (uint32_t)count, (uint32_t)ldrb, textVA, lcInsnRn(text[ldrb]));
        if (!guard || !mode || guard == mode) continue;

        uintptr_t a = (uintptr_t)guard, b = (uintptr_t)mode;
        uintptr_t delta = a > b ? a - b : b - a;
        if (delta > 0x10000) continue;
        if (!lcAddressWritableInImage(mh, slide, guard)) continue;
        if (!lcAddressWritableInImage(mh, slide, mode)) continue;
        if (*(volatile uint64_t *)guard != 0) continue; // lazy ctor already ran
        if (*(volatile uint8_t *)mode > 1) continue;    // not an allocator mode byte

        if (seen == 0) {
            firstGuard = guard;
            firstMode = mode;
            seen = 1;
        } else if (firstGuard == guard && firstMode == mode) {
            // operator new and operator delete agree: this is the pair.
            *guardOut = guard;
            *modeOut = mode;
            return true;
        }

        // A build where only one function carries the check is still
        // recognisable: guard, test-bit-0, mode, cmp #1, b.ne back to back,
        // with both fields in the same small struct.
        bool tight = (tbz == i + 1) && (ldrb <= tbz + 4) && (cmp == ldrb + 1) && (bne == cmp + 1);
        if (tight && !tightGuard && delta <= 0x200) {
            tightGuard = guard;
            tightMode = mode;
        }
    }

    if (tightGuard && tightMode) {
        *guardOut = tightGuard;
        *modeOut = tightMode;
        return true;
    }
    return lcFindAllocatorModeGlobalsLoose(text, count, textVA, mh, slide, guardOut, modeOut);
}

static void LCForceLegacyAllocatorMode(const struct mach_header *mh, intptr_t slide) {
    if (mh->magic != MH_MAGIC_64) return;

    void *guard = NULL, *mode = NULL;
    uint64_t textSize = 0;
    if (!lcFindAllocatorModeGlobals(mh, slide, &guard, &mode, &textSize)) {
        // Say so for sizeable images only: that is where an engine lives, and
        // a silent miss is exactly what made the previous pin fail quietly.
        if (textSize >= 0x400000) {
            NSLog(@"[LC] allocator scan: no match in a %llu KB __text",
                  (unsigned long long)(textSize / 1024));
        }
        return;
    }

    uintptr_t lo = ((uintptr_t)guard < (uintptr_t)mode ? (uintptr_t)guard : (uintptr_t)mode) & ~(uintptr_t)0xFFF;
    uintptr_t hi = (((uintptr_t)guard > (uintptr_t)mode ? (uintptr_t)guard : (uintptr_t)mode) + 8 + 0xFFF) & ~(uintptr_t)0xFFF;
    if (hi <= lo || hi - lo > 0x10000) return;
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)lo, (vm_size_t)(hi - lo), 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return;

    *(volatile uint64_t *)guard = 1; // __cxa_guard_acquire now returns 0: the lazy ctor never runs
    *(volatile uint8_t *)mode = 1;   // plain malloc/free allocator, identical to stock
    NSLog(@"[LC] guest allocator mode pinned to plain malloc/free (guard %p, mode %p)", guard, mode);
}

// Which images may be told the truth about the OS version, and which may not.
//
// Answers are faked so legacy engines keep their plain malloc/free allocator
// mode. A Swift image must not be lied to: falsified availability sends it down
// branches its own build never exercised, and that is the List<>.init(content:)
// trap reported for the SwiftUI guests. Swift metadata is the dividing line and
// it is visible in the image itself, so nothing is listed by name.
// Guest compatibility mode, chosen in the 5-tap developer section of Settings:
//   0 Auto (default) - decide per image, see LCGuestSpoofAvailableForImage
//   1 New            - truthful answers to every guest image
//   2 Old            - legacy answers to every guest image
static int LCGuestMode(void) {
    static int cached = -1;
    if (cached < 0) {
        cached = (int)[NSUserDefaults.standardUserDefaults integerForKey:@"LCGuestMode"];
        if (cached < 0 || cached > 2) cached = 0;
    }
    return cached;
}

static bool LCImageHasSwiftMetadata(const struct mach_header *mh) {
    const uint8_t *cursor = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            const struct section_64 *sections = (const struct section_64 *)(cursor + sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < seg->nsects; s++) {
                if (strncmp(sections[s].sectname, "__swift5", 8) == 0) {
                    return true;
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return false;
}

// Inline availability checks (the ones compilers emit for #available) go
// through here, not through availability_version_check. Engines that pick their
// allocator from this call see "iOS 16" and keep plain malloc/free, which is the
// mode they use on a stock install; anything older than 17 is answered honestly.
static int LCLegacyPlatformVersionCheck(uint32_t platform, uint32_t major, uint32_t minor, uint32_t subminor) {
    if (major >= 17) {
        return 0;
    }
    typedef int (*real_pvac_t)(uint32_t, uint32_t, uint32_t, uint32_t);
    static real_pvac_t real_pvac = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        real_pvac = (real_pvac_t)dlsym(RTLD_DEFAULT, "__isPlatformVersionAtLeast");
        if (!real_pvac) {
            real_pvac = (real_pvac_t)dlsym(RTLD_DEFAULT, "___isPlatformVersionAtLeast");
        }
    });
    if (real_pvac && real_pvac != (real_pvac_t)LCLegacyPlatformVersionCheck) {
        return real_pvac(platform, major, minor, subminor);
    }
    return 1;
}

// Auto decides per image. An engine's allocator mode only matters for the
// bundled C/C++ framework it lives in, so a .framework image gets the legacy
// answer; a Swift app executable is the one that must not be lied to, because
// falsified availability sends it down branches its build never exercised.
// That is the rule the working build had in practice, without a per-app list.
static bool LCGuestSpoofAvailableForImage(const struct mach_header *mh, const char *path) {
    int mode = LCGuestMode();
    if (mode == 1) return false; // New: truthful for everyone
    if (mode == 2) return true;  // Old: legacy for everyone
    if (path && strstr(path, ".framework/")) return true;
    return !LCImageHasSwiftMetadata(mh);
}

// ---------------------------------------------------------------------------
// C++ allocation operators
//
// Why the engine aborts under LiveContainer but not as a normal app: a guest is
// loaded as a library, after libc++abi is already bound, so the guest's strong
// operator new/delete no longer replace the weak ones process-wide the way a
// main executable's definitions do. The engine allocates with its own pool
// operator new (pointer + 16-byte header) and the shared-cache libc++ frees it
// with plain free() - "pointer being freed was not allocated".
//
// Answering availability checks differently only steers the engine towards its
// plain mode; that worked in the build where the mode byte was pinned, and it is
// why every availability-only attempt still aborted. The structural fix is to
// put the allocations themselves on plain malloc/free, which is what a stock
// install ends up doing: hook the guest's own operator new/delete when it
// defines them. A pair is only hooked when both halves are present, otherwise
// allocation and release would disagree again.
// ---------------------------------------------------------------------------

static void *lcPlainAlloc(size_t n) {
    return malloc(n ? n : 1);
}

static void *lcPlainAllocAligned(size_t n, size_t align) {
    void *p = NULL;
    if (align < sizeof(void *)) align = sizeof(void *);
    if (posix_memalign(&p, align, n ? n : 1) != 0) return NULL;
    return p;
}

static void lcPlainRelease(void *p) {
    free(p);
}

// Mach-O symbol names carry the leading underscore of the C symbol.
static void *lcFindSymbolInImage(const struct mach_header_64 *mh, intptr_t slide, const char *name) {
    const uint8_t *cursor = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SYMTAB) {
            const struct symtab_command *st = (const struct symtab_command *)cursor;
            const struct nlist_64 *syms = (const struct nlist_64 *)((const uint8_t *)mh + st->symoff);
            const char *strs = (const char *)mh + st->stroff;
            for (uint32_t s = 0; s < st->nsyms; s++) {
                if (syms[s].n_un.n_strx == 0) continue;
                if ((syms[s].n_type & N_TYPE) != N_SECT) continue;
                if (syms[s].n_value == 0) continue;
                if (strcmp(strs + syms[s].n_un.n_strx, name) != 0) continue;
                return (void *)(uintptr_t)(syms[s].n_value + (uint64_t)slide);
            }
        }
        cursor += lc->cmdsize;
    }
    return NULL;
}

static void LCHookGuestAllocationOperators(const struct mach_header *mh, intptr_t slide, const char *path) {
    const struct mach_header_64 *mh64 = (const struct mach_header_64 *)mh;
    if (!mh64 || mh64->magic != MH_MAGIC_64) return;

    void *znwm = lcFindSymbolInImage(mh64, slide, "__Znwm");
    void *zdlpv = lcFindSymbolInImage(mh64, slide, "__ZdlPv");
    if (!znwm || !zdlpv) {
        return; // this image does not override the operators: nothing to align
    }

    kern_return_t rcDel = litehook_hook_function(zdlpv, (void *)lcPlainRelease);
    kern_return_t rcNew = litehook_hook_function(znwm, (void *)lcPlainAlloc);
    NSLog(@"[LC] guest allocation operators -> malloc/free (rc %d/%d): %s", (int)rcNew, (int)rcDel, path ? path : "?");

    // Optional siblings, each pair handled on its own.
    struct { const char *newSym; const char *delSym; bool aligned; } pairs[] = {
        { "__Znam", "__ZdaPv", false },
        { "__ZnwmSt11align_val_t", "__ZdlPvSt11align_val_t", true },
        { "__ZnamSt11align_val_t", "__ZdaPvSt11align_val_t", true },
        { "__ZnwmRKSt9nothrow_t", "__ZdlPvRKSt9nothrow_t", false },
    };
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        void *n = lcFindSymbolInImage(mh64, slide, pairs[i].newSym);
        void *d = lcFindSymbolInImage(mh64, slide, pairs[i].delSym);
        if (!n || !d) continue;
        litehook_hook_function(d, (void *)lcPlainRelease);
        litehook_hook_function(n, pairs[i].aligned ? (void *)lcPlainAllocAligned : (void *)lcPlainAlloc);
    }
}

static void LCGuardGuestImageEarly(const struct mach_header *mh, intptr_t slide) {
    Dl_info info;
    if (!dladdr((const void *)mh, &info) || !info.dli_fname) return;
    const char *path = info.dli_fname;
    // Only patch guest app images and tweaks; LC's own images keep real answers.
    if (!strstr(path, "/Documents/Applications/") && !strstr(path, "/Documents/Tweaks/")) return;
    LCOverwriteGotSlotsInImage(mh, slide, "availability_version_check", (void *)LCLegacyAvailabilityCheck);
    if (!LCGuestSpoofAvailableForImage(mh, path)) {
        NSLog(@"[LC] availability left truthful for this image (mode %d): %s", LCGuestMode(), path);
    } else {
        LCOverwriteGotSlotsInImage(mh, slide, "__isPlatformVersionAtLeast", (void *)LCLegacyPlatformVersionCheck);
        LCOverwriteGotSlotsInImage(mh, slide, "___isPlatformVersionAtLeast", (void *)LCLegacyPlatformVersionCheck);
    }
    LCOverwriteGotSlotsInImage(mh, slide, "free", (void *)LCGuardedFreeEarly);
    LCOverwriteGotSlotsInImage(mh, slide, "malloc_zone_free", (void *)LCGuardedZoneFreeEarly);
    // Plain allocations first: the abort this fixes happens during the image's
    // own initializers, before any of the availability answers matter.
    LCHookGuestAllocationOperators(mh, slide, path);

    // The engine does not have to be the app executable: in the reported case
    // it is a framework inside the bundle (Frameworks/blackrussia-client),
    // which is why the pin has to run for every guest image, exactly like the
    // old UUID check did.
    LCForceLegacyAllocatorMode(mh, slide);
    NSLog(@"[LC] guest image guarded pre-init: %s", path);
}

static void LCInstallGuestAllocatorGuard(void) {
    static bool installed = false;
    if (installed) return;
    installed = true;
    gLCAllocatorScanBudget = 0x2000000ULL; // fresh budget per process
    // Fires immediately for all images loaded so far (LC's own - filtered out
    // by path) and for every image added later, before its initializers run.
    _dyld_register_func_for_add_image(LCGuardGuestImageEarly);
    NSLog(@"[LC] guest allocator guard registered");
}
// ---------------------------------------------------------------------------

static NSString* invokeAppMain(NSString *selectedApp, NSString *selectedContainer, int argc, char *argv[]) {
    NSString *appError = nil;
    if([[lcUserDefaults objectForKey:@"LCWaitForDebugger"] boolValue]) {
        sleep(100);
    }
    if (!LCSharedUtils.certificatePassword && !isSideStore) {
#if !TARGET_OS_SIMULATOR
        if(@available(iOS 26.0 ,*))  {
            return @"JITLess mode is required since iOS 26. Please set it up in settings. \nPlease go to LiveContainer settings -> tap \"Import Certificate from SideStore\" / \"Import Certificate\"";
        }
#endif
        // First of all, let's check if we have JIT
        for (int i = 0; i < 10 && !checkJITEnabled(); i++) {
            usleep(1000*100);
        }
        if (!checkJITEnabled()) {
            appError = @"JIT was not enabled. If you want to use LiveContainer without JIT, setup JITLess mode in settings.";
            return appError;
        }
    }

    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *docPath = [NSString stringWithFormat:@"%s/Documents", getenv("LC_HOME_PATH")];
    
    NSURL *appGroupFolder = nil;
    
    NSString *bundlePath = 0;
    if(!isSideStore) {
        bundlePath = [NSString stringWithFormat:@"%@/Applications/%@", docPath, selectedApp];
    } else if (isLiveProcess) {
        bundlePath = [[NSBundle.mainBundle.bundleURL.URLByDeletingLastPathComponent.URLByDeletingLastPathComponent URLByAppendingPathComponent:@"Frameworks/SideStoreApp.framework"] path];
    } else {
        bundlePath = [[NSBundle.mainBundle.bundleURL URLByAppendingPathComponent:@"Frameworks/SideStoreApp.framework"] path];
    }
    

    guestAppInfo = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/LCAppInfo.plist", bundlePath]];

    // not found locally, let's look for the app in shared folder
    if(!guestAppInfo) {
        NSURL *appGroupPath = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:[LCSharedUtils appGroupID]];
        appGroupFolder = [appGroupPath URLByAppendingPathComponent:@"LiveContainer"];
        bundlePath = [NSString stringWithFormat:@"%@/Applications/%@", appGroupFolder.path, selectedApp];
        guestAppInfo = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/LCAppInfo.plist", bundlePath]];
        isSharedBundle = true;
    }
    
    if(!guestAppInfo) {
        return @"App bundle not found! Unable to read LCAppInfo.plist.";
    }
    
    if([guestAppInfo[@"doUseLCBundleId"] boolValue] ) {
        NSMutableDictionary* infoPlist = [NSMutableDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist", bundlePath]];
        CFErrorRef error = NULL;
        void* taskSelf = SecTaskCreateFromSelf(NULL);
        CFTypeRef value = SecTaskCopyValueForEntitlement(taskSelf, CFSTR("application-identifier"), &error);
        CFRelease(taskSelf);
        if (value) {
            NSString *entStr = (__bridge NSString *)value;
            CFRelease(value);
            NSRange dotRange = [entStr rangeOfString:@"."];
            if (dotRange.location != NSNotFound) {
                NSString *expectedBundleId = [entStr substringFromIndex:dotRange.location + 1];
                if(![infoPlist[@"CFBundleIdentifier"] isEqualToString:expectedBundleId]) {
                    infoPlist[@"CFBundleIdentifier"] = expectedBundleId;
                    [infoPlist writeBinToFile:[NSString stringWithFormat:@"%@/Info.plist", bundlePath] atomically:YES];
                }
            }
        }
    }
    
    NSBundle *appBundle = [[NSBundle alloc] initWithPathForMainBundle:bundlePath];
    
    if(!appBundle) {
        return @"App not found";
    }
    
    // find container in Info.plist
    NSString* dataUUID = selectedContainer;
    if(!dataUUID) {
        dataUUID = guestAppInfo[@"LCDataUUID"];
    }

    if(dataUUID == nil) {
        return @"Container not found!";
    }
    
    if(isLiveProcess && !isSideStore) {
        lcAppUrlScheme = [lcUserDefaults stringForKey:@"hostUrlScheme"];
        [lcUserDefaults removeObjectForKey:@"hostUrlScheme"];
    }
    
    NSError *error;

    // Setup tweak loader
    NSString *tweakFolder = nil;
    if (isSharedBundle) {
        tweakFolder = [appGroupFolder.path  stringByAppendingPathComponent:@"Tweaks"];
    } else {
        tweakFolder = [docPath stringByAppendingPathComponent:@"Tweaks"];
    }
    setenv("LC_GLOBAL_TWEAKS_FOLDER", tweakFolder.UTF8String, 1);

    // Update TweakLoader symlink
    NSString *tweakLoaderPath = [tweakFolder stringByAppendingPathComponent:@"TweakLoader.dylib"];
    if (![fm fileExistsAtPath:tweakLoaderPath]) {
        remove(tweakLoaderPath.UTF8String);
        NSString *bundlePath = NSBundle.mainBundle.bundlePath;
        if([bundlePath hasSuffix:@"PlugIns/LiveProcess.appex"]) {
            // traverse back to LiveContainer.app
            bundlePath = bundlePath.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
        }
        NSString *target = [bundlePath stringByAppendingPathComponent:@"Frameworks/TweakLoader.dylib"];
        symlink(target.UTF8String, tweakLoaderPath.UTF8String);
    }

    // If JIT is enabled, bypass library validation so we can load arbitrary binaries
    bool isJitEnabled = checkJITEnabled();
    if (isJitEnabled) {
        init_bypassDyldLibValidation();
    }

    // Locate dyld image name address
    const char **path = _CFGetProcessPath();
    const char *oldPath = *path;
    
    // Overwrite @executable_path
    const char *appExecPath = appBundle.executablePath.fileSystemRepresentation;
    *path = appExecPath;
    overwriteExecPath(appExecPath);
    
    // Overwrite NSUserDefaults
    if([guestAppInfo[@"doUseLCBundleId"] boolValue]) {
        lcGuestAppId = guestAppInfo[@"LCOrignalBundleIdentifier"];
    } else {
        lcGuestAppId = appBundle.bundleIdentifier;
        
    }

    // Overwrite home and tmp path
    NSString *newHomePath = nil;
    NSArray<NSDictionary*>* containers = guestAppInfo[@"LCContainers"];
    NSURL* bookmarkURL = nil;

    // see if the container contains a bookmark. if so, resolve it and report error upon failure.
    if(containers && [containers isKindOfClass:NSArray.class]) {
        for(NSDictionary* container in containers){
            if(![container isKindOfClass:NSDictionary.class]) {
                continue;
            }
            if([container[@"folderName"] isEqualToString:dataUUID]) {
                NSData* bookmarkData = container[@"bookmarkData"];
                if(bookmarkData && [bookmarkData isKindOfClass:NSData.class]) {
                    // we will be killed by watchdog before timedout, so we set this error beforehand.
                    [lcUserDefaults setObject:@"Bookmark resolution timed out. Is the data storage offline?" forKey:@"error"];
                    NSError* err = nil;
                    BOOL isStale = false;
                    bookmarkURL = [NSURL URLByResolvingBookmarkData:bookmarkData options:0 relativeToURL:nil bookmarkDataIsStale:&isStale error:&err];
                    bool access = [bookmarkURL startAccessingSecurityScopedResource];
                    if(!bookmarkURL || !access) {
                        return [@"Bookmark resolution failed or unable to access the container. You might need to readd the data storage. %@" stringByAppendingString:err.localizedDescription];
                    }
                    [lcUserDefaults removeObjectForKey:@"error"];
                }
                break;
            }
        }
    }
    
    if(isSideStore) {
        if(isLiveProcess) {
            newHomePath = [lcUserDefaults stringForKey:@"specifiedSideStoreContainerPath"];;
            [lcUserDefaults removeObjectForKey:@"specifiedSideStoreContainerPath"];
        } else {
            newHomePath = [docPath stringByAppendingPathComponent:@"SideStore"];
        }
    } else if (bookmarkURL) {
        newHomePath = bookmarkURL.path;
    } else if(isSharedBundle) {
        newHomePath = [NSString stringWithFormat:@"%@/Data/Application/%@", appGroupFolder.path, dataUUID];
        
    } else {
        newHomePath = [NSString stringWithFormat:@"%@/Data/Application/%@", docPath, dataUUID];
    }
    
    
    NSString *newTmpPath = [newHomePath stringByAppendingPathComponent:@"tmp"];
    remove(newTmpPath.UTF8String);
    symlink(getenv("TMPDIR"), newTmpPath.UTF8String);
    
    if([guestAppInfo[@"doSymlinkInbox"] boolValue]) {
        NSString* inboxSymlinkPath = [NSString stringWithFormat:@"%s/%@-Inbox", getenv("TMPDIR"), [appBundle bundleIdentifier]];
        NSString* inboxPath = [newHomePath stringByAppendingPathComponent:@"Inbox"];
        
        if (![fm fileExistsAtPath:inboxPath]) {
            [fm createDirectoryAtPath:inboxPath withIntermediateDirectories:YES attributes:nil error:&error];
        }
        if([fm fileExistsAtPath:inboxSymlinkPath]) {
            NSString* fileType = [fm attributesOfItemAtPath:inboxSymlinkPath error:&error][NSFileType];
            if(fileType == NSFileTypeDirectory) {
                NSArray* contents = [fm contentsOfDirectoryAtPath:inboxSymlinkPath error:&error];
                for(NSString* content in contents) {
                    [fm moveItemAtPath:[inboxSymlinkPath stringByAppendingPathComponent:content] toPath:[inboxPath stringByAppendingPathComponent:content] error:&error];
                }
                [fm removeItemAtPath:inboxSymlinkPath error:&error];
            }
        }
        

        symlink(inboxPath.UTF8String, inboxSymlinkPath.UTF8String);
    } else {
        NSString* inboxSymlinkPath = [NSString stringWithFormat:@"%s/%@-Inbox", getenv("TMPDIR"), [appBundle bundleIdentifier]];
        NSDictionary* targetAttribute = [fm attributesOfItemAtPath:inboxSymlinkPath error:&error];
        if(targetAttribute) {
            if(targetAttribute[NSFileType] == NSFileTypeSymbolicLink) {
                [fm removeItemAtPath:inboxSymlinkPath error:&error];
            }
        }

    }
    
    setenv("CFFIXED_USER_HOME", newHomePath.UTF8String, 1);
    setenv("HOME", newHomePath.UTF8String, 1);
    // we don't change TMP's env in case some apps clear cache by directly deleting the tmp folder,
    // which if symlinked, the new tmp cannot be recreated (#1040, #1125) or the app may camplain about the tmp folder being a symlimk (#884)

    // Setup directories
    NSArray *dirList = @[@"Library/Caches", @"Library/Cookies", @"Documents", @"SystemData"];
    for (NSString *dir in dirList) {
        NSString *dirPath = [newHomePath stringByAppendingPathComponent:dir];
        [fm createDirectoryAtPath:dirPath withIntermediateDirectories:YES attributes:nil error:nil];
    }
    
    NSString* containerInfoPath = [newHomePath stringByAppendingPathComponent:@"LCContainerInfo.plist"];
    guestContainerInfo = [NSDictionary dictionaryWithContentsOfFile:containerInfoPath];
    
    [LCSharedUtils setContainerUsingByLC:lcAppUrlScheme folderName:dataUUID auditToken:0];

    // Overwrite NSBundle
    overwriteMainNSBundle(appBundle);

    // Overwrite CFBundle
    overwriteMainCFBundle();

    // Overwrite executable info
    if(!appBundle.executablePath) {
        return @"App's executable path not found. Please try force re-signing or reinstalling this app.";
    }

    NSMutableArray<NSString *> *objcArgv = NSProcessInfo.processInfo.arguments.mutableCopy;
    objcArgv[0] = appBundle.executablePath;
    [NSProcessInfo.processInfo performSelector:@selector(setArguments:) withObject:objcArgv];
    NSProcessInfo.processInfo.processName = appBundle.infoDictionary[@"CFBundleExecutable"];
    *_CFGetProgname() = NSProcessInfo.processInfo.processName.UTF8String;
    Class swiftNSProcessInfo = NSClassFromString(@"_NSSwiftProcessInfo");
    if(swiftNSProcessInfo) {
        // Swizzle the arguments method to return the ObjC arguments
        SEL selector = @selector(arguments);
        method_setImplementation(class_getInstanceMethod(swiftNSProcessInfo, selector), class_getMethodImplementation(NSProcessInfo.class, selector));
    }
    
    // hook NSUserDefault before running libraries' initializers
    NUDGuestHooksInit();
    if(!isSideStore) {
        SecItemGuestHooksInit();
        NSFMGuestHooksInit();
        initDead10ccFix();
    }
    if(isLiveProcess) {
        NSURLSCGuestHooksInit();
    }
    // ignore setting handler from guest app
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, NSSetUncaughtExceptionHandler, hook_do_nothing, nil);
    
    BOOL hookDlopen = !isSideStore && !isSharedBundle && LCSharedUtils.certificatePassword && isLiveProcess;
    DyldHooksInit([guestAppInfo[@"hideLiveContainer"] boolValue], hookDlopen, [guestAppInfo[@"spoofSDKVersion"] unsignedIntValue]);
    
    if([guestContainerInfo[@"spoofIdentifierForVendor"] boolValue]) {
        NSString* idForVendorStr = guestContainerInfo[@"spoofedIdentifierForVendor"];
        if([idForVendorStr isKindOfClass:NSString.class]) {
            NSUUID* idForVendorUUID = [[NSUUID UUID] initWithUUIDString:idForVendorStr];
            if(idForVendorUUID) {
                IDFVHookInit(idForVendorUUID);
            }
        }
    }
    
    bool is32bit = [guestAppInfo[@"is32bit"] boolValue];
    if(is32bit) {
        [lcUserDefaults removeObjectForKey:@"LC32BitTranslationLayerLogFile"];
        if (!isJitEnabled) {
            return @"JIT is required to run 32-bit apps.";
        }
        
        NSString *selected32BitLayer = guestAppInfo[@"selected32BitEmulator"] ?: [lcSharedDefaults stringForKey:@"LCSelected32BitEmulator"];
        if(selected32BitLayer.length == 0) {
            appError = @"No 32-bit emulator selected";
            NSLog(@"[LCBootstrap] %@", appError);
            *path = oldPath;
            return appError;
        }
        NSBundle *selected32bitLayerBundle = [NSBundle bundleWithPath:[NSString stringWithFormat:@"%@/Applications/%@", docPath, selected32BitLayer]];
        if(!selected32bitLayerBundle) {
            selected32bitLayerBundle = [NSBundle bundleWithPath:[NSString stringWithFormat:@"%@/Applications/%@", appGroupFolder.path, selected32BitLayer]];
        }
        if(!selected32bitLayerBundle) {
            appError = @"The specified 32-bit emulator app is not found";
            NSLog(@"[LCBootstrap] %@", appError);
            *path = oldPath;
            return appError;
        }
        // maybe need to save selected32bitLayerBundle to static variable?
        appExecPath = strdup(selected32bitLayerBundle.executablePath.UTF8String);
        overwriteExecPath(appExecPath);
    }
    if(![guestAppInfo[@"dontInjectTweakLoader"] boolValue]) {
        tweakLoaderLoaded = true;
    }
    
    // Install the guest allocator guard BEFORE the guest dlopen: dyld fires
    // add-image handlers for every guest image before its initializers run.
    LCInstallGuestAllocatorGuard();

    // Preload executable to bypass RT_NOLOAD
    appMainImageIndex = _dyld_image_count();
    __block void *appHandle = 0;
    void (^dlopenBlock)(void) = ^{
        appHandle = dlopen_nolock(appExecPath, RTLD_LAZY|RTLD_GLOBAL|RTLD_FIRST);
    };
    
    BOOL is27up = false;
    if(@available(iOS 27, *)) { is27up = true; }
    if(is27up && [guestAppInfo[@"segCountMismatch"] boolValue]) {
        bypass_seg_count_check(dlopenBlock);
    } else {
        dlopenBlock();
    }

    appExecutableHandle = appHandle;
    const char *dlerr = dlerror();
    
    if (!appHandle || (uint64_t)appHandle > 0xf00000000000) {
        if (dlerr) {
            appError = @(dlerr);
        } else {
            appError = @"dlopen: an unknown error occurred";
        }
        NSLog(@"[LCBootstrap] %@", appError);
        *path = oldPath;
        return appError;
    }
    
    if([guestAppInfo[@"dontInjectTweakLoader"] boolValue] && ![guestAppInfo[@"dontLoadTweakLoader"] boolValue]) {
        tweakLoaderLoaded = true;
        if([guestAppInfo[@"hideLiveContainer"] boolValue]) {
            dlopen([lcMainBundle.bundlePath stringByAppendingPathComponent:@"Frameworks/TweakLoader.dylib"].UTF8String, RTLD_LAZY|RTLD_GLOBAL);
        } else {
            dlopen("@loader_path/../TweakLoader.dylib", RTLD_LAZY|RTLD_GLOBAL);
        }
    }
    
    if(isSideStore) {
        tweakLoaderLoaded = true;
        dlopen([lcMainBundle.bundlePath stringByAppendingPathComponent:@"Frameworks/TweakLoader.dylib"].UTF8String, RTLD_LAZY|RTLD_GLOBAL);
    }
    
    if(sideStoreExist) {
        if (!isLiveProcess && (isSideStore || ![guestAppInfo[@"dontInjectTweakLoader"] boolValue])) {
            dlopen([lcMainBundle.bundlePath stringByAppendingPathComponent:@"Frameworks/SideStoreSupport.framework/SideStoreSupport"].UTF8String, RTLD_LAZY);
        } else if (isLiveProcess && isSideStore) {
            dlopen([lcMainBundle.bundlePath stringByAppendingPathComponent:@"../../Frameworks/SideStoreSupport.framework/SideStoreSupport"].UTF8String, RTLD_LAZY);
        }
    }
    
    // Fix dynamic properties of some apps
    [NSUserDefaults performSelector:@selector(initialize)];

    // Attempt to load the bundle. 32-bit bundle will always fail because of 32-bit main executable, so ignore it
    if (!is32bit && ![appBundle loadAndReturnError:&error]) {
        appError = error.localizedDescription;
        NSLog(@"[LCBootstrap] loading bundle failed: %@", error);
        *path = oldPath;
        return appError;
    }
    NSLog(@"[LCBootstrap] loaded bundle");

    // Find main()
    appMain = getAppEntryPoint(appHandle);
    if (!appMain) {
        appError = @"Could not find the main entry point";
        NSLog(@"[LCBootstrap] %@", appError);
        *path = oldPath;
        return appError;
    }

    // Go!
    NSLog(@"[LCBootstrap] jumping to main %p", appMain);
    int ret;
    if(!is32bit) {
        argv[0] = (char *)appExecPath;
        ret = appMain(argc, argv, environ);
    } else {
        char *argv32[] = {(char*)appExecPath, (char*)*path, NULL};
        ret = appMain(sizeof(argv32)/sizeof(*argv32) - 1, argv32, environ);
    }
    return [NSString stringWithFormat:@"App returned from its main function with code %d.", ret];
}

static void exceptionHandler(NSException *exception) {
    NSString *error = [NSString stringWithFormat:@"%@\nCall stack: %@", exception.reason, exception.callStackSymbols];
    if(isLiveProcess) {
        NSExtensionContext *context = [NSClassFromString(@"LiveProcessHandler") extensionContext];
        [context cancelRequestWithError:[NSError errorWithDomain:@"LiveProcess" code:1 userInfo:@{NSLocalizedDescriptionKey: error}]];
    } else {
        [lcUserDefaults setObject:error forKey:@"error"];
    }
}

int LiveContainerMain(int argc, char *argv[]) {
    lcMainBundle = [NSBundle mainBundle];
    lcUserDefaults = NSUserDefaults.standardUserDefaults;
    
    lcSharedDefaults = [[NSUserDefaults alloc] initWithSuiteName: [LCSharedUtils appGroupID]];
    lcAppUrlScheme = NSBundle.mainBundle.infoDictionary[@"CFBundleURLTypes"][0][@"CFBundleURLSchemes"][0];
    lcAppGroupPath = [[NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:[NSClassFromString(@"LCSharedUtils") appGroupID]] path];
    isLiveProcess = [lcAppUrlScheme isEqualToString:@"liveprocess"];
    setenv("LC_HOME_PATH", getenv("HOME"), 0);

    NSString *selectedApp = [lcUserDefaults stringForKey:@"selected"];
    NSString *selectedContainer = [lcUserDefaults stringForKey:@"selectedContainer"];
    NSString *launchUrl = nil;
    do {
        if(selectedApp) {
            launchUrl = [lcUserDefaults stringForKey:@"launchAppUrlScheme"];
            break;
        }
        // check launch task in shared defaults
        NSString* scheemFromLaunchExtension = [lcSharedDefaults stringForKey:@"LCLaunchExtensionScheme"];
        if(![scheemFromLaunchExtension isEqualToString:lcAppUrlScheme]) break;
        NSString* selectedAppFromLaunchExtension = [lcSharedDefaults stringForKey:@"LCLaunchExtensionBundleID"];
        if(!selectedAppFromLaunchExtension) break;
        NSDate* launchDate = [lcSharedDefaults objectForKey:@"LCLaunchExtensionLaunchDate"];
        NSTimeInterval secondsSinceDate = [launchDate timeIntervalSinceNow];
        if (secondsSinceDate >= 0 || secondsSinceDate < -3.0) break;
        
        selectedApp = selectedAppFromLaunchExtension;
        selectedContainer = [lcSharedDefaults stringForKey:@"LCLaunchExtensionContainerName"];
        launchUrl = [lcSharedDefaults stringForKey:@"LCLaunchExtensionLaunchURL"];
        
        [lcSharedDefaults removeObjectForKey:@"LCLaunchExtensionBundleID"];
        if (selectedContainer) [lcSharedDefaults removeObjectForKey:@"LCLaunchExtensionContainerName"];
        if (launchUrl) [lcSharedDefaults removeObjectForKey:@"LCLaunchExtensionLaunchURL"];
    } while (0);
    
    NSString* lastLaunchDataUUID;
    if(!isLiveProcess) {
        lastLaunchDataUUID = [lcUserDefaults objectForKey:@"lastLaunchDataUUID"];
    } else {
        lastLaunchDataUUID = selectedContainer;
    }
    
    // we put all files in app group after fixing 0xdead10cc. This call is here in case user upgraded lc with app's data in private Library/SharedDocuments
    [LCSharedUtils moveSharedAppFolderBack];
    
    if(lastLaunchDataUUID) {
        NSString* lastLaunchType = [lcUserDefaults objectForKey:@"lastLaunchType"];
        NSString* preferencesTo;
        if([lastLaunchType isEqualToString:@"Shared"]) {
            preferencesTo = [LCSharedUtils.appGroupPath.path stringByAppendingPathComponent:[NSString stringWithFormat:@"LiveContainer/Data/Application/%@/Library/Preferences", lastLaunchDataUUID]];
        } else {
            NSString *docPath = [NSString stringWithFormat:@"%s/Documents", getenv("LC_HOME_PATH")];
            preferencesTo = [docPath stringByAppendingPathComponent:[NSString stringWithFormat:@"Data/Application/%@/Library/Preferences", lastLaunchDataUUID]];
        }
        // recover preferences
        // this is not needed anymore, it's here for backward competability
        [LCSharedUtils dumpPreferenceToPath:preferencesTo dataUUID:lastLaunchDataUUID];
        if(!isLiveProcess) {
            [lcUserDefaults removeObjectForKey:@"lastLaunchDataUUID"];
            [lcUserDefaults removeObjectForKey:@"lastLaunchType"];
        }
    }
    // in case some weird apps remove the tmp folder
    [NSFileManager.defaultManager createDirectoryAtPath:@(getenv("TMPDIR")) withIntermediateDirectories:YES attributes:nil error:nil];
    
    if([selectedApp isEqualToString:@"ui"]) {
        selectedApp = nil;
        [lcUserDefaults removeObjectForKey:@"selected"];
        [lcUserDefaults removeObjectForKey:@"selectedContainer"];
    }
    
    if(isLiveProcess) {
        sideStoreExist = [NSFileManager.defaultManager fileExistsAtPath:[lcMainBundle.bundlePath stringByAppendingPathComponent:@"../../Frameworks/SideStoreApp.framework"]];
    } else {
        sideStoreExist = [NSFileManager.defaultManager fileExistsAtPath:[lcMainBundle.bundlePath stringByAppendingPathComponent:@"Frameworks/SideStoreApp.framework"]];
    }

    if([lcUserDefaults boolForKey:@"LCOpenSideStore"] || [selectedApp isEqualToString:@"builtinSideStore"]) {
        if(sideStoreExist) {
            isSideStore = true;
        } else {
            [lcUserDefaults setBool:NO forKey:@"LCOpenSideStore"];
        }
    }
    
    if(selectedApp && !isSideStore && !selectedContainer) {
        selectedContainer = [LCSharedUtils findDefaultContainerWithBundleId:selectedApp];
    }
    NSString* runningLC = [LCSharedUtils getContainerUsingLCSchemeWithFolderName:selectedContainer];
    // if another instance is running, we just switch to that one, these should be called after uiapplication initialized
    // however if the running lc is liveprocess and current lc is livecontainer1 we just continue
    if(selectedApp && runningLC) {
        [lcUserDefaults removeObjectForKey:@"selected"];
        [lcUserDefaults removeObjectForKey:@"selectedContainer"];
        
        if([runningLC hasSuffix:@"liveprocess"]) {
            runningLC = runningLC.stringByDeletingPathExtension;
        }
        
        NSString* selectedAppBackUp = selectedApp;
        selectedApp = nil;
        dispatch_time_t delay = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC));
        dispatch_after(delay, dispatch_get_main_queue(), ^{
            // Base64 encode the data
            NSString* urlStr;
            if(selectedContainer) {
                urlStr = [NSString stringWithFormat:@"%@://livecontainer-launch?bundle-name=%@&container-folder-name=%@", runningLC, selectedAppBackUp, selectedContainer];
            } else {
                urlStr = [NSString stringWithFormat:@"%@://livecontainer-launch?bundle-name=%@", runningLC, selectedAppBackUp];
            }
            
            NSURL* url = [NSURL URLWithString:urlStr];
            if([[NSClassFromString(@"UIApplication") sharedApplication] canOpenURL:url]){
                [[NSClassFromString(@"UIApplication") sharedApplication] openURL:url options:@{} completionHandler:nil];
                
                NSString *launchUrl = [lcUserDefaults stringForKey:@"launchAppUrlScheme"];
                // also pass url scheme to another lc
                if(launchUrl) {
                    [lcUserDefaults removeObjectForKey:@"launchAppUrlScheme"];

                    // Base64 encode the data
                    NSData *data = [launchUrl dataUsingEncoding:NSUTF8StringEncoding];
                    NSString *encodedUrl = [data base64EncodedStringWithOptions:0];
                    
                    NSString* finalUrl = [NSString stringWithFormat:@"%@://open-url?url=%@", runningLC, encodedUrl];
                    NSURL* url = [NSURL URLWithString: finalUrl];
                    
                    [[NSClassFromString(@"UIApplication") sharedApplication] openURL:url options:@{} completionHandler:nil];

                }
            }
        });

    }
    NSSetUncaughtExceptionHandler(&exceptionHandler);
    if (selectedApp || isSideStore) {
        [lcUserDefaults removeObjectForKey:@"selected"];
        [lcUserDefaults removeObjectForKey:@"selectedContainer"];
        if(launchUrl) {
            lcLaunchURL = launchUrl;
            [lcUserDefaults removeObjectForKey:@"launchAppUrlScheme"];
        }
        NSString *appError = invokeAppMain(selectedApp, selectedContainer, argc, argv);
        if (appError) {
            if(isLiveProcess) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(100 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
                    NSExtensionContext *context = [NSClassFromString(@"LiveProcessHandler") extensionContext];
                    [context cancelRequestWithError:[NSError errorWithDomain:@"LiveProcess" code:1 userInfo:@{NSLocalizedDescriptionKey: appError}]];
                    exit(1);
                });
                // spin and wait for iOS to terminate
                CFRunLoopRun();
            } else {
                [lcUserDefaults setObject:appError forKey:@"error"];
                // potentially unrecovable state, exit now
                return 1;
            }
        }
    }
    
    if(isLiveProcess) {
        NSLog(@"LiveProcess should not launch lcui!");
        return 0;
    }
    
    // put back cookies
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *libraryURL = [fm URLsForDirectory:NSLibraryDirectory inDomains:NSUserDomainMask].firstObject;;
    NSURL *cookies2URL = [libraryURL URLByAppendingPathComponent:@"Cookies2"];
    
    BOOL isDir = NO;
    if ([fm fileExistsAtPath:cookies2URL.path isDirectory:&isDir] && isDir) {
        NSError *error = nil;
        NSURL *cookiesURL  = [libraryURL URLByAppendingPathComponent:@"Cookies"];
        // Remove old Caches folder if exists
        if ([fm fileExistsAtPath:cookiesURL.path]) {
            if ([fm removeItemAtURL:cookiesURL error:&error]) {
                [fm moveItemAtURL:cookies2URL toURL:cookiesURL error:&error];
            } else{
                NSLog(@"Failed to remove old Cookies folder: %@", error);
            }
        }
    }
    
    void *LiveContainerSwiftUIHandle = dlopen("@executable_path/Frameworks/LiveContainerSwiftUI.framework/LiveContainerSwiftUI", RTLD_LAZY);
    NSCAssert(LiveContainerSwiftUIHandle, @"%s", dlerror());
    
    if(sideStoreExist) {
        void* sideStoreHandle = dlopen("@executable_path/Frameworks/SideStoreSupport.framework/SideStoreSupport", RTLD_LAZY);
    }

    if ([lcUserDefaults boolForKey:@"LCLoadTweaksToSelf"]) {
        NSString *tweakFolder = nil;
        if (isSharedBundle) {
            NSURL *appGroupPath = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:[LCSharedUtils appGroupID]];
            tweakFolder = [appGroupPath.path stringByAppendingPathComponent:@"LiveContainer/Tweaks"];
        } else {
            NSString *docPath = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].lastObject.path;
            tweakFolder = [docPath stringByAppendingPathComponent:@"Tweaks"];
        }
        setenv("LC_GLOBAL_TWEAKS_FOLDER", tweakFolder.UTF8String, 1);
#if TARGET_OS_MACCATALYST || TARGET_OS_SIMULATOR
        extern void DyldHookLoadableIntoProcess(void);
        DyldHookLoadableIntoProcess();
#endif
        dlopen("@executable_path/Frameworks/TweakLoader.dylib", RTLD_LAZY);
    }

    int (*LiveContainerSwiftUIMain)(void) = dlsym(LiveContainerSwiftUIHandle, "main");
    return LiveContainerSwiftUIMain();

}

#ifdef DEBUG
int callAppMain(int argc, char *argv[], char *envp[]) {
    assert(appMain != NULL);
    __attribute__((musttail)) return appMain(argc, argv, envp);
}
#endif
