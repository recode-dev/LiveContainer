#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <malloc/malloc.h>
#include <mach-o/dyld.h>
#import "../LiveContainer/utils.h"
// fishhook is compiled into this translation unit on purpose: it keeps the
// TweakLoader target's file list (and project.pbxproj) unchanged.
#include "fishhook.c"

// --- Guest free() guard + allocator-mode fix --------------------------------
//
// ROOT CAUSE (crashes #2-#5, Black Russia): the guest engine picks its C++
// allocator format lazily via a __cxa_guard-protected static constructor:
//     mode = (availability_version_check(2, 17.0.0) == 0) ? 1 : 0;
// mode 1 = plain malloc/free (matches the shared-cache libc++ deallocators),
// mode 0 = malloc(size+0x10) with a self-pointer header, delete frees
// *(p-0x10). availability_version_check consults dyld about the MAIN
// EXECUTABLE's build info — under LiveContainer that is LiveContainer itself
// (fresh SDK), so the check "passes" and the guest runs in header mode. Its
// strings then cross into the out-of-line std::string code inside the shared
// cache libc++.1.dylib, which frees with a plain unhookable free ->
// "pointer being freed was not allocated" -> SIGABRT in both directions
// (guest header pointer freed by libc++ __grow_by, and libc++abi plain
// pointer freed by the guest's free(*(p-0x10))). On a normal install the
// guest IS the main executable, the check fails on old SDKs and it stays in
// the plain mode — which is exactly what we restore here.
//
// Fix: rebind availability_version_check in every guest image (fishhook, the
// GOT slot is read before the fast path caches it) to a stub returning 0, so
// the guest selects the legacy plain-malloc allocator, identical to stock.
//
// Additionally, guest apps can still call free() on pointers that were
// allocated by other allocators. libmalloc aborts such frees with
// "pointer being freed was not allocated" -> SIGABRT. We therefore rebind
// free / malloc_zone_free in every guest image (Documents/Applications and
// Documents/Tweaks) with fishhook as well. Valid frees are forwarded
// unchanged, so behavior only differs for bogus pointers, which become small
// leaks. __interpose from the main executable does not reach images
// dlopen'ed after launch, hence fishhook.

static void LCGuardedFree(void *p) {
    if (!p) return;
    if (malloc_size(p) == 0) return; // not a live allocation start: ignore
    malloc_zone_t *zone = malloc_zone_from_ptr(p);
    malloc_zone_free(zone ? zone : malloc_default_zone(), p);
}

static void LCGuardedZoneFree(malloc_zone_t *zone, void *p) {
    if (!p) return;
    if (malloc_size(p) == 0) return;
    malloc_zone_free(zone ? zone : malloc_default_zone(), p);
}

// Guests must not inherit LiveContainer's (the main executable's) build-info
// based availability answers. Returning 0 = "requirement not met" puts the
// guest on the legacy code path of whatever it is gating (allocator format,
// OS feature gates), which is the path that runs on older iOS versions and
// is therefore the battle-tested one.
static int LCLegacyAvailabilityCheck(uint32_t count, void *args) {
    return 0;
}

static int LCLegacyPlatformVersionCheck(uint32_t platform, uint32_t major, uint32_t minor, uint32_t subminor) {
    if (major >= 16) return 0;
    return 1;
}

// Duplicated from LCBootstrap.m (this is a separate image): overwrite every
// GOT slot whose resolved value equals dlsym(symbolName). Chained-fixups
// binaries have empty indirect symbol tables, so the fishhook pass above
// silently no-ops for them; value matching needs no symbol tables.
static void LCOverwriteGotSlotsLocal(const struct mach_header *mh, intptr_t slide,
                                     const char *symbolName, void *replacement) {
    if (mh->magic != MH_MAGIC_64) return;
    void *target = dlsym(RTLD_DEFAULT, symbolName);
    if (!target) return;
    uintptr_t targetClean = (uintptr_t)target & 0x7FFFFFFFFFFFULL;
    const uint8_t *cursor = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (strcmp(seg->segname, "__DATA") != 0 &&
                strcmp(seg->segname, "__DATA_CONST") != 0 &&
                strcmp(seg->segname, "__AUTH") != 0 &&
                strcmp(seg->segname, "__AUTH_CONST") != 0) {
                cursor += lc->cmdsize;
                continue;
            }
            const struct section_64 *sections = (const struct section_64 *)(cursor + sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < seg->nsects; s++) {
                const struct section_64 *sect = &sections[s];
                uint8_t type = sect->flags & SECTION_TYPE;
                bool isGot = (type == S_NON_LAZY_SYMBOL_POINTERS ||
                              type == S_LAZY_SYMBOL_POINTERS ||
                              strncmp(sect->sectname, "__got", 5) == 0 ||
                              strncmp(sect->sectname, "__auth_got", 10) == 0 ||
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
                    uintptr_t slotClean = (uintptr_t)slots[k] & 0x7FFFFFFFFFFFULL;
                    if (slotClean == targetClean || slots[k] == target) {
                        slots[k] = replacement;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }
}

static void LCGuardGuestImages(const struct mach_header *mh, intptr_t slide) {
    Dl_info info;
    if (!dladdr((const void *)mh, &info) || !info.dli_fname) return;
    const char *path = info.dli_fname;
    if (!path) return;
    // Only patch guest app images and tweaks; LC's own images keep plain free.
    if (!strstr(path, "/Documents/Applications/") && !strstr(path, "/Documents/Tweaks/")) return;
    struct rebinding rebindings[] = {
        { "free", (void *)LCGuardedFree, NULL },
        { "malloc_zone_free", (void *)LCGuardedZoneFree, NULL },
        { "availability_version_check", (void *)LCLegacyAvailabilityCheck, NULL },
        { "_availability_version_check", (void *)LCLegacyAvailabilityCheck, NULL },
        { "__isPlatformVersionAtLeast", (void *)LCLegacyPlatformVersionCheck, NULL },
        { "___isPlatformVersionAtLeast", (void *)LCLegacyPlatformVersionCheck, NULL },
    };
    rebind_symbols_image((void *)mh, slide, rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
    // Chained-fixups images (all modern apps/tweaks) have empty indirect
    // symbol tables and the fishhook pass above no-ops for them; patch by
    // resolved value instead. Idempotent with LCBootstrap.m's pre-init pass.
    LCOverwriteGotSlotsLocal(mh, slide, "__isPlatformVersionAtLeast", (void *)LCLegacyPlatformVersionCheck);
    LCOverwriteGotSlotsLocal(mh, slide, "___isPlatformVersionAtLeast", (void *)LCLegacyPlatformVersionCheck);
    LCOverwriteGotSlotsLocal(mh, slide, "_availability_version_check", (void *)LCLegacyAvailabilityCheck);
    LCOverwriteGotSlotsLocal(mh, slide, "availability_version_check", (void *)LCLegacyAvailabilityCheck);
    LCOverwriteGotSlotsLocal(mh, slide, "free", (void *)LCGuardedFree);
    LCOverwriteGotSlotsLocal(mh, slide, "malloc_zone_free", (void *)LCGuardedZoneFree);
    NSLog(@"[LC] guest image guarded: %s", path);
}

__attribute__((constructor))
static void LCGuardedFreeInstall(void) {
    // Fires for every already-loaded image right away (guest binaries and
    // frameworks are loaded before TweakLoader) and for every image loaded
    // later (tweak dylibs), always before the new image's initializers run.
    _dyld_register_func_for_add_image(LCGuardGuestImages);
}
// ---------------------------------------------------------------------------

static NSString *loadTweakAtURL(NSURL *url) {
    NSString *tweakPath = url.path;
    NSString *tweak = tweakPath.lastPathComponent;
    if (![tweakPath hasSuffix:@".dylib"] && ![tweakPath hasSuffix:@".framework"]) {
        return nil;
    }
    if ([tweakPath hasSuffix:@".framework"]) {
        NSURL* infoPlistURL = [url URLByAppendingPathComponent:@"Info.plist"];
        NSDictionary* infoDict = [NSDictionary dictionaryWithContentsOfURL:infoPlistURL];
        NSString* binary = infoDict[@"CFBundleExecutable"];
        if(!binary || ![binary isKindOfClass:NSString.class]) {
            return [NSString stringWithFormat:@"Unable to load %@: Unable to read Info.Plist", tweak];
        }
        tweakPath = [[url URLByAppendingPathComponent:binary] path];
    }
    
    void *handle = dlopen(tweakPath.UTF8String, RTLD_LAZY | RTLD_GLOBAL);
    const char *error = dlerror();
    if (handle) {
        NSLog(@"Loaded tweak %@", tweak);
        return nil;
    } else if (error) {
        NSLog(@"Error: %s", error);
        return @(error);
    } else {
        NSLog(@"Error: dlopen(%@): Unknown error because dlerror() returns NULL", tweak);
        return [NSString stringWithFormat:@"dlopen(%@): unknown error, handle is NULL", tweakPath];
    }
}

static void loadTweaksRecursively(NSURL *folderURL, NSMutableArray *errors) {
    NSArray<NSURL *> *items = [NSFileManager.defaultManager contentsOfDirectoryAtURL:folderURL includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 error:nil];
    for (NSURL *fileURL in items) {
        NSString *name = fileURL.lastPathComponent;
        if ([name hasSuffix:@".disabled"]) {
            NSLog(@"Skipping disabled tweak %@", name);
            continue;
        }
        NSNumber *isDirectory = nil;
        [fileURL getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:nil];
        // a .framework is a directory but loads as a single tweak
        if (isDirectory.boolValue && ![name hasSuffix:@".framework"]) {
            loadTweaksRecursively(fileURL, errors);
        } else {
            NSString *error = loadTweakAtURL(fileURL);
            if (error) {
                [errors addObject:error];
            }
        }
    }
}

static void showDlerrAlert(NSString *error) {
    UIWindow *window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Failed to load tweaks" message:error preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction* okAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {
        window.windowScene = nil;
    }];
    [alert addAction:okAction];
    UIAlertAction* cancelAction = [UIAlertAction actionWithTitle:@"Copy" style:UIAlertActionStyleCancel handler:^(UIAlertAction * action) {
        UIPasteboard.generalPasteboard.string = error;
        window.windowScene = nil;
    }];
    [alert addAction:cancelAction];
    window.rootViewController = [UIViewController new];
    window.windowLevel = 1000;
    window.windowScene = (id)UIApplication.sharedApplication.connectedScenes.anyObject;
    [window makeKeyAndVisible];
    [window.rootViewController presentViewController:alert animated:YES completion:nil];
    objc_setAssociatedObject(alert, @"window", window, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

 __attribute__((constructor))
static void TweakLoaderConstructor() {
    const char *tweakFolderC = getenv("LC_GLOBAL_TWEAKS_FOLDER");
    NSString *globalTweakFolder = @(tweakFolderC);
    unsetenv("LC_GLOBAL_TWEAKS_FOLDER");
    
    if([NSUserDefaults.guestAppInfo[@"dontInjectTweakLoader"] boolValue]) {
        // don't load any tweak since tweakloader is loaded after all initializers
        NSLog(@"Skip loading tweaks");
        return;
    }
    
    NSMutableArray *errors = [NSMutableArray new];
    
    NSArray<NSURL *> *globalTweaks = [NSFileManager.defaultManager contentsOfDirectoryAtURL:[NSURL fileURLWithPath:globalTweakFolder]
    includingPropertiesForKeys:@[] options:0 error:nil];
    NSString *tweakFolderName = NSUserDefaults.guestAppInfo[@"LCTweakFolder"];
    
    if([globalTweaks count] <= 1 && tweakFolderName.length == 0) {
        // nothing to load
        return;
    }

    // Load CydiaSubstrate
    const char *lcMainBundlePath;
    if(NSUserDefaults.isLiveProcess) {
        lcMainBundlePath = NSUserDefaults.lcMainBundle.bundlePath.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent.fileSystemRepresentation;
    } else {
        lcMainBundlePath = NSUserDefaults.lcMainBundle.bundlePath.fileSystemRepresentation;
    }
    char substratePath[PATH_MAX];
    snprintf(substratePath, sizeof(substratePath), "%s/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", lcMainBundlePath);
    dlopen(substratePath, RTLD_LAZY | RTLD_GLOBAL);
    const char *substrateError = dlerror();
    if (substrateError) {
        [errors addObject:@(substrateError)];
    }

    // Load global tweaks
    NSLog(@"Loading tweaks from the global folder");

    for (NSURL *fileURL in globalTweaks) {
        NSString *name = fileURL.lastPathComponent;
        if ([name isEqualToString:@"TweakLoader.dylib"]) {
            // skip loading myself
            continue;
        }
        if ([name hasSuffix:@".disabled"]) {
            NSLog(@"Skipping disabled global tweak %@", name);
            continue;
        }
        NSString *error = loadTweakAtURL(fileURL);
        if (error) {
            [errors addObject:error];
        }
    }

    // Load selected tweak folder, recursively
    if (tweakFolderName.length > 0) {
        NSLog(@"Loading tweaks from the selected folder");
        NSString *tweakFolder = [globalTweakFolder stringByAppendingPathComponent:tweakFolderName];
        loadTweaksRecursively([NSURL fileURLWithPath:tweakFolder], errors);
    }

    if (errors.count > 0) {
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *error = [errors componentsJoinedByString:@"\n"];
            showDlerrAlert(error);
        });
    }
}
