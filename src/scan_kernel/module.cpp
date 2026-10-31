#include <mach/mach_types.h>
#include <mach/kmod.h>
extern "C" kern_return_t SkywalkScanCompat_kern_start(kmod_info_t *,void *);
extern "C" kern_return_t SkywalkScanCompat_kern_stop(kmod_info_t *,void *);
extern "C" {
KMOD_EXPLICIT_DECL(org.geekaudio.SkywalkScanCompat,"0.1.3",SkywalkScanCompat_kern_start,SkywalkScanCompat_kern_stop)
__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain=SkywalkScanCompat_kern_start;
__attribute__((visibility("hidden"))) kmod_stop_func_t *_antimain=SkywalkScanCompat_kern_stop;
__attribute__((visibility("hidden"))) int _kext_apple_cc=__APPLE_CC__;
}
