#include <mach/mach_types.h>
#include <mach/kmod.h>
#if !defined(PRODUCT_NAME) || !defined(MODULE_VERSION) || !defined(BUNDLE_IDENTIFIER)
#error "Unified module identity must be supplied by build_unified_kernel.py"
#endif
#define ABC_CAT_INNER(a,b) a##b
#define ABC_CAT(a,b) ABC_CAT_INNER(a,b)
#define ABC_STRING_INNER(a) #a
#define ABC_STRING(a) ABC_STRING_INNER(a)
#define ABC_START ABC_CAT(PRODUCT_NAME,_kern_start)
#define ABC_STOP ABC_CAT(PRODUCT_NAME,_kern_stop)
#define ABC_KMOD(name,version,start,stop) KMOD_EXPLICIT_DECL(name,version,start,stop)
extern "C" kern_return_t ABC_START(kmod_info_t *,void *);
extern "C" kern_return_t ABC_STOP(kmod_info_t *,void *);
extern "C" {
ABC_KMOD(BUNDLE_IDENTIFIER,ABC_STRING(MODULE_VERSION),ABC_START,ABC_STOP)
__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain=ABC_START;
__attribute__((visibility("hidden"))) kmod_stop_func_t *_antimain=ABC_STOP;
__attribute__((visibility("hidden"))) int _kext_apple_cc=__APPLE_CC__;
}
