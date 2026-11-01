// Host-only replay of the production public-KPI fallback contracts. No hooks
// are installed and none of the supplied kernel addresses are invoked.
#include "src/private_mac_compat/ifnet_kpi_contract.hpp"
#include "src/private_mac_compat/network_callback_contract.hpp"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

static bool read(const char *path, size_t limit, std::vector<uint8_t> &out) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    const auto size=input.tellg();
    if (!input || size<=0 || static_cast<uint64_t>(size)>limit) return false;
    out.resize(static_cast<size_t>(size));input.seekg(0);
    return static_cast<bool>(input.read(reinterpret_cast<char *>(out.data()),size));
}

int main(int argc,char **argv) {
    if (argc!=11) return 2;
    std::vector<uint8_t> prefix,image;
    if (!read(argv[1],48,prefix) || !read(argv[2],64U*1024U*1024U,image)) return 2;
    uintptr_t values[8] {};
    for (int i=0;i<8;++i) {
        char *end=nullptr;errno=0;
        const auto value=strtoull(argv[i+3],&end,16);
        if (errno || !end || *end || end==argv[i+3] || !value ||
            value>static_cast<uint64_t>(UINTPTR_MAX)) return 2;
        values[i]=static_cast<uintptr_t>(value);
    }
    using namespace PrivateMAC;
    const auto publicPrefix=IfnetKPIContract::safeRoutePrefix(prefix.data(),prefix.size());
    const NetworkCallbackContract::ImageView view(image.data(),image.size(),values[0]);
    const bool callback=NetworkCallbackContract::verify(view,values[1],values[2],
        values[3],values[4],{values[5],values[6],values[7]});
    size_t callbackPrefix=0;
    if (values[2]>=values[0] && values[2]-values[0]<=image.size() &&
        IfnetKPIContract::PrefixBudget<=image.size()-(values[2]-values[0]))
        callbackPrefix=IfnetKPIContract::safeRoutePrefix(
            image.data()+(values[2]-values[0]),IfnetKPIContract::PrefixBudget);
    printf("{\"public_ioctl_prefix_bytes\":%zu,\"interface_ioctl_prefix_bytes\":%zu,"
           "\"network_callback_contract\":%s,\"passed\":%s}\n",
           publicPrefix,callbackPrefix,callback?"true":"false",
           publicPrefix && callbackPrefix && callback?"true":"false");
    return 0;
}
