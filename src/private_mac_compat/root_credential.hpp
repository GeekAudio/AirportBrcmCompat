#ifndef PRIVATE_MAC_ROOT_CREDENTIAL_HPP
#define PRIVATE_MAC_ROOT_CREDENTIAL_HPP

#include <sys/kauth.h>

namespace PrivateMAC {
inline bool currentCredentialIsRoot() {
    const kauth_cred_t credential = kauth_cred_get();
    return kauth_cred_getuid(credential) == 0;
}
} // namespace PrivateMAC

#endif
