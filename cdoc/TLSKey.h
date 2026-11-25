// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef __TLSKEY_H__
#define __TLSKEY_H__

#include "utils/memory.h"

#include <openssl/evp.h>

namespace libcdoc {

class NetworkBackend;

/**
 * @brief Client TLS key whose private operations go to NetworkBackend::signTLS
 *
 * The key belongs to an OpenSSL provider of libcdoc's own, so OpenSSL hands it the digest
 * and, for RSA, the padding, including the RSASSA-PSS that TLS 1.3 requires.
 *
 * @param network the backend to sign with; it must outlive the key
 * @param cert the client certificate, which gives the public key
 * @return the key, empty for an unsupported key type or on error
 */
unique_ptr_t<EVP_PKEY_free> createTLSKey(NetworkBackend *network, X509 *cert);

} // namespace libcdoc

#endif // __TLSKEY_H__
