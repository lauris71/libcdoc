// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef RCPTINFO_H
#define RCPTINFO_H

#include "utils/memory.h"

#include <vector>

namespace libcdoc {

struct RcptInfo {
    // PKCS11/NCrypt data
    // NB! PIN is stored in secret
    struct PKCS11Info {
        int64_t slot = -1;
        std::vector<uint8_t> key_id;
        std::string key_label;
    };

    enum Type {
        // For decryption (use the lock type)
        LOCK,
        // For encryption
        // Certificate from file
        CERT,
        // Password from command line
        PASSWORD,
        // Symetric key from command line
        SKEY,
        // Public key from command line
        PKEY,
        // Symetric key from PKCS11 device
        P11_SYMMETRIC,
        // Public key from PKC11 device
        P11_PKI,
        // Windows
        NCRYPT,
        // N of n
        SHARE
    };

    Type type;
    // Locks label
    std::string label;
    // Certificate for encryption
    std::vector<uint8_t> cert;
    // Pin or password
    SecureBytes secret;
    // PKCS11-specific info
    PKCS11Info p11;

    // Keyfile name for automatic labels
    std::string key_file_name;
    // ID code for shares server
    std::string id;
    // Lock index
    int lock_idx = -1;

    bool isPKCS11() const { return p11.slot >= 0; }
    bool needPassword() const { return (type == PASSWORD || type == P11_SYMMETRIC || type == P11_PKI) && !secret.empty() && secret[0] == '?'; }
};

}

#endif // RCPTINFO_H
