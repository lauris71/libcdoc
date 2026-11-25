// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef SSLCERTIFICATE_H
#define SSLCERTIFICATE_H

#include "CDoc.h"
#include "utils/memory.h"

#include <string>
#include <vector>

using X509 = struct x509_st;

namespace libcdoc {

class Certificate {
public:
    enum EIDType : unsigned char {
        Unknown,
        IDCard,
        DigiID,
        DigiID_EResident
    };

    explicit Certificate(const std::vector<uint8_t>& data);

    std::string getName(int NID) const;
    std::string getCommonName() const;
    std::string getGivenName() const;
    std::string getSurname() const;
    std::string getSerialNumber() const;

    EIDType getEIDType() const;

    std::vector<uint8_t> getPublicKey() const;
    Algorithm getAlgorithm() const;
    time_t getNotAfter() const;

    std::vector<uint8_t> getDigest() const;

    X509* handle() const noexcept { return cert.get(); }
    operator bool() const noexcept { return cert.operator bool(); };

private:
    unique_free_t<X509> cert;
};

} // Namespace

#endif // SSLCERTIFICATE_H
