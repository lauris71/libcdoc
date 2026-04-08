/*
 * libcdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openssl/x509v3.h>

#include "Crypto.h"
#include "Certificate.h"

namespace libcdoc {

Certificate::Certificate(const std::vector<uint8_t>& data)
    : cert(d2i<d2i_X509,X509_free>(data, nullptr))
{
    if(!data.empty() && !cert)
        LOG_SSL_ERROR("d2i_X509");
}

std::string Certificate::getName(int NID) const
{
    std::string cn;
    if(!cert)
        return cn;
    X509_NAME *name = X509_get_subject_name(cert.get());
    if(!name)
        return cn;
    int pos = X509_NAME_get_index_by_NID(name, NID, -1);
    if(pos == -1)
        return cn;
    X509_NAME_ENTRY *e = X509_NAME_get_entry(name, pos);
    if(!e)
        return cn;
    char *data = nullptr;
    if(int size = ASN1_STRING_to_UTF8((uint8_t**)&data, X509_NAME_ENTRY_get_data(e)); size > 0)
        cn.assign(data, size_t(size));
    OPENSSL_free(data);
    return cn;
}

std::string
Certificate::getCommonName() const
{
    return getName(NID_commonName);
}

std::string
Certificate::getGivenName() const
{
    return getName(NID_givenName);
}

std::string
Certificate::getSurname() const
{
    return getName(NID_surname);
}

std::string
Certificate::getSerialNumber() const
{
    return getName(NID_serialNumber);
}

time_t
Certificate::getNotAfter() const
{
    if(!cert)
        return 0;
    tm tm{};
    if(ASN1_TIME_to_tm(X509_get0_notAfter(cert.get()), &tm) != 1)
        return 0;
#ifdef _WIN32
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
}

Certificate::EIDType
Certificate::getEIDType() const
{
    if(!cert)
        return Unknown;

    auto cp = make_unique_cast<CERTIFICATEPOLICIES_free>(X509_get_ext_d2i(
        cert.get(), NID_certificate_policies, nullptr, nullptr));
    if(!cp)
        return Unknown;

    constexpr int PolicyBufferLen = 50;
    char buf[PolicyBufferLen + 1]{};
    for(int i = 0; i < sk_POLICYINFO_num(cp.get()); i++) {
        POLICYINFO *pi = sk_POLICYINFO_value(cp.get(), i);
        int len = OBJ_obj2txt(buf, PolicyBufferLen, pi->policyid, 1);
        if(len == NID_undef) {
            continue;
        }

        std::string_view policy(buf, size_t(len));
        if (policy.starts_with("2.999.")) { // Zetes TEST OID prefix
            policy = policy.substr(6);
        }

        if (policy.starts_with("1.3.6.1.4.1.51361.1.1.3") ||
            policy.starts_with("1.3.6.1.4.1.51361.1.2.3")) {
            return DigiID;
        }

        if (policy.starts_with("1.3.6.1.4.1.51361.1.1.4") ||
            policy.starts_with("1.3.6.1.4.1.51361.1.2.4") ||
            policy.starts_with("1.3.6.1.4.1.51361.2.1.6")) {
            return DigiID_EResident;
        }

        if (policy.starts_with("1.3.6.1.4.1.51361.1.1") ||
            policy.starts_with("1.3.6.1.4.1.51361.1.2") ||
            policy.starts_with("1.3.6.1.4.1.51361.2.1") ||
            policy.starts_with("1.3.6.1.4.1.51455.1.1") ||
            policy.starts_with("1.3.6.1.4.1.51455.1.2") ||
            policy.starts_with("1.3.6.1.4.1.51455.2.1")) {
            return IDCard;
        }
    }

    // If the execution reaches so far then EID type determination failed.
    return Unknown;
}

std::vector<uint8_t>
Certificate::getPublicKey() const
{
    if(cert)
        return Crypto::toPublicKeyDer(X509_get0_pubkey(cert.get()));
    return {};
}

PKType
Certificate::getAlgorithm() const
{
    if(!cert)
        return {};

    EVP_PKEY *pkey = X509_get0_pubkey(cert.get());
	int alg = EVP_PKEY_get_base_id(pkey);

    return (alg == EVP_PKEY_RSA) ? PKType::RSA : PKType::ECC;
}

std::vector<uint8_t> Certificate::getDigest() const
{
    if(!cert)
        return {};

    const EVP_MD* digest_type = EVP_get_digestbyname("sha1");

    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;

    if (X509_digest(cert.get(), digest_type, digest.data(), &digest_len))
    {
        digest.resize(digest_len);
    }
    else
    {
        digest.clear();
    }

    return digest;
}

} // namespace libcdoc
