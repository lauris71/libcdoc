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

#include "Recipient.h"

#include "CDoc2.h"
#include "Certificate.h"
#include "Crypto.h"
#include "Lock.h"
#include "Utils.h"

#include <algorithm>
#include <chrono>

#include <openssl/core_names.h>
#include <openssl/x509.h>

using namespace std;

namespace libcdoc {

Recipient
Recipient::makeSymmetric(std::string label, int32_t kdf_iter)
{
    Recipient rcpt(Type::SYMMETRIC_KEY);
    rcpt.label = std::move(label);
    rcpt.lbl_parts[std::string(CDoc2::Label::TYPE)] = kdf_iter ? CDoc2::Label::TYPE_PASSWORD : CDoc2::Label::TYPE_SYMMETRIC;
    rcpt.kdf_iter = kdf_iter;
    return rcpt;
}

static int
EVP_PKEY_get_nid(EVP_PKEY *pkey)
{
    std::array<char, 256> name;
    if (SSL_FAILED(EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, name.data(), name.size(), nullptr), "EVP_PKEY_get_utf8_string_param"))
        return NID_undef;
    return OBJ_sn2nid(name.data());
}

static Recipient
makeEVP_PKEY(std::string label, EVP_PKEY *pkey, std::string server_id) {
    Recipient rcpt;
    auto public_key = Crypto::toPublicKeyDer(pkey);
    if (public_key.empty())
        return rcpt;
    switch (EVP_PKEY_get_id(pkey)) {
    case EVP_PKEY_RSA:
        rcpt.pk_type = RSA;
        break;
    case EVP_PKEY_EC:
        switch(EVP_PKEY_get_nid(pkey)) {
        case NID_secp384r1:
            rcpt.ec_type = Curve::SECP_384_R1;
            break;
        case NID_X9_62_prime256v1:
            rcpt.ec_type = Curve::SECP_256_R1;
            break;
        case NID_secp521r1:
            rcpt.ec_type = Curve::SECP_521_R1;
            break;
        default:
            return rcpt;
        }
        rcpt.pk_type = ECC;
        break;
    default:
        return rcpt;
    }
    rcpt.type = Recipient::Type::PUBLIC_KEY;
    rcpt.label = std::move(label);
    rcpt.rcpt_key = std::move(public_key);
    rcpt.server_id = std::move(server_id);
    return rcpt;
}

Recipient
Recipient::makePublicKey(std::string label, const std::vector<uint8_t> &public_key, std::string server_id) {
    auto pkey = Crypto::fromPublicKeyDer(public_key);
    Recipient rcpt = makeEVP_PKEY(std::move(label), pkey.get(), std::move(server_id));
    if (rcpt.type == Type::NONE)
        return rcpt;
    if (!rcpt.server_id.empty()) {
        const auto six_months_from_now = std::chrono::system_clock::now() + std::chrono::months(6);
        rcpt.expiry_ts = std::chrono::system_clock::to_time_t(six_months_from_now);
    }
    return rcpt;
}

Recipient
Recipient::makePublicKey(const Lock &lock, std::string server_id)
{
    auto params = Lock::parseLabel(lock.label);
    Recipient rcpt(Type::PUBLIC_KEY);
    rcpt.pk_type = lock.pk_type;
    rcpt.ec_type = lock.ec_type;
    rcpt.rcpt_key = lock.getBytes(Lock::RCPT_KEY);
    if (rcpt.rcpt_key.empty())
        return {Type::NONE};
    if (lock.isCDoc1())
        rcpt.cert = lock.getBytes(Lock::CERT);
    if (params.empty())
        rcpt.label = lock.label;
    if (params.contains(CDoc2::Label::EXPIRY))
    {
        const auto &val = params[CDoc2::Label::EXPIRY];
        if(std::from_chars(val.data(), val.data() + val.size(), rcpt.expiry_ts).ec == std::errc{})
            params.erase(CDoc2::Label::EXPIRY);
    }
    rcpt.lbl_parts = std::move(params);
    rcpt.server_id = std::move(server_id);
    return rcpt;
}

Recipient
Recipient::makeCertificate(std::string label, std::vector<uint8_t> cert, std::string server_id)
{
    Certificate x509(cert);
    if (!x509)
        return {Type::NONE};
    Recipient rcpt = makeEVP_PKEY(std::move(label), X509_get0_pubkey(x509.handle()), std::move(server_id));
    if (rcpt.type == Type::NONE)
        return rcpt;
    rcpt.cert = std::move(cert);
    rcpt.expiry_ts = x509.getNotAfter();
    if (auto eid = x509.getEIDType(); eid != Certificate::Unknown) {
        rcpt.lbl_parts = {
            {std::string(CDoc2::Label::TYPE), std::string(CDoc2::eid_strs[eid])},
            {std::string(CDoc2::Label::CN), x509.getCommonName()},
            {std::string(CDoc2::Label::SERIAL_NUMBER), x509.getSerialNumber()},
            {std::string(CDoc2::Label::LAST_NAME), x509.getSurname()},
            {std::string(CDoc2::Label::FIRST_NAME), x509.getGivenName()},
        };
    } else {
        rcpt.lbl_parts = {
            {std::string(CDoc2::Label::TYPE), std::string(CDoc2::Label::TYPE_CERTIFICATE)},
            {std::string(CDoc2::Label::CN), x509.getCommonName()},
            {std::string(CDoc2::Label::CERT_SHA1), toHex(x509.getDigest())},
        };
    }
    if (!rcpt.server_id.empty()) {
        const auto six_months_from_now = std::chrono::system_clock::now() + std::chrono::months(6);
        const auto expiry_ts = std::chrono::system_clock::to_time_t(six_months_from_now);
        rcpt.expiry_ts = std::min(rcpt.expiry_ts, uint64_t(expiry_ts));
    }
    return rcpt;
}

#ifdef HAS_KEYSHARES
Recipient
Recipient::makeShare(std::string label, std::string server_id, std::string recipient_id)
{
    Recipient rcpt(Type::KEYSHARE);
    rcpt.label = std::move(label);
    rcpt.server_id = std::move(server_id);
    rcpt.id = std::move(recipient_id);
    return rcpt;
}
#endif

bool
Recipient::isTheSameRecipient(const Recipient& other) const
{
    if (!isPKI()) return false;
    if (!other.isPKI()) return false;
    return rcpt_key == other.rcpt_key;
}

bool
Recipient::isTheSameRecipient(const std::vector<uint8_t>& public_key) const
{
    if (!isPKI()) return false;
    if (rcpt_key.empty() || public_key.empty()) return false;
    return rcpt_key == public_key;
}

std::string
Recipient::getLabel(std::map<std::string_view, std::string_view> extra) const
{
    LOG_DBG("Generating label");
    if (!label.empty()) return label;
    std::ostringstream ofs;
    switch(type) {
    case NONE:
        LOG_DBG("The recipient is not initialized");
        break;
    case SYMMETRIC_KEY:
    case PUBLIC_KEY:
        ofs << CDoc2::LABELPREFIX << ','
            << CDoc2::Label::VERSION << '=' << std::to_string(CDoc2::KEYLABELVERSION);
        for (const auto& [key, value] : lbl_parts) {
            if (key == "v")
                continue;
            if (auto it = extra.find(key); it != extra.end()) {
                ofs << '&' << urlEncode(key) << '=' << urlEncode(it->second);
                extra.erase(it);
            } else {
                ofs << '&' << urlEncode(key) << '=' << urlEncode(value);
            }
        }
        for (const auto& [key, value] : extra) {
            if (!value.empty())
                ofs << '&' << urlEncode(key) << '=' << urlEncode(value);
        }
        break;
#ifdef HAS_KEYSHARES
    case KEYSHARE:
        break;
#endif
    }
    LOG_DBG("Generated label: {}", ofs.str());
    return ofs.str();
}

bool
Recipient::validate() const
{
    switch(type) {
        case SYMMETRIC_KEY:
            // Either user-defined label or LABEL property is required
            return !label.empty() || lbl_parts.contains(std::string(CDoc2::Label::LABEL));
        case PUBLIC_KEY:
            // Public key should not be empty
            return !rcpt_key.empty();
#ifdef HAS_KEYSHARES
        case KEYSHARE:
            // S13: the recipient id must be a valid ETSI semantics identifier
            // (PNO<CC>-<digits>, stored without the "etsi/" prefix). A malformed
            // id would only fail late (at the share server) or, worse, bind the
            // shares to a wrong identity.
            return !server_id.empty() && libcdoc::parseEtsiRecipientId("etsi/" + id).valid();
#endif
        default:
            return false;
    }
    return true;
}

} // namespace libcdoc
