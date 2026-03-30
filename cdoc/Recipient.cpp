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
#include "Utils.h"

#include <algorithm>
#include <chrono>

using namespace std;

namespace libcdoc {

Recipient
Recipient::makeSymmetric(std::string label, int32_t kdf_iter)
{
	Recipient rcpt(Type::SYMMETRIC_KEY);
	rcpt.label = std::move(label);
	rcpt.kdf_iter = kdf_iter;
	return rcpt;
}

Recipient
Recipient::makePublicKey(std::string label, std::vector<uint8_t> public_key, PKType pk_type)
{
    if (public_key.empty())
        return {Type::NONE};
    Recipient rcpt(Type::PUBLIC_KEY);
    rcpt.label = std::move(label);
    rcpt.pk_type = pk_type;
    if (pk_type == PKType::ECC && public_key[0] == 0x30) {
        // 0x30 identifies SEQUENCE tag in ASN.1 encoding
        auto evp = Crypto::fromECPublicKeyDer(public_key);
        rcpt.rcpt_key = Crypto::toPublicKeyDer(evp.get());
    } else {
        rcpt.rcpt_key = std::move(public_key);
    }
	return rcpt;
}

Recipient
Recipient::makeCertificate(std::string label, std::vector<uint8_t> cert)
{
    Certificate x509(cert);
    if (!x509)
        return {Type::NONE};
    Recipient rcpt(Type::PUBLIC_KEY);
    rcpt.label = std::move(label);
    rcpt.cert = std::move(cert);
    rcpt.rcpt_key = x509.getPublicKey();
    rcpt.pk_type = (x509.getAlgorithm() == libcdoc::Certificate::RSA) ? PKType::RSA : PKType::ECC;
    rcpt.expiry_ts = x509.getNotAfter();
    return rcpt;
}

Recipient
Recipient::makeServer(std::string label, std::vector<uint8_t> public_key, PKType pk_type, std::string server_id)
{
    Recipient rcpt = makePublicKey(std::move(label), std::move(public_key), pk_type);
    rcpt.server_id = std::move(server_id);
    const auto six_months_from_now = std::chrono::system_clock::now() + std::chrono::months(6);
    const auto expiry_ts = std::chrono::system_clock::to_time_t(six_months_from_now);
    rcpt.expiry_ts = uint64_t(expiry_ts);
    return rcpt;
}

Recipient
Recipient::makeServer(std::string label, std::vector<uint8_t> cert, std::string server_id)
{
    Recipient rcpt = makeCertificate(std::move(label), std::move(cert));
    rcpt.server_id = std::move(server_id);
    const auto six_months_from_now = std::chrono::system_clock::now() + std::chrono::months(6);
    const auto expiry_ts = std::chrono::system_clock::to_time_t(six_months_from_now);
    rcpt.expiry_ts = std::min(rcpt.expiry_ts, uint64_t(expiry_ts)); 
    return rcpt;
}

Recipient
Recipient::makeShare(std::string label, std::string server_id, std::string recipient_id)
{
    Recipient rcpt(Type::KEYSHARE);
    rcpt.label = std::move(label);
    rcpt.server_id = std::move(server_id);
    rcpt.id = std::move(recipient_id);
    return rcpt;
}

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

static void
buildLabel(std::ostream& ofs, std::string_view type, const std::map<std::string_view,std::string_view> lbl_parts, std::initializer_list<std::pair<std::string_view, std::string_view>> extra)
{
    auto parts = lbl_parts;
    if (parts.contains("v"))
        parts.erase("v");
    if (parts.contains("type"))
        parts.erase("type");
    for (const auto& [key, value] : extra) {
        if (!value.empty())
            parts[key] = value;
    }
    ofs << CDoc2::LABELPREFIX;
    ofs << CDoc2::Label::VERSION << '=' << std::to_string(CDoc2::KEYLABELVERSION) << '&'
        << CDoc2::Label::TYPE << '=' << type;
    for (const auto& [key, value] : parts) {
        if (!value.empty())
            ofs << '&' << urlEncode(key) << '=' << urlEncode(value);
    }
}

static void
BuildLabelEID(std::ostream& ofs, Certificate::EIDType type, const Certificate& x509, const std::map<std::string_view,std::string_view>& lbl_parts)
{
    
    buildLabel(ofs, CDoc2::eid_strs[type], lbl_parts, {
        {CDoc2::Label::CN, x509.getCommonName()},
        {CDoc2::Label::SERIAL_NUMBER, x509.getSerialNumber()},
        {CDoc2::Label::LAST_NAME, x509.getSurname()},
        {CDoc2::Label::FIRST_NAME, x509.getGivenName()},
    });
}

static void
BuildLabelCertificate(std::ostream &ofs, const Certificate& x509, const std::map<std::string_view,std::string_view>& lbl_parts)
{
    buildLabel(ofs, CDoc2::Label::TYPE_CERTIFICATE, lbl_parts, {
        {CDoc2::Label::CN, x509.getCommonName()},
        {CDoc2::Label::CERT_SHA1, toHex(x509.getDigest())}
    });
}

std::string
Recipient::getLabel(const std::vector<std::pair<std::string_view, std::string_view>> &extra) const
{
    LOG_DBG("Generating label");
    if (!label.empty()) return label;
    std::map<std::string_view,std::string_view> parts;
    for (const auto& [key, value] : lbl_parts) {
        if (!value.empty())
            parts[key] = value;
    }
    for (const auto& [key, value] : extra) {
        if (!value.empty())
            parts[key] = value;
    }
    std::ostringstream ofs;
    switch(type) {
        case NONE:
            LOG_DBG("The recipient is not initialized");
            break;
        case SYMMETRIC_KEY:
            if (kdf_iter > 0) {
                buildLabel(ofs, CDoc2::Label::TYPE_PASSWORD, parts, {});
            } else {
                buildLabel(ofs, CDoc2::Label::TYPE_SYMMETRIC, parts, {});
            }
            break;
        case PUBLIC_KEY:
            if (!cert.empty()) {
                Certificate x509(cert);
                if (auto eid = x509.getEIDType(); eid != Certificate::Unknown) {
                    BuildLabelEID(ofs, eid, x509, parts);
                } else {
                    BuildLabelCertificate(ofs, x509, parts);
                }
            } else {
                buildLabel(ofs, CDoc2::Label::TYPE_PUBLIC_KEY, parts, {});
            }
            break;
        case KEYSHARE:
            break;
    }
    LOG_DBG("Generated label: {}", ofs.str());
    return ofs.str();
}

} // namespace libcdoc

