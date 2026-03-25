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

/**
 * @brief Prefix with what starts machine generated Lock's label.
 */
constexpr string_view LABELPREFIX{"data:"};

/**
 * @brief String after label prefix indicating, the rest of the label is Base64 encoded.
 */
constexpr string_view LABELBASE64IND{";base64,"};

/**
 * @brief EID type values for machine-readable label
 */
static constexpr std::string_view eid_strs[] = {
    "Unknown",
    "ID-card",
    "Digi-ID",
    "Digi-ID E-RESIDENT"
};

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
buildLabel(std::ostream& ofs, std::string_view type, std::initializer_list<std::pair<std::string_view, std::string_view>> components)
{
    ofs << LABELPREFIX;
    ofs << "v" << '=' << std::to_string(CDoc2::KEYLABELVERSION) << '&'
        << "type" << '=' << type;
    for (const auto& [key, value] : components) {
        if (!value.empty())
            ofs << '&' << urlEncode(key) << '=' << urlEncode(value);
    }
}

static void
BuildLabelEID(std::ostream& ofs, Certificate::EIDType type, const Certificate& x509)
{
    buildLabel(ofs, eid_strs[type], {
        {"cn", x509.getCommonName()},
        {"serial_number", x509.getSerialNumber()},
        {"last_name", x509.getSurname()},
        {"first_name", x509.getGivenName()},
    });
}

static void
BuildLabelCertificate(std::ostream &ofs, const std::string& file, const Certificate& x509)
{
    buildLabel(ofs, "cert", {
        {"file", file},
        {"cn", x509.getCommonName()},
        {"cert_sha1", toHex(x509.getDigest())}
    });
}

static void
BuildLabelPublicKey(std::ostream &ofs, const std::string& file)
{
    buildLabel(ofs, "pub_key", {
        {"file", file}
    });
}

static void
BuildLabelSymmetricKey(std::ostream &ofs, const std::string& label, const std::string& file)
{
    buildLabel(ofs, "secret", {
        {"label", label},
        {"file", file}
    });
}

static void
BuildLabelPassword(std::ostream &ofs, const std::string& label)
{
    buildLabel(ofs, "pw", {
        {"label", label}
    });
}

std::string
Recipient::getLabel(const std::vector<std::pair<std::string_view, std::string_view>> &extra) const
{
    LOG_DBG("Generating label");
    if (!label.empty()) return label;
    std::ostringstream ofs;
    switch(type) {
        case NONE:
            LOG_DBG("The recipient is not initialized");
            break;
        case SYMMETRIC_KEY:
            if (kdf_iter > 0) {
                BuildLabelPassword(ofs, key_name);
            } else {
                BuildLabelSymmetricKey(ofs, key_name, file_name);
            }
            break;
        case PUBLIC_KEY:
            if (!cert.empty()) {
                Certificate x509(cert);
                if (auto eid = x509.getEIDType(); eid != Certificate::Unknown) {
                    BuildLabelEID(ofs, eid, x509);
                } else {
                    BuildLabelCertificate(ofs, file_name, x509);
                }
            } else {
                BuildLabelPublicKey(ofs, file_name);
            }
            break;
        case KEYSHARE:
            break;
    }
    for (const auto& [key, value] : extra) {
        if (!value.empty())
            ofs << '&' << urlEncode(key) << '=' << urlEncode(value);
    }
    LOG_DBG("Generated label: {}", ofs.str());
    return ofs.str();
}

map<string, string> Recipient::parseLabel(const string& label)
{
    map<string, string> parsed_label;
    // Check if provided label starts with the machine generated label prefix.
    if (!label.starts_with(LABELPREFIX))
    {
        return parsed_label;
    }

    string label_wo_prefix(label.substr(LABELPREFIX.size()));

    // Label to be processed
    string label_to_prcss;

    // We ignore mediatype part

    // Check, if the label is Base64 encoded
    string::size_type base64IndPos = label_wo_prefix.find(LABELBASE64IND);
    if (base64IndPos == string::npos)
    {
        if (label_wo_prefix.starts_with(",")) {
            label_to_prcss = label_wo_prefix.substr(1);
        } else {
            label_to_prcss = std::move(label_wo_prefix);
        }
    }
    else
    {
        string base64_label(label_wo_prefix.substr(base64IndPos + LABELBASE64IND.size()));
        vector<uint8_t> decodedLabel(fromBase64(base64_label));
        label_to_prcss.assign(decodedLabel.cbegin(), decodedLabel.cend());
    }

    vector<string> label_parts(split(label_to_prcss, '&'));
    for (vector<string>::const_reference part : label_parts)
    {
        vector<string> label_data_parts(split(part, '='));
        if (label_data_parts.size() != 2)
        {
            // Invalid label data. We just ignore them.
            LOG_ERROR("The label '{}' is invalid", label);
        }
        else
        {
            std::string key = urlDecode(label_data_parts[0]);
            std::string value = urlDecode(label_data_parts[1]);
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
            parsed_label[key] = value;
        }
    }

    return parsed_label;
}

} // namespace libcdoc

