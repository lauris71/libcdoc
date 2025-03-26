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

#define __KEYSHARES_CPP__

#include "KeyShares.h"

#include "Crypto.h"
#include "CryptoBackend.h"
#include "NetworkBackend.h"
#include "ILogger.h"
#include "Utils.h"
#include "json/jwt.h"

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include <chrono>
#include <thread>
#include <iostream>

static std::string
toBase64URL(const std::string& data)
{
    return jwt::base::details::encode(data, jwt::alphabet::base64url::data(), "");
}

static std::string
toBase64URL(const std::vector<uint8_t>& data)
{
    return toBase64URL(std::string((const char *) data.data(), data.size()));
}

libcdoc::ShareData::ShareData(const std::string& _base_url, const std::string& _share_id, const std::string& _nonce)
: base_url(_base_url), share_id(_share_id), nonce(_nonce)
{
}

std::string
libcdoc::ShareData::getURL()
{
    return base_url + "key-shares/" + share_id + "?nonce=" + nonce;
}

namespace libcdoc {

/* Helper for JWT signing */
struct JWTSigner {
    Signer *parent;
    JWTSigner(Signer *_parent) : parent(_parent) {}
    std::string sign(const std::string& data, std::error_code& ec) const {
        LOG_DBG("Sign JWT: {}", data);
        std::vector<uint8_t> digest(32);
        SHA256((uint8_t *) data.c_str(), data.size(), digest.data());
        std::vector<uint8_t> dst;
        parent->signDigest(dst, digest);
        return std::string((const char *) dst.data(), dst.size());
    }
    void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {};
    std::string name() const { return parent->algo_name; }
};

struct Disclosure {
    // Disclosure salt (base64url)
    std::string salt64;
    // Disclosure JSON
    std::string json;

    Disclosure(const std::string name, const std::string& val);
    Disclosure(const std::string name, std::vector<Disclosure>& val);

    std::string getSHA256();
};

Disclosure::Disclosure(const std::string name, const std::string& val)
{
    salt64 = toBase64URL(libcdoc::Crypto::random(16));
    //
    // [SALT, HASH]
    // [SALT, NAME, HASH]
    //
    std::vector<picojson::value> v;
    if (name.empty()) {
        v = {
            picojson::value(salt64),
            picojson::value(val)
        };
    } else {
        v = {
            picojson::value(salt64),
            picojson::value(name),
            picojson::value(val)
        };
    }
    json = picojson::value(v).serialize();
}

Disclosure::Disclosure(const std::string name, std::vector<Disclosure>& val)
{
    salt64 = toBase64URL(libcdoc::Crypto::random(16));
    //
    // [SALT, [{..., HASH}, {..., HASH}...]
    // [SALT, NAME, [{..., HASH}, {..., HASH}...]
    //
    std::vector<picojson::value> l;
    for (auto d : val) {
        picojson::object o({
            {"...", picojson::value(d.getSHA256())}
        });
        l.push_back(picojson::value(o));
    }
    std::vector<picojson::value> v;
    if (name.empty()) {
        v = {
            picojson::value(salt64),
            picojson::value(l)
        };
    } else {
        v = {
            picojson::value(salt64),
            picojson::value(name),
            picojson::value(l)
        };
    }
    json = picojson::value(v).serialize();
}

std::string
Disclosure::getSHA256()
{
    std::string b64 = toBase64URL(json);
    std::vector<uint8_t> b(32);
    SHA256((uint8_t *) b64.c_str(), b64.size(), b.data());
    return toBase64URL(b);
}

result_t
Signer::generateTickets(std::vector<std::string>& dst, std::vector<ShareData>& shares)
{
    JWTSigner jwtsig(this);

    // Create list of individual disclosures
    std::vector<Disclosure> disclosures;
    for (auto share : shares) {
        Disclosure d({}, share.getURL());
        LOG_DBG("Disclosure for {}: {}", share.base_url, d.json);
        disclosures.push_back(d);
    }
    // Create disclosure of the whole list
    Disclosure aud("aud", disclosures);
    LOG_DBG("Full disclosure: {}", aud.json);

    // Create and sign JWT container
    picojson::array _sd({picojson::value(aud.getSHA256())});
	std::string token = jwt::create()
						   .set_type("vnd.cdoc2.auth-token.v1+sd-jwt")
                           .set_algorithm(algo_name)
						   .set_payload_claim("iss", picojson::value(rcpt_id))
						   .set_payload_claim("_sd", picojson::value(_sd))
						   .set_payload_claim("_sd_alg", picojson::value("sha-256"))
						   .sign(jwtsig);
    LOG_DBG("Token: {}", token);

    // Append aud disclosure
    std::string jwt = token + "~" + toBase64URL(aud.json);

    // Create individual tickets by appending corresponding disclosures
    for (unsigned int i = 0; i < disclosures.size(); i++) {
        std::string disclosed = jwt + "~" + toBase64URL(disclosures[i].json) + "~";
        dst.push_back(disclosed);
        LOG_DBG("Ticket for {}: {}", shares[i].base_url, disclosed);
    }

    return OK;
}

result_t
SIDSigner::signDigest(std::vector<uint8_t>& dst, const std::vector<uint8_t>& digest)
{
    LOG_DBG("SID signing: {}", toHex(digest));

    network->signSID(dst, cert, url, rp_uuid, rp_name, rcpt_id, digest, libcdoc::CryptoBackend::SHA_256);

    LOG_DBG("SID dignature:{}", toHex(dst));
    LOG_DBG("SID signatureB64:{}", toBase64URL(dst));
    LOG_DBG("SID certificateB64:{}", toBase64(cert));
    
    return OK;
}

result_t
libcdoc::MIDSigner::signDigest(std::vector<uint8_t>& dst, const std::vector<uint8_t>& digest)
{

    LOG_DBG("MID signing: {}", toHex(digest));

    network->signMID(dst, cert, url, rp_uuid, rp_name, phone, rcpt_id, digest, libcdoc::CryptoBackend::SHA_256);

    LOG_DBG("MID signature:{}", toHex(dst));
    LOG_DBG("MID signatureB64:{}", toBase64URL(dst));
    LOG_DBG("MID certificateB64:{}", toBase64(cert));
    
    return OK;
}

} // namespace libcdoc


