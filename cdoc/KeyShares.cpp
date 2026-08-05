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
#include "Utils.h"
#include "json/jwt.h"

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <thread>
#include <iostream>

std::string
libcdoc::ShareData::getURL()
{
    // fixme: Understand where the trailing '/' is dropped
    std::string url = base_url;
    if (!base_url.ends_with('/'))
        url = url + "/";
    url = url +  + "key-shares/" + share_id + "?nonce=" + nonce;
    LOG_DBG("Share URL: {}", url);
    return url;
}

namespace libcdoc {

/* Helper for JWT signing */
struct JWTSigner {
    Signer *parent;
    result_t *result {};

    JWTSigner(Signer *_parent) : parent(_parent) {}
    std::string sign(const std::string& data, std::error_code& ec) const {
        LOG_DBG("Sign JWT: {}", data);
        std::vector<uint8_t> digest(32);
        SHA256((uint8_t *) data.c_str(), data.size(), digest.data());
        std::vector<uint8_t> dst;
        auto rv = parent->signDigest(dst, digest);
        if (result)
            *result = rv;
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
    auto rand_bytes = libcdoc::Crypto::random(16);
    if (rand_bytes.empty()) return;
    salt64 = toBase64URL(rand_bytes);
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
    auto rand_bytes = libcdoc::Crypto::random(16);
    if (rand_bytes.empty()) return;
    salt64 = toBase64URL(rand_bytes);
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
    result_t result = OK;
    jwtsig.result = &result;

    // Create list of individual disclosures
    std::vector<Disclosure> disclosures;
    for (auto share : shares) {
        Disclosure &d = disclosures.emplace_back(std::string{}, share.getURL());
        LOG_DBG("Disclosure for {}: {}", share.base_url, d.json);
    }
    // Create disclosure of the whole list
    Disclosure aud("aud", disclosures);
    LOG_DBG("Full disclosure: {}", aud.json);

    // Create and sign JWT container
    error = {};
    picojson::array _sd({picojson::value(aud.getSHA256())});
	std::string token = jwt::create()
						   .set_type("vnd.cdoc2.auth-token.v1+sd-jwt")
                           .set_algorithm(algo_name)
						   .set_payload_claim("iss", picojson::value(rcpt_id))
						   .set_payload_claim("_sd", picojson::value(_sd))
						   .set_payload_claim("_sd_alg", picojson::value("sha-256"))
						   .sign(jwtsig);
    LOG_DBG("Token: {}", token);
    if (result != OK) {
        LOG_DBG("Jwt signing failed with code {}", result);
        return result;
    }

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
    LOG_TRACE_KEY("SID signing: {}", digest);

    result_t result = network->signSID(dst, cert, params, url, session.token, session.cert, rcpt_id, digest, libcdoc::CryptoBackend::SHA_256);
    if (result != OK) {
        error = network->getLastErrorStr(result);
    }

    LOG_DBG("SID signature:{}", toHex(dst));
    LOG_DBG("SID signatureB64:{}", toBase64URL(dst));
    LOG_DBG("SID certificateB64:{}", toBase64(cert));
    
    return result;
}

result_t
MIDSigner::signDigest(std::vector<uint8_t>& dst, const std::vector<uint8_t>& digest)
{

    LOG_TRACE_KEY("MID signing: {}", digest);

    result_t result = network->signMID(dst, cert, url, rp_uuid, rp_name, phone, rcpt_id, digest, libcdoc::CryptoBackend::SHA_256);
    if (result != OK) {
        error = network->getLastErrorStr(result);
    }

    LOG_DBG("MID signature:{}", toHex(dst));
    LOG_DBG("MID signatureB64:{}", toBase64URL(dst));
    LOG_DBG("MID certificateB64:{}", toBase64(cert));
    
    return result;
}

SessionToken::SessionToken(std::string_view str)
{
    auto parts = split(str, '~');
    if (parts.size() > 2) {
        jwt = parts[0];
        aud = parts[1];
        for (size_t i = 2; i < parts.size(); i++) {
            disclosures.push_back(parts[i]);
        }
    }
}

// Extract the target URL from a base64url-encoded SD-JWT disclosure.
// Returns an empty string if the disclosure is malformed. Never throws:
// fromBase64URL throws on malformed base64 until the S2 fix lands, and a
// malformed (server-issued) disclosure must not crash the process.
static std::string
disclosureTargetUrl(const std::string& disclosure)
{
    std::vector<uint8_t> decoded_part;
    try {
        decoded_part = fromBase64URL(disclosure);
    } catch (const std::exception &) {
        return {};
    }
    std::string json_str(decoded_part.begin(), decoded_part.end());
    picojson::value json;
    if (!picojson::parse(json, json_str).empty())
        return {};
    if (!json.is<picojson::array>())
        return {};
    picojson::array arr = json.get<picojson::array>();
    if (arr.size() < 2 || !arr[1].is<std::string>())
        return {};
    return arr[1].get<std::string>();
}

std::string
SessionToken::discloseForUrl(std::string_view url)
{
    LOG_DBG("Building token for: {}", url);
    for (auto& d : disclosures) {
        std::string target_url = disclosureTargetUrl(d);
        if (target_url.empty()) continue;
        if (target_url.find(url) != std::string::npos) {
            std::string token = jwt + "~" + aud + "~" + d + "~";
            LOG_DBG("Disclosed token: {}", token);
            return token;
        }
    }
    return {};
}

bool
SessionToken::hasDisclosureForUrl(std::string_view url)
{
    // Compare origins (scheme, host, port): the disclosure authorizes a
    // share server, and the credential-theft risk (S1) is about the session
    // token and user certificate being sent to a different host. Origin
    // comparison is robust against trailing-slash and path variations.
    // parseURL also rejects non-https URLs, so a disclosure or share URL
    // with a plain-http scheme never matches.
    std::string host, path;
    int port = 0;
    if (parseURL(std::string(url), host, port, path) != OK)
        return false;
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    for (const auto& d : disclosures) {
        std::string target = disclosureTargetUrl(d);
        if (target.empty())
            continue;
        std::string dhost, dpath;
        int dport = 0;
        if (parseURL(target, dhost, dport, dpath) != OK)
            continue;
        std::transform(dhost.begin(), dhost.end(), dhost.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (host == dhost && port == dport) {
            LOG_DBG("Server {} is authorized by a session disclosure", url);
            return true;
        }
    }
    LOG_WARN("No session disclosure authorizes server {}", url);
    return false;
}

std::string
decodeTicket(const std::string& ticket)
{
    auto decoded = jwt::decode(ticket);
    auto a = decoded.get_header_json();
    for (auto t : a) {
        LOG_DBG("Header {}: {}", t.first, t.second.to_str());
    }
    a = decoded.get_payload_json();
    for (auto t : a) {
        LOG_DBG("Payload {}: {}", t.first, t.second.to_str());
    }
    auto b = decoded.get_signature();
    LOG_DBG("Signature: {}", b);
    return picojson::value(decoded.get_payload_json()).serialize();
}

} // namespace libcdoc


