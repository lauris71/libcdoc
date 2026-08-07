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

    result_t result = network->signMID(dst, cert, params, url, phone, session.token, session.cert, rcpt_id, digest, libcdoc::CryptoBackend::SHA_256);
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
// Returns an empty string if the disclosure is malformed (fromBase64URL is
// non-throwing; a malformed server-issued disclosure must not crash the
// process).
static std::string
disclosureTargetUrl(const std::string& disclosure)
{
    std::vector<uint8_t> decoded_part = fromBase64URL(disclosure);
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

// Compare two URLs by origin (scheme, host, port). Used for SD-JWT
// disclosure binding (S7): a disclosure authorizes exactly one server, so
// substring matching is not acceptable - a disclosure for
// share.example.com.evil.ee must not match share.example.com, and a short
// query URL must not over-match many disclosures. Origin comparison is
// robust against trailing-slash and path variations (session-token
// disclosures carry the nonce on the path). parseURL enforces the https
// scheme on both sides, so plain-http never matches. Host comparison is
// case-insensitive.
static bool
urlsMatchByOrigin(std::string_view a, std::string_view b)
{
    std::string ahost, apath, bhost, bpath;
    int aport = 0, bport = 0;
    if (parseURL(std::string(a), ahost, aport, apath) != OK)
        return false;
    if (parseURL(std::string(b), bhost, bport, bpath) != OK)
        return false;
    std::transform(ahost.begin(), ahost.end(), ahost.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::transform(bhost.begin(), bhost.end(), bhost.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return ahost == bhost && aport == bport;
}

std::string
SessionToken::discloseForUrl(std::string_view url)
{
    LOG_DBG("Building token for: {}", url);
    for (auto& d : disclosures) {
        std::string target_url = disclosureTargetUrl(d);
        if (target_url.empty()) continue;
        if (urlsMatchByOrigin(target_url, url)) {
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
    for (const auto& d : disclosures) {
        std::string target = disclosureTargetUrl(d);
        if (!target.empty() && urlsMatchByOrigin(target, url)) {
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
    // jwt::decode throws on malformed input; the ticket comes from a remote
    // server, so a decode failure must not crash the process. An empty result
    // makes the caller's JSON parse step report the format error.
    try {
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
    } catch (const std::exception &e) {
        LOG_WARN("decodeTicket: invalid JWT: {}", e.what());
        return {};
    }
}


std::string
buildAcspV2Payload(const std::string& scheme_name, const std::string& server_random,
                            const std::string& rp_challenge, const std::string& user_challenge,
                            const std::string& rp_name, const std::string& interactions_digest,
                            const std::string& interaction_type_used, const std::string& flow_type)
{
    // schemeName|ACSP_V2|serverRandom|rpChallenge|userChallenge|base64(rpName)||
    // interactionsDigest|interactionTypeUsed||flowType
    // (brokeredRpNameBase64 and initialCallbackUrl are always empty here)
    std::string rp_name64 = toBase64((const uint8_t *) rp_name.data(), rp_name.size());
    return scheme_name + "|ACSP_V2|" + server_random + "|" + rp_challenge + "|" + user_challenge
        + "|" + rp_name64 + "||" + interactions_digest + "|" + interaction_type_used + "||" + flow_type;
}

libcdoc::result_t
validateSessionData(CryptoBackend *crypto, const std::string& rcpt_id, bool is_mid,
                             const std::string& session_token, const std::string& session_cert_b64,
                             std::string& scheme_name, std::string& rp_name, std::string& error)
{
    if (!crypto) {
        error = "No crypto backend";
        return CryptoBackend::INVALID_PARAMS;
    }
    // The session certificate belongs to the person the session authenticated;
    // it must match the container recipient (base64url per the auth server spec).
    std::vector<uint8_t> cert_der = fromBase64URL(session_cert_b64);
    if (cert_der.empty()) {
        error = "Invalid session certificate";
        return DATA_FORMAT_ERROR;
    }
    if (auto rv = crypto->validateCertificate(rcpt_id, cert_der); rv != OK) {
        error = FORMAT("Session certificate does not match recipient {}", rcpt_id);
        return rv;
    }
    // Session token claims: expiry (fail fast; servers are authoritative) and
    // the schemeName/rpName needed to reconstruct the ACSP_V2 payload.
    SessionToken stoken(session_token);
    std::string payload = decodeTicket(stoken.jwt);
    picojson::value json;
    if (!picojson::parse(json, payload).empty() || !json.is<picojson::object>()) {
        error = "Invalid session token";
        return DATA_FORMAT_ERROR;
    }
    if (json.get("exp").is<double>() && json.get("exp").get<double>() < libcdoc::getTime()) {
        error = "Session token is expired";
        return NetworkBackend::NETWORK_ERROR;
    }
    scheme_name = json.get("schemeName").is<std::string>() ? json.get("schemeName").get<std::string>() : std::string();
    rp_name = json.get("rpName").is<std::string>() ? json.get("rpName").get<std::string>() : std::string();
    if (!is_mid && (scheme_name.empty() || rp_name.empty())) {
        error = "Session token misses schemeName/rpName claims";
        return DATA_FORMAT_ERROR;
    }
    return OK;
}

libcdoc::result_t
validateAuthTicket(CryptoBackend *crypto, const std::string& rcpt_id,
                            const std::string& ticket, const std::vector<uint8_t>& cert_der,
                            const std::string& signature_params_json,
                            const std::string& scheme_name, const std::string& rp_name,
                            std::string& error)
{
    if (!crypto) {
        error = "No crypto backend";
        return CryptoBackend::INVALID_PARAMS;
    }
    // Signing certificate identity must match the container recipient.
    if (auto rv = crypto->validateCertificate(rcpt_id, cert_der); rv != OK) {
        error = FORMAT("Signing certificate does not match recipient {}", rcpt_id);
        return rv;
    }

    // The signed part of the ticket JWT is header64.payload64.sig64
    auto parts = split(ticket, '~');
    if (parts.empty()) {
        error = "Invalid ticket";
        return DATA_FORMAT_ERROR;
    }
    auto jwt_parts = split(parts[0], '.');
    if (jwt_parts.size() != 3) {
        error = "Invalid ticket JWT";
        return DATA_FORMAT_ERROR;
    }
    std::string signing_input = jwt_parts[0] + "." + jwt_parts[1];
    std::vector<uint8_t> signature = fromBase64URL(jwt_parts[2]);
    if (signature.empty()) {
        error = "Invalid ticket signature";
        return DATA_FORMAT_ERROR;
    }

    // The rpChallenge sent to the RP server is base64(SHA256(signing input))
    std::vector<uint8_t> digest(32);
    SHA256(reinterpret_cast<uint8_t *>(signing_input.data()), signing_input.size(), digest.data());
    std::string rp_challenge = toBase64(digest);

    // ACSP_V2 parameters returned by the RP server
    picojson::value json;
    if (!picojson::parse(json, signature_params_json).empty() || !json.is<picojson::object>()) {
        error = "Invalid signature parameters";
        return DATA_FORMAT_ERROR;
    }
    auto getStr = [](const picojson::value& obj, const char *key) -> std::string {
        picojson::value v = obj.get(key);
        return v.is<std::string>() ? v.get<std::string>() : std::string();
    };
    picojson::value sig = json.get("signature");
    if (!sig.is<picojson::object>()) {
        error = "Missing ACSP_V2 signature parameters";
        return DATA_FORMAT_ERROR;
    }
    std::string server_random = getStr(sig, "serverRandom");
    std::string user_challenge = getStr(sig, "userChallenge");
    std::string flow_type = getStr(sig, "flowType");
    std::string interactions_digest = getStr(json, "interactionsDigest");
    std::string interaction_type = getStr(json, "interactionTypeUsed");
    if (server_random.empty() || user_challenge.empty() || flow_type.empty()
        || interactions_digest.empty() || interaction_type.empty()) {
        error = "Missing ACSP_V2 signature parameters";
        return DATA_FORMAT_ERROR;
    }

    std::string payload = buildAcspV2Payload(scheme_name, server_random, rp_challenge, user_challenge,
                                             rp_name, interactions_digest, interaction_type, flow_type);
    if (!Crypto::validateSignature(cert_der, {payload.cbegin(), payload.cend()}, signature,
                                   Crypto::SignatureAlgorithm::RSASSA_PSS_SHA256)) {
        error = "Auth ticket signature verification failed";
        return CRYPTO_ERROR;
    }
    return OK;
}

} // namespace libcdoc



