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

#include "NetworkBackend.h"

#include "Certificate.h"
#include "Crypto.h"
#include "CryptoBackend.h"
#include "Utils.h"
#include "KeyShares.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/bio.h>
#include <openssl/http.h>
#include <openssl/ssl.h>

#include "json/picojson/picojson.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include <chrono>

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#endif

#define CDOC_SSL_TIMEOUT 30

using namespace std::literals::chrono_literals;

using EC_KEY_sign = int (*)(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
using EC_KEY_sign_setup = int (*)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);

static ECDSA_SIG* ecdsa_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey);
static int rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const ::RSA *rsa);

struct Private {
    libcdoc::Certificate x509;
    EVP_PKEY *pkey = nullptr;

    RSA_METHOD *rsamethod = nullptr;
    EC_KEY_METHOD *ecmethod = nullptr;

    explicit Private(libcdoc::NetworkBackend *backend, const std::vector<uint8_t> &client_cert)
        : x509(client_cert)
    {
        if (!x509) return;
        pkey = X509_get_pubkey(x509.handle());
        if (!pkey) return;
        int id = EVP_PKEY_get_id(pkey);
        if (id == EVP_PKEY_EC) {
            ecmethod = EC_KEY_METHOD_new(EC_KEY_get_default_method());
            EC_KEY_sign sign = nullptr;
            EC_KEY_sign_setup sign_setup = nullptr;
            EC_KEY_METHOD_get_sign(ecmethod, &sign, &sign_setup, nullptr);
            EC_KEY_METHOD_set_sign(ecmethod, sign, sign_setup, ecdsa_do_sign);

            auto *ec = (EC_KEY *) EVP_PKEY_get1_EC_KEY(pkey);
            EC_KEY_set_method(ec, ecmethod);
            EC_KEY_set_ex_data(ec, 0, backend);
            EVP_PKEY_set1_EC_KEY(pkey, ec);
        } else if (id == EVP_PKEY_RSA) {
            rsamethod = RSA_meth_dup(RSA_get_default_method());
            RSA_meth_set1_name(rsamethod, "libcdoc");
            RSA_meth_set_sign(rsamethod, rsa_sign);

            RSA *rsa = (RSA *) EVP_PKEY_get1_RSA(pkey);
            RSA_set_method(rsa, rsamethod);
            RSA_set_ex_data(rsa, 0, backend);
            EVP_PKEY_set1_RSA(pkey, rsa);
        }
    }

    ~Private() {
        if (pkey) EVP_PKEY_free(pkey);
        if (rsamethod) RSA_meth_free(rsamethod);
        if (ecmethod) EC_KEY_METHOD_free(ecmethod);
    }
};

#ifdef HAS_KEYSHARES
struct MIDSIDResultData {
    int code;
    std::string_view str;
    std::string_view desc;
};

static constexpr auto midsid_results = std::to_array<MIDSIDResultData>({
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED, "USER_REFUSED", "User refused the session"},
    {libcdoc::NetworkBackend::MIDSID_TIMEOUT, "TIMEOUT", "User did not confirm action within the timeframe"},
    {libcdoc::NetworkBackend::MIDSID_DOCUMENT_UNUSABLE, "DOCUMENT_UNUSABLE", "Document unusable, please contact Smart ID customer support"},
    {libcdoc::NetworkBackend::MIDSID_WRONG_VC, "WRONG_VC", "User chose a wrong Smart ID verification code"},
    {libcdoc::NetworkBackend::MIDSID_REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP, "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP", "Smart ID app does not support current protocol"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_CERT_CHOICE, "USER_REFUSED_CERT_CHOICE", "User refused certificate choice"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_INTERACTION, "USER_REFUSED_INTERACTION", "User refused the interaction"},
    {libcdoc::NetworkBackend::MIDSID_PROTOCOL_FAILURE, "PROTOCOL_FAILURE", "There was a logical error in the signing protocol"},
    {libcdoc::NetworkBackend::MIDSID_EXPECTED_LINKED_SESSION, "EXPECTED_LINKED_SESSION", "The app received a different transaction while waiting for the linked session"},
    {libcdoc::NetworkBackend::MIDSID_SERVER_ERROR, "SERVER_ERROR", "The process was terminated due to server-side technical error"},
    {libcdoc::NetworkBackend::ACCOUNT_UNUSABLE, "ACCOUNT_UNUSABLE", "The account is currently unusable"},
    // Old
    {libcdoc::NetworkBackend::MIDSID_NOT_MID_CLIENT, "NOT_MID_CLIENT", "user has no active Mobile-ID certificates"},
    {libcdoc::NetworkBackend::MIDSID_USER_CANCELLED, "USER_CANCELLED", "user rejected the operation on the device"},
    {libcdoc::NetworkBackend::MIDSID_SIGNATURE_HASH_MISMATCH, "SIGNATURE_HASH_MISMATCH", "mismatch between SIM and service provider configuration"},
    {libcdoc::NetworkBackend::MIDSID_PHONE_ABSENT, "PHONE_ABSENT", "SIM card is not available"},

    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_DISPLAYTEXTANDPIN, "USER_REFUSED_DISPLAYTEXTANDPIN", "User canceled the PIN choice"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_VC_CHOICE, "USER_REFUSED_VC_CHOICE", "User canceled the verification code choice"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_CONFIRMATIONMESSAGE, "USER_REFUSED_CONFIRMATIONMESSAGE", "User refused the confirmation message"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE, "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE", "User refused the confirmation message and verification code choice"},
    {libcdoc::NetworkBackend::MIDSID_DELIVERY_ERROR, "DELIVERY_ERROR", "SMS sending error"},
    {libcdoc::NetworkBackend::MIDSID_SIM_ERROR, "SIM_ERROR", "Invalid response from SIM card"}
});

static libcdoc::result_t
parseMIDSIDResult(std::string_view str)
{
    if (str == "OK") return libcdoc::OK;
    for (auto v : midsid_results) {
        if (str == v.str) return v.code;
    }
    return libcdoc::UNSPECIFIED_ERROR;
}

static std::string_view
getMIDSIDDescription(libcdoc::result_t code)
{
    for (auto v : midsid_results) {
        if (code == v.code) return v.desc;
    }
    return {};
}

// Map a CryptoBackend::HashAlgorithm to the algorithm name string the
// SK Smart-ID / Mobile-ID JSON API expects ("SHA224", "SHA256",
// "SHA384", "SHA512"). Returns an empty string_view when the algorithm
// is not in the supported set; callers MUST treat that as a hard error
// rather than indexing an array - foreign-language bindings (SWIG / Java
// / C#) and any future addition to the HashAlgorithm enum can otherwise
// drive the previous `algo_names[(int)algo]` lookup out of bounds.
//
// The function is constexpr so that the static_assert block below can
// verify at compile time that every documented enumerator maps to a
// non-empty string. Any new HashAlgorithm value added to CryptoBackend.h
// will trigger -Wswitch (no default branch covers it) and the
// static_asserts will catch it explicitly.
static constexpr std::string_view
hashAlgorithmToSidName(libcdoc::CryptoBackend::HashAlgorithm algo) noexcept
{
    switch (algo) {
    case libcdoc::CryptoBackend::HashAlgorithm::SHA_256: return "SHA-256";
    case libcdoc::CryptoBackend::HashAlgorithm::SHA_384: return "SHA-384";
    case libcdoc::CryptoBackend::HashAlgorithm::SHA_512: return "SHA-512";
    default:
        break;
    }
    return {};
}

static_assert(hashAlgorithmToSidName(libcdoc::CryptoBackend::HashAlgorithm::SHA_256) == "SHA-256");
static_assert(hashAlgorithmToSidName(libcdoc::CryptoBackend::HashAlgorithm::SHA_384) == "SHA-384");
static_assert(hashAlgorithmToSidName(libcdoc::CryptoBackend::HashAlgorithm::SHA_512) == "SHA-512");
// Out-of-range value (e.g. coming from a SWIG-generated foreign caller)
// must produce an empty result rather than reading past the array.
static_assert(hashAlgorithmToSidName(static_cast<libcdoc::CryptoBackend::HashAlgorithm>(99)).empty());

static constexpr std::string_view
hashAlgorithmToMidName(libcdoc::CryptoBackend::HashAlgorithm algo) noexcept
{
    switch (algo) {
    case libcdoc::CryptoBackend::HashAlgorithm::SHA_256: return "SHA256";
    case libcdoc::CryptoBackend::HashAlgorithm::SHA_384: return "SHA384";
    case libcdoc::CryptoBackend::HashAlgorithm::SHA_512: return "SHA512";
    default:
        break;
    }
    return {};
}
#endif

thread_local std::string error;

static std::string
getJsonString(const picojson::value& json, const std::string& key, libcdoc::result_t& result)
{
    error = {};
    // picojson::value::get(key) throws std::runtime_error if json is not an
    // object - check first, the input comes from a remote server.
    if (!json.is<picojson::object>()) {
        error = FORMAT("{} is missing (the response is not a JSON object)", key);
        LOG_WARN("{}", error);
        result = libcdoc::DATA_FORMAT_ERROR;
        return {};
    }
    picojson::value v = json.get(key);
    if (!v.is<std::string>()) {
        error = FORMAT("{} is missing or is not a string", key);
        LOG_WARN("{}", error);
        result = libcdoc::DATA_FORMAT_ERROR;
        return {};
    }
    result = libcdoc::OK;
    return v.get<std::string>();
}

static picojson::object
getJsonObject(const picojson::value& json, const std::string& key, libcdoc::result_t& result)
{
    error = {};
    // picojson::value::get(key) throws std::runtime_error if json is not an
    // object - check first, the input comes from a remote server.
    if (!json.is<picojson::object>()) {
        error = FORMAT("{} is missing (the response is not a JSON object)", key);
        LOG_WARN("{}", error);
        result = libcdoc::DATA_FORMAT_ERROR;
        return {};
    }
    picojson::value v = json.get(key);
    if (!v.is<picojson::object>()) {
        error = FORMAT("{} is missing or is not an object", key);
        LOG_WARN("{}", error);
        result = libcdoc::DATA_FORMAT_ERROR;
        return {};
    }
    result = libcdoc::OK;
    return v.get<picojson::object>();
}

std::string
libcdoc::NetworkBackend::getLastErrorStr(result_t code) const
{
    if (!error.empty()) return error;
	switch (code) {
    case OK:
        return {};
	case NETWORK_ERROR:
		return "NetworkBackend: Network error";
	default:
		break;
	}
#ifdef HAS_KEYSHARES
    std::string_view str = getMIDSIDDescription(code);
    if (!str.empty()) return std::string(str);
#endif
   return libcdoc::getErrorStr(code);
}

//
// Set peer certificate(s) for given server url
//
static libcdoc::result_t
setPeerCertificates(httplib::SSLClient& cli, libcdoc::NetworkBackend *network, const std::string& url)
{
    std::vector<std::vector<uint8_t>> certs;
    libcdoc::result_t result = network->getPeerTLSCertificates(certs, url);
    if (result != libcdoc::OK) {
        error = FORMAT("Cannot get peer certificate list: {}", result);
        return result;
    }
    libcdoc::LOG_DBG("Num TLS certs {}", certs.size());
    if (!certs.empty()) {
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            libcdoc::Certificate x509(c);
            if (!x509) return libcdoc::CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.handle());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    }
    else {
#ifdef LIBCDOC_ALLOW_INSECURE_TLS
        LOG_WARN("TLS certificate verification disabled (LIBCDOC_ALLOW_INSECURE_TLS)");
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
#else
        error = "No peer TLS certificates configured";
        return libcdoc::CONFIGURATION_ERROR;
#endif
    }
    return libcdoc::OK;
}

//
// Set proxy parameters
//
static libcdoc::result_t
setProxy(httplib::SSLClient& cli, libcdoc::NetworkBackend *network)
{
    libcdoc::NetworkBackend::ProxyCredentials cred;
    switch (auto result = network->getProxyCredentials(cred)) {
    case libcdoc::NOT_IMPLEMENTED:
        return libcdoc::OK;
    case libcdoc::OK:
        if (!cred.host.empty()) {
            cli.set_proxy(cred.host, cred.port);
        }
        if (!cred.username.empty()) {
            cli.set_proxy_basic_auth(cred.username, cred.password);
        }
        return libcdoc::OK;
    default: return result;
    }
}

//
// Set SSL timeouts
//
static libcdoc::result_t
applySSLTimeout(httplib::SSLClient& cli, libcdoc::NetworkBackend *network)
{
    cli.set_connection_timeout(CDOC_SSL_TIMEOUT);
    cli.set_read_timeout(CDOC_SSL_TIMEOUT);
    cli.set_write_timeout(CDOC_SSL_TIMEOUT);
    return libcdoc::OK;
}

//
// Post request and fetch response
//
static libcdoc::result_t
post(httplib::SSLClient& cli, const std::string& path, httplib::Headers& hdrs, const std::string& req, httplib::Response& rsp)
{
    // Capture TLS and HTTP errors
    LOG_DBG("POST: {}", path);
    LOG_TRACE("  Body: {}", req);
    for (auto h : hdrs) {
        LOG_TRACE("    Header {}: {}", h.first, h.second);
    }
    httplib::Result res = cli.Post(path, hdrs, req, "application/json");
    if (!res) {
        error = FORMAT("Cannot connect to https://{}:{}{}", cli.host(), cli.port(), path);
        return libcdoc::NetworkBackend::NETWORK_ERROR;
    }
    int status = res->status;
    LOG_DBG("Status: {}", status);
    LOG_TRACE("  Body: {}", res->body);
    for (auto h : res->headers) {
        LOG_TRACE("    Header {}: {}", h.first, h.second);
    }
    if ((status < 200) || (status >= 300)) {
        error = FORMAT("Http status {}", status);
        return libcdoc::NetworkBackend::NETWORK_ERROR;
    }
    rsp = res.value();
    error = {};
    return libcdoc::OK;
}

//
// Get url and fetch JSON response
//
static libcdoc::result_t
get(httplib::SSLClient& cli, httplib::Headers& hdrs, const std::string& path, httplib::Response& rsp)
{
    // Capture TLS and HTTP errors
    LOG_DBG("GET: {}", path);
    for (auto h : hdrs) {
        LOG_TRACE("    Header {}: {}", h.first, h.second);
    }
    httplib::Result res = cli.Get(path, hdrs);
    if (!res) {
        error = FORMAT("Cannot connect to https://{}:{}{}", cli.host(), cli.port(), path);
        return libcdoc::NetworkBackend::NETWORK_ERROR;
    }
    int status = res->status;
    LOG_DBG("Status: {}", status);
    LOG_TRACE("  Body: {}", res->body);
    for (auto h : res->headers) {
        LOG_TRACE("    Header {}: {}", h.first, h.second);
    }
    if ((status < 200) || (status >= 300)) {
        error = FORMAT("Http status {}", status);
        return libcdoc::NetworkBackend::NETWORK_ERROR;
    }
    rsp = res.value();
    error = {};
    return libcdoc::OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::sendKey (CapsuleInfo& dst, const std::string& url, const std::vector<uint8_t>& rcpt_key, const std::vector<uint8_t> &key_material, const std::string& type, uint64_t expiry_ts)
{
    LOG_DBG("Sendkey");
    picojson::object obj = {
        {"recipient_id", picojson::value(libcdoc::toBase64(rcpt_key))},
        {"ephemeral_key_material", picojson::value(libcdoc::toBase64(key_material))},
        {"capsule_type", picojson::value(type)}
    };
    picojson::value req_json(obj);
    std::string req_str = req_json.serialize();

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    std::string full = path + "/key-capsules";
    httplib::Headers hdrs;
    if (expiry_ts) {
        std::string expiry_str = timeToISO(expiry_ts);
        LOG_DBG("Expiry time: {}", expiry_str);
        hdrs.emplace("x-expiry-time", expiry_str);
    }
    httplib::Response rsp;
    result = post(cli, full, hdrs, req_str, rsp);
    if (result != libcdoc::OK) return result;

    std::string location = rsp.get_header_value("Location");
    if (location.empty()) {
        error = FORMAT("No Location header in response");
        return NETWORK_ERROR;
    }
    constexpr std::string_view prefix = "/key-capsules/";
    if (location.compare(0, prefix.size(), prefix) != 0) {
        error = FORMAT("Unexpected Location header value");
        return NETWORK_ERROR;
    }
    error = {};
    location.erase(0, prefix.size());
    dst.transaction_id = std::move(location);

    std::string expiry_str = rsp.get_header_value("x-expiry-time");
    LOG_DBG("Server expiry: {}", expiry_str);
    if (expiry_str.empty()) {
        dst.expiry_time = expiry_ts;
        LOG_DBG("Given expiry timestamp: {}", dst.expiry_time);
    } else {
        dst.expiry_time = uint64_t(timeFromISO(expiry_str));
        LOG_DBG("Server expiry timestamp: {}", dst.expiry_time);
    }

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchKey (std::vector<uint8_t>& dst, const std::string& url, const std::string& transaction_id)
{
    std::string host, path;
    int port;
    result_t result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    std::vector<uint8_t> cert;
    result = getClientTLSCertificate(cert);
    if (result != OK) return result;
    std::unique_ptr<Private> d = std::make_unique<Private>(this, cert);
    if (!cert.empty() && (!d->x509 || !d->pkey)) return CRYPTO_ERROR;

    httplib::SSLClient cli(host, port, d->x509.handle(), d->pkey);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    // S12: transaction_id comes from the (untrusted) container
    std::string full = path + "/key-capsules/" + urlEncodeComponent(transaction_id);
    httplib::Headers hdrs;
    httplib::Response rsp;;
    result = get(cli, hdrs, full, rsp);
    if (result != libcdoc::OK) return result;

    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, rsp.body);
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!rsp_json.is<picojson::object>()) {
        error = "Invalid Authentication response";
        LOG_WARN("Invalid Authentication response");
        return NetworkBackend::NETWORK_ERROR;
    }

    std::string ks = getJsonString(rsp_json, "ephemeral_key_material", result);
    if (result != libcdoc::OK) return NETWORK_ERROR;
    dst = fromBase64(ks);
    if (dst.empty()) {
        error = FORMAT("Invalid base64 in 'ephemeral_key_material'");
        return NETWORK_ERROR;
    }

    return libcdoc::OK;
}

#ifdef HAS_KEYSHARES
libcdoc::result_t
libcdoc::NetworkBackend::sendShare(std::vector<uint8_t>& dst, const std::string& url, const std::string& recipient, const std::vector<uint8_t>& share)
{
    // Create KeyShare container
    LOG_DBG("Creating keyshare for recipient: {}", recipient);
    picojson::object obj = {
        {"share", picojson::value(libcdoc::toBase64(share))},
        {"recipient", picojson::value(recipient)}
    };
    picojson::value req_json(obj);
    std::string req_str = req_json.serialize();
    LOG_DBG("POST keyshare to: {}", url);
    LOG_TRACE_KEY("{}", req_str);

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    std::string full = path + "/key-shares";
    httplib::Headers hdrs;
    httplib::Response rsp;
    result = post(cli, full, hdrs, req_str, rsp);
    if (result != libcdoc::OK) return result;

    std::string location = rsp.get_header_value("Location");
    if (location.empty()) {
        error = FORMAT("No Location header in response");
        return NETWORK_ERROR;
    }
    constexpr std::string_view prefix = "/key-shares/";
    if (location.compare(0, prefix.size(), prefix) != 0) {
        error = FORMAT("Unexpected Location header value");
        return NETWORK_ERROR;
    }
    error = {};

    dst.assign(location.cbegin() + prefix.size(), location.cend());
    LOG_DBG("Share: {}", std::string((const char *) dst.data(), dst.size()));

    return OK;
}

namespace libcdoc {

struct AuthResponse {
    std::string status;
    std::string endResult;
    std::string sessionToken;
    std::string cert;
};

static result_t
waitForAuthResult(AuthResponse& dst, httplib::SSLClient& cli, const std::string& path, const std::string& auth_proc_uuid, double seconds)
{
    httplib::Headers hdrs;

    double end = getTime() + seconds;
    std::string full = path + auth_proc_uuid;
    LOG_DBG("SID/MID authentication query path: {}", full);
    while (getTime() < end) {
        httplib::Response rsp;
        result_t result = get(cli, hdrs, full, rsp);
        if (result != OK) return result;

        picojson::value rsp_json;
        std::string parse_err = picojson::parse(rsp_json, rsp.body);
        if (!parse_err.empty()) {
            error = FORMAT("JSON parse error: {}", parse_err);
            LOG_ERROR("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }
        if (!rsp_json.is<picojson::object>()) {
            error = "Invalid Authentication response";
            LOG_WARN("Invalid Authentication response");
            return NetworkBackend::NETWORK_ERROR;
        }

        // Status
        dst.status = getJsonString(rsp_json, "status", result);
        if (result != OK) return NetworkBackend::NETWORK_ERROR;
        LOG_DBG("Status: {}", dst.status);

        if (dst.status == "RUNNING") {
            // Pause for 0.5 seconds and repeat
            std::chrono::milliseconds duration(500);
            std::this_thread::sleep_for(duration);
            continue;
        } else if (dst.status != "COMPLETE") {
            error = FORMAT("Invalid SmartID state: {}", dst.status);
            LOG_WARN("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }

        // State is complete, check for end result
        dst.endResult = getJsonString(rsp_json, "endResult", result);
        if (result != OK) return NetworkBackend::NETWORK_ERROR;
        LOG_DBG("EndResult: {}", dst.endResult);
        if (dst.endResult != "OK") {
            LOG_WARN("Authentication endResult is {}", dst.endResult);
            return parseMIDSIDResult(dst.endResult);
        }

        // Fetch session token and certificate
        dst.sessionToken = getJsonString(rsp_json, "sessionToken", result);
        if (result != OK) return NetworkBackend::NETWORK_ERROR;
        LOG_TRACE("Session token: {}", dst.sessionToken);
        dst.cert = getJsonString(rsp_json, "signingCertificate", result);
        if (result != OK) return NetworkBackend::NETWORK_ERROR;
        LOG_TRACE("Certificate: {}", dst.cert);
        error = {};
        return OK;
    }
    // Timeout
    error = "Timeout waiting SID/MID result";
    LOG_WARN("{}", error);
    return UNSPECIFIED_ERROR;
}

}

libcdoc::result_t
libcdoc::NetworkBackend::authenticateForShares(const std::string& url, const std::string& rcpt_id, const std::string& phone, std::string& token, std::string& cert)
{
    // Start authentication
    std::string host, path;
    int port;
    result_t result = parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    // The session is bound to the actual recipient identity from the lock.
    // A hardcoded or malformed id would break the identity chain
    // (session identity == signing identity == lock recipient).
    if (!parseEtsiRecipientId(rcpt_id).valid()) {
        error = FORMAT("Invalid recipient id: {}", rcpt_id);
        LOG_WARN("{}", error);
        return DATA_FORMAT_ERROR;
    }

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    picojson::object obj = {
        {"identifier", picojson::value(rcpt_id)}
    };
    if (!phone.empty()) {
        obj.emplace("mobileNr", picojson::value(phone));
    }
    picojson::value req_json(obj);
    std::string req_str = req_json.serialize();
    LOG_DBG("POST authentication request to: {}", url);
    LOG_DBG("{}", req_str);

    std::string full = path + "/auth/start";
    httplib::Headers hdrs;
    httplib::Response rsp;
    result = post(cli, full, hdrs, req_str, rsp);
    if (result != libcdoc::OK) return result;

    std::string location = rsp.get_header_value("Location");
    LOG_DBG("Location: {}", location);
    if (location.empty()) {
        error = FORMAT("No Location header in response");
        return NETWORK_ERROR;
    }
    constexpr std::string_view prefix = "/auth/status/";
    if (location.compare(0, prefix.size(), prefix) != 0) {
        error = FORMAT("Unexpected Location header value");
        return NETWORK_ERROR;
    }
    location.erase(0, prefix.size());

    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, rsp.body);
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!rsp_json.is<picojson::object>()) {
        error = "Invalid Authentication response";
        LOG_WARN("Invalid Authentication response");
        return NetworkBackend::NETWORK_ERROR;
    }
    // Verification code
    std::string ver_code = getJsonString(rsp_json, "vc", result);
    if (result != libcdoc::OK) return NETWORK_ERROR;
    LOG_DBG("Verification code: {}", ver_code);

    // S16: the verification code is the user's consent anchor - a malformed
    // server value must never be rendered as 0 or garbage. Smart-ID/Mobile-ID
    // numeric4 codes are 0000-9999.
    int vc = 0;
    if (!libcdoc::parseBoundedUInt(ver_code, 9999, vc)) {
        error = FORMAT("Invalid verification code in response: {}", ver_code);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }

    SIDMIDFeedback fb = {
        .code = vc,
    };
    result = showFeedback(fb);
    if (result != OK) {
        error = FORMAT("Failed to show verification code: {}", result);
        LOG_ERROR("{}", error);
        return result;
    }

    // Fetch authentication response
    AuthResponse auth_rsp;
    result = waitForAuthResult(auth_rsp, cli, path + "/auth/status/", location, 60);
    if (result != OK) return result;

    cert = auth_rsp.cert;

    auto parts = split(auth_rsp.sessionToken, '~');
    // In minimum we need JWT, AUD, RP disclosure and 2 share disclosures
    if (parts.size() < 5) {
        error = "Invalid JWT-SD token";
        LOG_WARN("Invalid JWT-SD token");
        return NetworkBackend::NETWORK_ERROR;
    }
    std::string jwt = parts[0];
    std::string aud = parts[1];
    for (size_t i = 2; i < parts.size(); i++) {
        auto v = parts[i];
        LOG_DBG("Session token part {} ({}) : {}", i, v.size(), v);
        if (i > 0) {
            std::vector<uint8_t> decoded_part = fromBase64URL(v);
            LOG_DBG("Decoded part {} ({}): {}", i, decoded_part.size(), std::string(decoded_part.begin(), decoded_part.end()));
        }
    }

    token = auth_rsp.sessionToken;

    auto decoded = decodeTicket(jwt);
    LOG_TRACE("Session token: {}", decoded);
    picojson::value dec_json;
    auto p_err = picojson::parse(dec_json, decoded);
    if (!p_err.empty()) {
        error = FORMAT("JSON parse error: {}", p_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!dec_json.is<picojson::object>()) {
        error = "Invalid Authentication response";
        LOG_WARN("Invalid Authentication response");
        return NetworkBackend::NETWORK_ERROR;
    }

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchNonce(std::vector<uint8_t>& dst, const std::string& url, const std::string& share_id, const std::string& auth_token, const std::string& auth_cert)
{
    LOG_DBG("Get nonce from: {}", url);

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    SessionToken stoken(auth_token);
    std::string session_token_disclosed = stoken.discloseForUrl(url);

    // S10: never send an empty session token header. A missing disclosure
    // means the token is malformed or the server is not authorized for this
    // session - fail before making the request.
    if (session_token_disclosed.empty()) {
        error = FORMAT("Session token has no disclosure for {}", url);
        LOG_WARN("{}", error);
        return libcdoc::DATA_FORMAT_ERROR;
    }

    // S12: share_id comes from the (untrusted) container
    std::string full = path + "/key-shares/" + urlEncodeComponent(share_id) + "/nonce";
    httplib::Headers hdrs;
    hdrs.insert({"x-cdoc2-session-token", session_token_disclosed});
    hdrs.insert({"x-cdoc2-session-x5c", auth_cert});
    LOG_DBG("POST nonce request to: {}", full);
    httplib::Response rsp;
    result = post(cli, full, hdrs, "", rsp);
    if (result != libcdoc::OK) return result;

    LOG_DBG("Response: {}", rsp.body);
    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, rsp.body);
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    libcdoc::result_t rv = libcdoc::OK;
    std::string nonce_str = getJsonString(rsp_json, "nonce", rv);
    if (rv != libcdoc::OK) return rv;
    dst = toUint8Vector(nonce_str);
    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchShare(ShareInfo& share, const std::string& url, const std::string& share_id,
    const std::string& session_token, const std::string& session_cert, const std::string& auth_token, const std::vector<uint8_t>& auth_cert, const std::map<std::string, std::string>& auth_params)
{
    LOG_DBG("Get share from: {}", url);

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;

    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    SessionToken stoken(session_token);
    std::string session_token_disclosed = stoken.discloseForUrl(url);

    // S10: never send an empty session token header. A missing disclosure
    // means the token is malformed or the server is not authorized for this
    // session - fail before making the request.
    if (session_token_disclosed.empty()) {
        error = FORMAT("Session token has no disclosure for {}", url);
        LOG_WARN("{}", error);
        return libcdoc::DATA_FORMAT_ERROR;
    }

    // S12: share_id comes from the (untrusted) container
    std::string full = path + "/key-shares/" + urlEncodeComponent(share_id);
    LOG_DBG("Share url: {}", full);
    httplib::Headers hdrs;
    hdrs.insert({"x-cdoc2-session-token", session_token_disclosed});
    hdrs.insert({"x-cdoc2-session-x5c", session_cert});
    hdrs.insert({"x-cdoc2-auth-token", auth_token});
    hdrs.insert({"x-cdoc2-auth-x5c", toBase64URL(auth_cert)});
    for (const auto& val : auth_params) {
        hdrs.insert({val.first, val.second});
    }
    httplib::Response rsp;
    result = get(cli, hdrs, full, rsp);
    if (result != libcdoc::OK) return result;

    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, rsp.body);
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!rsp_json.is<picojson::object>()) {
        error = "Invalid Authentication response";
        LOG_WARN("Invalid Authentication response");
        return NetworkBackend::NETWORK_ERROR;
    }

    libcdoc::result_t rv = libcdoc::OK;
    std::string share64 = getJsonString(rsp_json, "share", rv);
    if (rv != libcdoc::OK) return rv;
    LOG_DBG("Share64: {}", share64);
    std::string recipient = getJsonString(rsp_json, "recipient", rv);
    if (rv != libcdoc::OK) return rv;
    std::vector<uint8_t> shareval = fromBase64(share64);
    if (shareval.size() != 32) {
        error = FORMAT("Invalid share size: expected 32, got {}", shareval.size());
        return NETWORK_ERROR;
    }
    LOG_DBG("Share: {}", toHex(shareval));
    share = {std::move(shareval), std::move(recipient)};
    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchWellKnownKeys(std::string& dst, const std::string& url)
{
    LOG_DBG("Get well-known keys from: {}", url);

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    std::string full = path + "/.well-known/jwks.jws";
    httplib::Headers hdrs;
    if (httplib::Result rsp = cli.Get(full, hdrs); !rsp)
        return NETWORK_ERROR;
    else if (rsp->status < 200 || rsp->status >= 300) {
        error = FORMAT("Well-known keys request failed with status {}", rsp->status);
        LOG_WARN("{}", error);
        return NETWORK_ERROR;
    } else
        dst = std::move(rsp->body);

    // The endpoint name says .jws: accept both a plain JWK Set (what the
    // servers currently return) and a JWS compact serialization
    // (header64.payload64.signature64) whose payload is the JWK Set.
    if (dst.find("\"keys\"") == std::string::npos) {
        std::vector<std::string> parts = split(dst, '.');
        if (parts.size() == 3) {
            std::vector<uint8_t> payload = fromBase64URL(parts[1]);
            dst.assign(payload.begin(), payload.end());
        }
    }
    if (dst.find("\"keys\"") == std::string::npos) {
        error = "Well-known keys response is not a JWK Set";
        LOG_WARN("{}", error);
        dst.clear();
        return NETWORK_ERROR;
    }
    return libcdoc::OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::showFeedback(SIDMIDFeedback& feedback)
{
    LOG_INFO("Verification code: {:04d} url: {}", feedback.code, feedback.url);
    std::cout << "###########################" << "\n";
    std::cout << "# Verification code: " << feedback.code << " #" << "\n";
    std::cout << "###########################" << "\n";
    return OK;
}

//
// https://open-eid.github.io/CDOC2/
//

struct SIDParams {
    // Signature json without signature value to create verification info
    picojson::object signature_json;
    std::string inter_type_used;
};

struct MIDParams {
    std::string x_rp_signed_hash;
    std::string x_rp_name;
    std::string signature_input;
    std::string signature;
};

struct SIDMIDResponse {
    // Signature value, base64 encoded
    std::string signature;
    // Signer certificate, base64 encoded
    std::string cert;
    // Protocol parameters
    SIDParams sid;
    MIDParams mid;
};

namespace libcdoc {

static result_t
waitForResult(SIDMIDResponse& dst, httplib::SSLClient& cli, const std::string& path, const std::string& auth_token_disclosed, const std::string& auth_cert, const std::string& session_id, bool sid, double seconds)
{
    double end = libcdoc::getTime() + seconds;
    // S12: session_id comes from the server response
    std::string full = path + urlEncodeComponent(session_id);
    LOG_DBG("SID/MID session query path: {}", full);
    while (libcdoc::getTime() < end) {
        httplib::Response rsp;
        httplib::Headers hdrs;
        hdrs.insert({"x-cdoc2-session-token", auth_token_disclosed});
        hdrs.insert({"x-cdoc2-session-x5c", auth_cert});
        result_t result = get(cli, hdrs, full, rsp);
        if (result != OK) return result;

        picojson::value rsp_json;
        std::string parse_err = picojson::parse(rsp_json, rsp.body);
        if (!parse_err.empty()) {
            error = FORMAT("JSON parse error: {}", parse_err);
            LOG_ERROR("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }
        if (!rsp_json.is<picojson::object>()) {
            error = "Invalid Authentication response";
            LOG_WARN("Invalid Authentication response");
            return NetworkBackend::NETWORK_ERROR;
        }

        // State
        std::string str = getJsonString(rsp_json, "state", result);
        if (result != OK) return result;
        if (str == "RUNNING") {
            // Pause for 0.5 seconds and repeat
            std::chrono::milliseconds duration(500);
            std::this_thread::sleep_for(duration);
            continue;
        } else if (str != "COMPLETE") {
            error = FORMAT("Invalid state value: {}", str);
            LOG_WARN("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }

        if (sid) {
            // State is complete, check for end result
            picojson::object result_obj = getJsonObject(rsp_json, "result", result);
            if (result != OK) return result;
            str = getJsonString(picojson::value(result_obj), "endResult", result);
            if (result != OK) return result;
            result = parseMIDSIDResult(str);
            if (result == UNSPECIFIED_ERROR) {
                // Unknown result
                error = FORMAT("unknwon endResult value: {}", str);
                LOG_WARN("{}", error);
                return NetworkBackend::NETWORK_ERROR;
            } else if (result != OK) {
                LOG_WARN("EndResult is not OK: {}", str);
                return result;
            }
            // documentNumber
            // details

            // signatureProtocol
            // Signature (optional field; rsp is a verified object here)
            if (picojson::value sig = rsp_json.get("signature"); sig.is<picojson::object>()) {
                dst.signature = getJsonString(sig, "value", result);
                if (result != OK) return result;
                dst.sid.signature_json = sig.get<picojson::object>();
                dst.sid.signature_json.erase("value");
            }
            // Interaction type
            dst.sid.inter_type_used = getJsonString(rsp_json, "interactionTypeUsed", result);
            if (result != OK) return result;

            // Certificate
            picojson::object cert_obj = getJsonObject(rsp_json, "cert", result);
            if (result != OK) return result;
            dst.cert = getJsonString(picojson::value(cert_obj), "value", result);
            if (result != OK) return result;
        } else {
            std::string str = getJsonString(rsp_json, "result", result);
            if (result != OK) return result;
            result = parseMIDSIDResult(str);
            if (result == UNSPECIFIED_ERROR) {
                // Unknown result
                error = FORMAT("unknwon endResult value: {}", str);
                LOG_WARN("{}", error);
                return NetworkBackend::NETWORK_ERROR;
            } else if (result != OK) {
                LOG_WARN("EndResult is not OK: {}", str);
                return result;
            }
            picojson::object sig = getJsonObject(rsp_json, "signature", result);
            if (result != OK) return result;
            dst.signature = getJsonString(picojson::value(sig), "value", result);
            if (result != OK) return result;
            dst.cert = getJsonString(picojson::value(rsp_json), "cert", result);
            if (result != OK) return result;

            dst.mid.x_rp_signed_hash = rsp.get_header_value("x-rp-signed-hash");
            dst.mid.x_rp_name = rsp.get_header_value("x-rp-name");
            dst.mid.signature_input = rsp.get_header_value("Signature-Input");
            dst.mid.signature = rsp.get_header_value("Signature");
        }
        error = {};

        return OK;
    }
    // Timeout
    error = "Timeout waiting SID/MID result";
    LOG_WARN("{}", error);
    return UNSPECIFIED_ERROR;
}

}

libcdoc::result_t
libcdoc::NetworkBackend::signSID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert, std::map<std::string, std::string>& params,
    const std::string& url, const std::string& session_token, const std::string& session_cert,
    const std::string& rcpt_id, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo)
{
    // Start authentication:
    //
    // semanticsIdentifier: PNOEE-XYZ...
    // certificateLevel: QUALIFIED
    // signatureProtocol: ACSP_V2
    // signatureProtocolParameters:
    //   rpChallenge: S480uRoCX4pAb1tWqAy8WGl/AWE1RnqaP2y5iamCDhlCyQrMTVa5d8Dh34sZ+UePHXRNKTwz7QTvsIL1ls05AQ==
    //   signatureAlgorithm: rsassa-pss
    //   signatureAlgorithmParameters:
    //     hashAlgorithm: SHA-512
    // interactions: W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkRlY3J5cHRpbmcgY29udGFpbmVyIGZpbGUgXCJ0ZXN0LnR4dFwiIn0seyJ0eXBlIjoiZGlzcGxheVRleHRBbmRQSU4iLCJkaXNwbGF5VGV4dDYwIjoiRGVjcnlwdGluZyBjb250YWluZXIgZmlsZSBcInRlc3QudHh0XCIifV0=
    // vcType: numeric4
    //
    std::string certificateLevel = "QUALIFIED";
    std::string hashAlgorithm = "SHA-256";
    if (!rcpt_id.starts_with("etsi/")) return libcdoc::INTERNAL_ERROR;
    std::string semanticIdentifier = rcpt_id.substr(5);

    SessionToken stoken(session_token);
    std::string session_token_disclosed = stoken.discloseForUrl(url);

    // S10: never send an empty session token header. A missing disclosure
    // means the token is malformed or the server is not authorized for this
    // session - fail before making the request.
    if (session_token_disclosed.empty()) {
        error = FORMAT("Session token has no disclosure for {}", url);
        LOG_WARN("{}", error);
        return libcdoc::DATA_FORMAT_ERROR;
    }

    picojson::object sap = {
        {"hashAlgorithm", picojson::value(hashAlgorithm)}
    };
    picojson::object spp = {
        {"rpChallenge", picojson::value(toBase64(digest))},
        {"signatureAlgorithm", picojson::value("rsassa-pss")},
        {"signatureAlgorithmParameters", picojson::value(sap)}
    };
    picojson::object inter = {
        {"type", picojson::value("confirmationMessageAndVerificationCodeChoice")},
        {"displayText200", picojson::value("Do you want to decrypt the document")}
    };
    picojson::array inter_arr = {
        picojson::value(inter)
    };
    //std::string inter_str = picojson::value(inter_arr).serialize();
    std::string inter_str = "[{\"type\":\"confirmationMessageAndVerificationCodeChoice\",\"displayText200\":\"Do you want to decrypt the document\"}]";
    LOG_DBG("Interactions: {}", inter_str);
    inter_str = toBase64((const uint8_t *) inter_str.data(), inter_str.size());
    std::string inter_str_64 = toBase64((const uint8_t *) inter_str.data(), inter_str.size());
    picojson::object obj = {
        {"semanticsIdentifier", picojson::value(semanticIdentifier)},
        {"certificateLevel", picojson::value(certificateLevel)},
        {"signatureProtocol", picojson::value("ACSP_V2")},
        {"signatureProtocolParameters", picojson::value(spp)},
        {"interactions", picojson::value(inter_str)},
        {"vcType", picojson::value("numeric4")}
    };
    picojson::value query(obj);
    LOG_DBG("JSON:{}", query.serialize());

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    LOG_DBG("URL:{}", url);
    LOG_DBG("HOST:{}", host);
    LOG_DBG("PORT:{}", port);
    LOG_DBG("PATH:{}", path);

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    // Generate code
    SIDMIDFeedback fb;
    std::array<uint8_t, 32> b;
    SHA256(digest.data(), digest.size(), b.data());
    fb.code = ((b[30] << 8) | b[31]) % 10000;
    result = showFeedback(fb);
    if (result != OK) return result;

    //
    // Begin authentication session
    //
    std::string full = path + "/sid/authenticate";
    LOG_DBG("SmartID path: {}", full);
    httplib::Headers hdrs;
    hdrs.insert({"x-cdoc2-session-token", session_token_disclosed});
    hdrs.insert({"x-cdoc2-session-x5c", session_cert});
    httplib::Response rsp;
    result = post(cli, full, hdrs, query.serialize(), rsp);
    if (result != libcdoc::OK) return result;

    // Reply:
    //
    // {"sessionID":"xyz..."}
    //
    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, rsp.body);
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!rsp_json.is<picojson::object>()) {
        error = "Invalid Authentication response";
        LOG_WARN("Invalid Authentication response");
        return NetworkBackend::NETWORK_ERROR;
    }
    libcdoc::result_t rv = libcdoc::OK;
    std::string sessionId = getJsonString(rsp_json, "sessionID", rv);
    if (rv != libcdoc::OK) return rv;
    LOG_DBG("SessionID: {}", sessionId);

    SIDMIDResponse sidrsp;
    result = waitForResult(sidrsp, cli, path + "/sid/session/", session_token_disclosed, session_cert, sessionId, true, 60);
    if (result != OK) return result;

    LOG_DBG("Certificate: {}", sidrsp.cert);
    LOG_DBG("Signature: {}", sidrsp.signature);

    SHA256((uint8_t *) inter_str.c_str(), inter_str.size(), b.data());
    std::string inter_hash_64 = toBase64(b.data(), b.size());

    picojson::object sig_parms = {
        {"interactionsDigest", picojson::value(inter_hash_64)},
        {"interactionTypeUsed", picojson::value(sidrsp.sid.inter_type_used)},
        {"signature", picojson::value(sidrsp.sid.signature_json)},
    };

    dst = fromBase64(sidrsp.signature);
    cert = fromBase64(sidrsp.cert);
    params[X_CDOC2_SID_RPV3_SIGNATURE_PARAMETERS] = toBase64URL(picojson::value(sig_parms).serialize());

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::signMID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert, std::map<std::string, std::string>& params,
    const std::string& url, const std::string& phone, const std::string& session_token, const std::string& session_cert,
    const std::string& rcpt_id, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo)
{
        //phoneNumber: '+3726234566'
        //nationalIdentityNumber: '38412319871'
        //hash: 0nbgC2fVdLVQFZJdBbmG8B+kXnZtX1FSTM59UVDQ4Gc=
        //hashType: SHA256
        //language: ENG
        //displayText: Decrypting container file "test.txt"
        //displayTextFormat: GSM-7

    // Validate rcpt_id BEFORE doing anything else (network setup, key
    // material, etc.). The previous implementation called
    // rcpt_id.substr(11, 11) which throws std::out_of_range when
    // rcpt_id.size() < 11 and silently returns a too-short identifier
    // when 11 <= size < 22 - both of which would propagate to the SK
    // Mobile-ID service as garbage and (worse) leak partially-filled
    // payloads to the network in the latter case.
    libcdoc::EtsiRecipientId parsed = libcdoc::parseEtsiRecipientId(rcpt_id);
    if (!parsed.valid()) {
        error = "Invalid Mobile ID recipient identifier";
        LOG_ERROR("Invalid Mobile ID recipient identifier: '{}'", rcpt_id);
        return libcdoc::WRONG_ARGUMENTS;
    }

    // The SK Mobile-ID API expects `nationalIdentityNumber` to be the
    // bare digits with no country prefix, so we use the parsed national
    // identifier directly.
    const std::string &id_num = parsed.national_id;

    if (digest.empty()) {
        error = "Empty digest";
        LOG_ERROR("Empty digest passed to signMID");
        return libcdoc::WRONG_ARGUMENTS;
    }

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    LOG_DBG("URL:{}", url);
    LOG_DBG("HOST:{}", host);
    LOG_DBG("PORT:{}", port);
    LOG_DBG("PATH:{}", path);

    SessionToken stoken(session_token);
    std::string session_token_disclosed = stoken.discloseForUrl(url);

    // S10: never send an empty session token header. A missing disclosure
    // means the token is malformed or the server is not authorized for this
    // session - fail before making the request.
    if (session_token_disclosed.empty()) {
        error = FORMAT("Session token has no disclosure for {}", url);
        LOG_WARN("{}", error);
        return libcdoc::DATA_FORMAT_ERROR;
    }

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    //
    // Authenticate
    //
    std::string_view algo_name = hashAlgorithmToMidName(algo);
    if (algo_name.empty()) {
        error = "Unsupported hash algorithm for Mobile-ID";
        LOG_ERROR("Unsupported hash algorithm for Mobile-ID: {}",
                  static_cast<int>(algo));
        return libcdoc::WRONG_ARGUMENTS;
    }

    // Generate verification code. digest is guaranteed non-empty above.
    SIDMIDFeedback fb;
    fb.code = (((digest[0] & 0xfc) << 5) | (digest[digest.size() - 1] & 0x7f));
    result = showFeedback(fb);
    if (result != OK) return result;

    picojson::object qobj = {
        {"phoneNumber", picojson::value(phone)},
        {"nationalIdentityNumber", picojson::value(id_num)},
        {"hash", picojson::value(toBase64(digest))},
        {"hashType", picojson::value(std::string(algo_name))},
        {"language", picojson::value("ENG")},
        {"displayText", picojson::value("Tahad dekryptida?")},
        {"displayTextFormat", picojson::value("GSM-7")}
    };
    picojson::value query = picojson::value(qobj);
    LOG_DBG("JSON:{}", query.serialize());
    //
    // Begin authentication session
    //
    std::string full = path + "/mid/authenticate";
    LOG_DBG("MobileID path: {}", full);
    httplib::Headers hdrs;
    hdrs.insert({"x-cdoc2-session-token", session_token_disclosed});
    hdrs.insert({"x-cdoc2-session-x5c", session_cert});
    httplib::Response rsp;
    result = post(cli, full, hdrs, query.serialize(), rsp);
    if (result != libcdoc::OK) return result;
    LOG_DBG("Response: {}", rsp.body);

    // Reply:
    //
    // {"sessionID":"xyz..."}
    //
    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, rsp.body);
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!rsp_json.is<picojson::object>()) {
        error = "Invalid Authentication response";
        LOG_WARN("Invalid Authentication response");
        return NetworkBackend::NETWORK_ERROR;
    }
    libcdoc::result_t rv = libcdoc::OK;
    std::string sessionId = getJsonString(rsp_json, "sessionID", rv);
    if (rv != libcdoc::OK) return rv;
    LOG_DBG("SessionID: {}", sessionId);

    SIDMIDResponse midrsp;
    result = waitForResult(midrsp, cli, path + "/mid/session/", session_token_disclosed, session_cert, sessionId, false, 60);
    if (result != OK) return result;

    LOG_DBG("Certificate: {}", midrsp.cert);
    LOG_DBG("Signature: {}", midrsp.signature);
    LOG_DBG("x-rp-signed-hash: {}", midrsp.mid.x_rp_signed_hash);
    LOG_DBG("x-rp-name: {}", midrsp.mid.x_rp_name);
    LOG_DBG("Signature-Input: {}", midrsp.mid.signature_input);
    LOG_DBG("Signature: {}", midrsp.mid.signature);

    params[X_RP_SIGNED_HASH] = midrsp.mid.x_rp_signed_hash;
    params[X_RP_NAME] = midrsp.mid.x_rp_name;
    params[HDR_SIGNATURE_INPUT] = midrsp.mid.signature_input;
    params[HDR_SIGNATURE] = midrsp.mid.signature;

    dst = fromBase64(midrsp.signature);
    cert = fromBase64(midrsp.cert);

    return OK;
}
#endif

ECDSA_SIG *
ecdsa_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM * /*inv*/, const BIGNUM * /*rp*/, EC_KEY *eckey)
{
    auto *backend = (libcdoc::NetworkBackend *) EC_KEY_get_ex_data(eckey, 0);
    std::vector<uint8_t> dst;
    std::vector<uint8_t> digest(dgst, dgst + dgst_len);
    int result = backend->signTLS(dst, libcdoc::CryptoBackend::SHA_512, digest);
    if (result != libcdoc::OK) {
        return nullptr;
    }
    int size_2 = (int) dst.size() / 2;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig,
                   BN_bin2bn(dst.data(), size_2, nullptr),
                   BN_bin2bn(dst.data() + size_2, size_2, nullptr));
    return sig;
}

int
rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    auto *backend = (libcdoc::NetworkBackend *) RSA_get_ex_data(rsa, 0);
    auto algo = libcdoc::CryptoBackend::SHA_512;
    switch (type) {
    case NID_sha224:
        algo = libcdoc::CryptoBackend::SHA_224;
        break;
    case NID_sha256:
        algo = libcdoc::CryptoBackend::SHA_256;
        break;
    case NID_sha384:
        algo = libcdoc::CryptoBackend::SHA_384;
        break;
    case NID_sha512:
        break;
    default:
        return 0;
    }
    std::vector<uint8_t> dst;
    std::vector<uint8_t> digest(m, m + m_len);
    int result = backend->signTLS(dst, algo, digest);
    if (result != libcdoc::OK) {
        return 0;
    }
    if (sigret && (*siglen >= dst.size())) {
        memcpy(sigret, dst.data(), dst.size());
    }
    *siglen = (unsigned int) dst.size();
    return 1;
}
