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
#ifdef HAS_KEYSHARES
#include "KeyShares.h"
#endif

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

// The default confirmation text shown on the user's device in SID/MID
// dialogs when no DISPLAY_TEXT configuration value is set. Overridable at
// compile time (e.g. -DCDOC2_DEFAULT_DISPLAY_TEXT="...").
#ifndef CDOC2_DEFAULT_DISPLAY_TEXT
#define CDOC2_DEFAULT_DISPLAY_TEXT "Do you want to decrypt the CDoc container?"
#endif

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
// SID/MID result-code table and helpers live in the HAS_KEYSHARES block at
// the end of this file; getLastErrorStr needs the description lookup.
static std::string_view getMIDSIDDescription(libcdoc::result_t code);
#endif

thread_local std::string error;

// Normalize an HTTP header name to lowercase for case-insensitive lookup in
// the std::map used by get()/post()/getAuthResponse()/getSignResponse().
// HTTP/2 mandates lowercase header names; HTTP/1.1 servers vary. All
// response headers are stored under their lowercase key, and all lookups
// must use lowercase names.
static std::string
headerKey(std::string_view name)
{
    std::string out(name);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

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
    LOG_DBG("Num TLS certs {}", certs.size());
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
httpPost(httplib::SSLClient& cli, const std::string& path, httplib::Headers& hdrs, const std::string& req, httplib::Response& rsp)
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
httpGet(httplib::SSLClient& cli, httplib::Headers& hdrs, const std::string& path, httplib::Response& rsp)
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
libcdoc::NetworkBackend::get(const std::string& url, std::vector<uint8_t>& body, std::map<std::string, std::string>& headers, bool client_cert)
{
    std::string host, path;
    int port;
    result_t result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    httplib::Headers hdrs;
    for (const auto& hdr : headers) {
        hdrs.insert({hdr.first, hdr.second});
    }
    httplib::Response rsp;

    if (client_cert) {
        std::vector<uint8_t> cert;
        result = getClientTLSCertificate(cert);
        if (result != OK) return result;
        // L1: an empty or unparseable client certificate must not produce a
        // client with null credentials - reject before constructing the
        // SSLClient.
        if (cert.empty()) return CRYPTO_ERROR;
        std::unique_ptr<Private> d = std::make_unique<Private>(this, cert);
        if (!d->x509 || !d->pkey) return CRYPTO_ERROR;

        httplib::SSLClient cli(host, port, d->x509.handle(), d->pkey);
        if (result = applySSLTimeout(cli, this); result != OK) return result;
        if (result = setPeerCertificates(cli, this, buildURL(host, port)); result != OK) return result;
        if (result = setProxy(cli, this); result != OK) return result;
        result = httpGet(cli, hdrs, path, rsp);
    } else {
        httplib::SSLClient cli(host, port);
        if (result = applySSLTimeout(cli, this); result != OK) return result;
        if (result = setPeerCertificates(cli, this, buildURL(host, port)); result != OK) return result;
        if (result = setProxy(cli, this); result != OK) return result;
        result = httpGet(cli, hdrs, path, rsp);
    }
    if (result != libcdoc::OK) return result;

    headers.clear();
    for (const auto& hdr : rsp.headers) {
        headers.insert({headerKey(hdr.first), hdr.second});
    }
    body.assign(rsp.body.begin(), rsp.body.end());

    return libcdoc::OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::post(const std::string& url, std::vector<uint8_t>& body, std::map<std::string, std::string>& headers, bool client_cert)
{
    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    httplib::Headers hdrs;
    for (const auto& hdr : headers) {
        hdrs.insert({hdr.first, hdr.second});
    }
    httplib::Response rsp;

    if (client_cert) {
        std::vector<uint8_t> cert;
        result = getClientTLSCertificate(cert);
        if (result != OK) return result;
        // L1: an empty or unparseable client certificate must not produce a
        // client with null credentials - reject before constructing the
        // SSLClient.
        if (cert.empty()) return CRYPTO_ERROR;
        std::unique_ptr<Private> d = std::make_unique<Private>(this, cert);
        if (!d->x509 || !d->pkey) return CRYPTO_ERROR;

        httplib::SSLClient cli(host, port, d->x509.handle(), d->pkey);
        if (result = applySSLTimeout(cli, this); result != OK) return result;
        if (result = setPeerCertificates(cli, this, buildURL(host, port)); result != OK) return result;
        if (result = setProxy(cli, this); result != OK) return result;
        result = httpPost(cli, path, hdrs, std::string(body.cbegin(), body.cend()), rsp);
    } else {
        httplib::SSLClient cli(host, port);
        if (result = applySSLTimeout(cli, this); result != OK) return result;
        if (result = setPeerCertificates(cli, this, buildURL(host, port)); result != OK) return result;
        if (result = setProxy(cli, this); result != OK) return result;
        result = httpPost(cli, path, hdrs, std::string(body.cbegin(), body.cend()), rsp);
    }
    if (result != libcdoc::OK) return result;

    headers.clear();
    for (const auto& hdr : rsp.headers) {
        headers.insert({headerKey(hdr.first), hdr.second});
    }
    body.assign(rsp.body.begin(), rsp.body.end());

    return libcdoc::OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::sendKey (CapsuleInfo& dst, const std::string& url, const std::vector<uint8_t>& rcpt_key, const std::vector<uint8_t> &key_material, const std::string& type, uint64_t expiry_ts)
{
    LOG_DBG("NetworkBackend::Sendkey");
    picojson::object obj = {
        {"recipient_id", picojson::value(libcdoc::toBase64(rcpt_key))},
        {"ephemeral_key_material", picojson::value(libcdoc::toBase64(key_material))},
        {"capsule_type", picojson::value(type)}
    };
    picojson::value req_json(obj);
    std::string req_str = req_json.serialize();

    std::string full = joinUrl(url, "/key-capsules");
    std::map<std::string, std::string> headers;
    if (expiry_ts) {
        std::string expiry_str = timeToISO(expiry_ts);
        LOG_DBG("Expiry time: {}", expiry_str);
        headers.emplace("x-expiry-time", expiry_str);
    }
    std::vector<uint8_t> body(req_str.begin(), req_str.end());
    result_t result = post(full, body, headers, false);
    if (result != libcdoc::OK) return result;

    std::string location;
    if (auto it = headers.find("location"); it != headers.end())
        location = it->second;
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

    std::string expiry_str;
    if (auto it = headers.find("x-expiry-time"); it != headers.end())
        expiry_str = it->second;
    LOG_DBG("Server expiry: {}", expiry_str);
    if (expiry_str.empty()) {
        dst.expiry_time = expiry_ts;
        LOG_DBG("Given expiry timestamp: {}", dst.expiry_time);
    } else {
        double parsed = timeFromISO(expiry_str);
        if (parsed < 0) {
            LOG_WARN("Invalid server expiry '{}', using client-supplied expiry", expiry_str);
            dst.expiry_time = expiry_ts;
        } else {
            dst.expiry_time = uint64_t(parsed);
        }
        LOG_DBG("Server expiry timestamp: {}", dst.expiry_time);
    }

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchKey (std::vector<uint8_t>& dst, const std::string& url, const std::string& transaction_id)
{
    // S12: transaction_id comes from the (untrusted) container
    std::string full = joinUrl(url, "/key-capsules/") + urlEncodeComponent(transaction_id);
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;
    result_t result = get(full, body, headers, true);
    if (result != libcdoc::OK) return result;

    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, std::string(body.begin(), body.end()));
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!rsp_json.is<picojson::object>()) {
        error = "Invalid Authentication response";
        LOG_ERROR("{}", error);
        return NetworkBackend::NETWORK_ERROR;
    }

    std::string ks = getJsonString(rsp_json, "ephemeral_key_material", result);
    if (result != libcdoc::OK) return NETWORK_ERROR;
    dst = fromBase64(ks);
    if (dst.empty()) {
        error = FORMAT("Invalid base64 in 'ephemeral_key_material'");
        LOG_WARN("{}", error);
        return NETWORK_ERROR;
    }

    return libcdoc::OK;
}

#ifdef HAS_KEYSHARES
struct MIDSIDResultData {
    int code;
    std::string_view str;
    std::string_view desc;
};

static constexpr auto midsid_results = std::to_array<MIDSIDResultData>({
    // Smart-ID v3.1+ session endResult codes
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
    // Mobile-ID session end result codes
    {libcdoc::NetworkBackend::MIDSID_NOT_MID_CLIENT, "NOT_MID_CLIENT", "user has no active Mobile-ID certificates"},
    {libcdoc::NetworkBackend::MIDSID_USER_CANCELLED, "USER_CANCELLED", "user rejected the operation on the device"},
    {libcdoc::NetworkBackend::MIDSID_SIGNATURE_HASH_MISMATCH, "SIGNATURE_HASH_MISMATCH", "mismatch between SIM and service provider configuration"},
    {libcdoc::NetworkBackend::MIDSID_PHONE_ABSENT, "PHONE_ABSENT", "SIM card is not available"},
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

libcdoc::result_t
libcdoc::NetworkBackend::getAuthResponse(const std::string& url, std::vector<uint8_t>& body,
    std::map<std::string, std::string>& headers)
{
    std::string host, path;
    int port;
    result_t result = parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    if (result = setPeerCertificates(cli, this, buildURL(host, port)); result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    // POST /auth/start
    std::string full = path + "/auth/start";
    httplib::Headers hdrs;
    for (const auto& h : headers) {
        hdrs.insert({h.first, h.second});
    }
    httplib::Response rsp;
    result = httpPost(cli, full, hdrs, std::string(body.cbegin(), body.cend()), rsp);
    if (result != libcdoc::OK) return result;

    // Parse Location header for the polling path
    std::string location = rsp.get_header_value("Location");
    LOG_DBG("Location: {}", location);
    if (location.empty()) {
        error = FORMAT("No Location header in response");
        return NETWORK_ERROR;
    }
    // M3: the Location header path includes the server base path (from the
    // configured URL), so prefix-check against path + "/auth/status/" rather
    // than a hardcoded root-relative path. parseURL strips the trailing '/'
    // from path, so path + "/auth/status/" is always well-formed.
    const std::string prefix = path + "/auth/status/";
    if (location.compare(0, prefix.size(), prefix) != 0) {
        error = FORMAT("Unexpected Location header value");
        return NETWORK_ERROR;
    }
    std::string auth_proc_uuid = location.substr(prefix.size());

    // Parse the initial response body for the verification code
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

    // Poll GET /auth/status/{uuid} on the same connection until COMPLETE.
    // The server closes idle keep-alive connections (Connection: close), and
    // reusing a dead socket fails with "Cannot connect". Open a fresh
    // connection for each poll instead.
    cli.set_keep_alive(false);

    std::string poll_path = path + "/auth/status/" + auth_proc_uuid;
    double end = getTime() + 60.0;
    while (getTime() < end) {
        httplib::Response poll_rsp;
        httplib::Headers poll_hdrs;
        result = httpGet(cli, poll_hdrs, poll_path, poll_rsp);
        if (result != OK) return result;

        picojson::value poll_json;
        parse_err = picojson::parse(poll_json, poll_rsp.body);
        if (!parse_err.empty()) {
            error = FORMAT("JSON parse error: {}", parse_err);
            LOG_ERROR("{}", error);
            return NETWORK_ERROR;
        }
        if (!poll_json.is<picojson::object>()) {
            error = "Invalid Authentication response";
            LOG_WARN("Invalid Authentication response");
            return NetworkBackend::NETWORK_ERROR;
        }

        std::string status = getJsonString(poll_json, "status", result);
        if (result != OK) return NetworkBackend::NETWORK_ERROR;
        LOG_DBG("Status: {}", status);

        if ((status == "RUNNING") || (status == "STARTED")) {
            std::chrono::milliseconds duration(500);
            std::this_thread::sleep_for(duration);
            continue;
        } else if (status != "COMPLETE") {
            error = FORMAT("Invalid SmartID state: {}", status);
            LOG_WARN("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }

        // State is COMPLETE - return the final response body and headers
        body.assign(poll_rsp.body.cbegin(), poll_rsp.body.cend());
        headers.clear();
        for (const auto& h : poll_rsp.headers) {
            headers.insert({headerKey(h.first), h.second});
        }
        error = {};
        return OK;
    }

    error = "Timeout waiting SID/MID result";
    LOG_WARN("{}", error);
    return UNSPECIFIED_ERROR;
}

libcdoc::result_t
libcdoc::NetworkBackend::getSignResponse(const std::string& url, const std::string& post_path,
    std::vector<uint8_t>& body, std::map<std::string, std::string>& headers,
    const std::string& poll_path_prefix)
{
    std::string host, path;
    int port;
    result_t result = parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;

    httplib::SSLClient cli(host, port);
    if (result = applySSLTimeout(cli, this); result != OK) return result;
    if (result = setPeerCertificates(cli, this, buildURL(host, port)); result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    // POST the signing request
    std::string full = path + post_path;
    httplib::Headers hdrs;
    for (const auto& h : headers) {
        hdrs.insert({h.first, h.second});
    }
    httplib::Response rsp;
    result = httpPost(cli, full, hdrs, std::string(body.cbegin(), body.cend()), rsp);
    if (result != libcdoc::OK) return result;

    // Parse session ID from the response body
    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, rsp.body);
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!rsp_json.is<picojson::object>()) {
        error = "Invalid response";
        LOG_WARN("Invalid response");
        return NetworkBackend::NETWORK_ERROR;
    }
    std::string sessionId = getJsonString(rsp_json, "sessionID", result);
    if (result != libcdoc::OK) return result;
    LOG_DBG("SessionID: {}", sessionId);

    // Poll GET {poll_path_prefix}{sessionID} on the same connection.
    // The server closes idle keep-alive connections (Connection: close), and
    // reusing a dead socket fails with "Cannot connect". Open a fresh
    // connection for each poll instead.
    cli.set_keep_alive(false);

    // S12: session_id comes from the server response
    std::string poll_path = path + poll_path_prefix + urlEncodeComponent(sessionId);
    LOG_DBG("SID/MID session query path: {}", poll_path);
    double end = getTime() + 60.0;
    while (getTime() < end) {
        httplib::Response poll_rsp;
        httplib::Headers poll_hdrs;
        for (const auto& h : headers) {
            poll_hdrs.insert({h.first, h.second});
        }
        result = httpGet(cli, poll_hdrs, poll_path, poll_rsp);
        if (result != OK) return result;

        picojson::value poll_json;
        parse_err = picojson::parse(poll_json, poll_rsp.body);
        if (!parse_err.empty()) {
            error = FORMAT("JSON parse error: {}", parse_err);
            LOG_ERROR("{}", error);
            return NETWORK_ERROR;
        }
        if (!poll_json.is<picojson::object>()) {
            error = "Invalid response";
            LOG_WARN("Invalid response");
            return NetworkBackend::NETWORK_ERROR;
        }

        std::string status = getJsonString(poll_json, "state", result);
        if (result != OK) return result;
        LOG_DBG("State: {}", status);

        if (status == "RUNNING") {
            std::chrono::milliseconds duration(500);
            std::this_thread::sleep_for(duration);
            continue;
        } else if (status != "COMPLETE") {
            error = FORMAT("Invalid state value: {}", status);
            LOG_WARN("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }

        // State is COMPLETE - return the final response body and headers
        body.assign(poll_rsp.body.cbegin(), poll_rsp.body.cend());
        headers.clear();
        for (const auto& h : poll_rsp.headers) {
            headers.insert({headerKey(h.first), h.second});
        }
        error = {};
        return OK;
    }

    error = "Timeout waiting SID/MID result";
    LOG_WARN("{}", error);
    return UNSPECIFIED_ERROR;
}

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

    std::string full = joinUrl(url, "/key-shares");
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body(req_str.begin(), req_str.end());
    result_t result = post(full, body, headers, false);
    if (result != libcdoc::OK) return result;

    std::string location;
    if (auto it = headers.find("location"); it != headers.end())
        location = it->second;
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
    LOG_TRACE("Share: {}", std::string((const char *) dst.data(), dst.size()));

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::authenticateForShares(const std::string& url, const std::string& rcpt_id, const std::string& phone, SessionData& session)
{
    // The session is bound to the actual recipient identity from the lock.
    // A hardcoded or malformed id would break the identity chain
    // (session identity == signing identity == lock recipient).
    if (!parseEtsiRecipientId(rcpt_id).valid()) {
        error = FORMAT("Invalid recipient id: {}", rcpt_id);
        LOG_WARN("{}", error);
        return DATA_FORMAT_ERROR;
    }

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

    std::vector<uint8_t> body(req_str.cbegin(), req_str.cend());
    std::map<std::string, std::string> headers;
    result_t result = getAuthResponse(url, body, headers);
    if (result != libcdoc::OK) return result;

    // Parse the COMPLETE response body
    std::string response_body(body.cbegin(), body.cend());
    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, response_body);
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

    // Check end result
    std::string endResult = getJsonString(rsp_json, "endResult", result);
    if (result != OK) return NetworkBackend::NETWORK_ERROR;
    LOG_DBG("EndResult: {}", endResult);
    if (endResult != "OK") {
        LOG_WARN("Authentication endResult is {}", endResult);
        return parseMIDSIDResult(endResult);
    }

    // Fetch session token and certificate
    session.token = getJsonString(rsp_json, "sessionToken", result);
    if (result != OK) return NetworkBackend::NETWORK_ERROR;
    LOG_TRACE("Session token: {}", session.token);
    session.cert = getJsonString(rsp_json, "signingCertificate", result);
    if (result != OK) return NetworkBackend::NETWORK_ERROR;
    LOG_TRACE("Certificate: {}", session.cert);

    auto parts = split(session.token, '~');
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
        // L2: session token disclosures are session-scoped credentials
        // (they authorize specific share servers) - trace level only.
        LOG_TRACE("Session token part {} ({}) : {}", i, v.size(), v);
        std::vector<uint8_t> decoded_part = fromBase64URL(v);
        LOG_TRACE("Decoded part {} ({}): {}", i, decoded_part.size(), std::string(decoded_part.begin(), decoded_part.end()));
    }

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
libcdoc::NetworkBackend::fetchNonce(std::vector<uint8_t>& dst, const std::string& url, const std::string& share_id, const SessionData& session)
{
    LOG_TRACE("Get nonce from: {}", url);

    SessionToken stoken(session.token);
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
    std::string full = joinUrl(url, "/key-shares/") + urlEncodeComponent(share_id) + "/nonce";
    std::map<std::string, std::string> headers;
    headers.insert({"x-cdoc2-session-token", session_token_disclosed});
    headers.insert({"x-cdoc2-session-x5c", session.cert});
    std::vector<uint8_t> body;
    result_t result = post(full, body, headers, false);
    if (result != libcdoc::OK) return result;

    LOG_TRACE("Response: {}", std::string(body.begin(), body.end()));
    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, std::string(body.begin(), body.end()));
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
    const SessionData& session, const SessionData& auth)
{
    LOG_TRACE("Get share from: {}", url);

    SessionToken stoken(session.token);
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
    std::string full = joinUrl(url, "/key-shares/") + urlEncodeComponent(share_id);
    std::map<std::string, std::string> headers;
    headers.insert({"x-cdoc2-session-token", session_token_disclosed});
    headers.insert({"x-cdoc2-session-x5c", session.cert});
    headers.insert({"x-cdoc2-auth-token", auth.token});
    headers.insert({"x-cdoc2-auth-x5c", auth.cert});
    for (const auto& val : auth.params) {
        headers.insert({val.first, val.second});
    }
    std::vector<uint8_t> body;
    result_t result = get(full, body, headers, false);
    if (result != libcdoc::OK) return result;

    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, std::string(body.begin(), body.end()));
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
    LOG_TRACE("Share64: {}", share64);
    std::string recipient = getJsonString(rsp_json, "recipient", rv);
    if (rv != libcdoc::OK) return rv;
    std::vector<uint8_t> shareval = fromBase64(share64);
    if (shareval.size() != 32) {
        error = FORMAT("Invalid share size: expected 32, got {}", shareval.size());
        return NETWORK_ERROR;
    }
    LOG_TRACE("Share: {}", toHex(shareval));
    share = {std::move(shareval), std::move(recipient)};
    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::showFeedback(SIDMIDFeedback& feedback)
{
    LOG_INFO("Verification code: {:04d} url: {}", feedback.code, feedback.url);
    std::cout << "#############################" << "\n";
    std::cout << FORMAT("# Verification code: {:04d} #", feedback.code) << "\n";
    std::cout << "#############################" << "\n";
    return OK;
}

//
// https://open-eid.github.io/CDOC2/
//

libcdoc::result_t
libcdoc::NetworkBackend::signSID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert, std::map<std::string, std::string>& params,
    const std::string& url, const SessionData& session,
    const std::string& rcpt_id, std::string& text, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo)
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

    SessionToken stoken(session.token);
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

    // The confirmation text shown on the user's device (displayText200).
    // Fall back to the generic prompt when no text was configured.
    const std::string display_text = text.empty() ? std::string(CDOC2_DEFAULT_DISPLAY_TEXT) : text;
    // displayText200 allows at most 200 characters.
    size_t n_chars = 0, n_ext = 0;
    bool gsm7 = true, bmp = true;
    result_t result = libcdoc::classifyDisplayText(display_text, n_chars, n_ext, gsm7, bmp);
    if (result != OK) {
        error = "Display text is not valid UTF-8";
        LOG_WARN("{}", error);
        return result;
    }
    if (n_chars > 200) {
        error = FORMAT("Display text too long ({} characters, max 200)", n_chars);
        LOG_WARN("{}", error);
        return libcdoc::DATA_FORMAT_ERROR;
    }
    // Build the interactions array with picojson so the text is properly
    // JSON-escaped.
    picojson::object inter = {
        {"type", picojson::value("confirmationMessageAndVerificationCodeChoice")},
        {"displayText200", picojson::value(display_text)}
    };
    picojson::array inter_arr = {
        picojson::value(inter)
    };
    std::string inter_str = picojson::value(inter_arr).serialize();
    LOG_DBG("Interactions: {}", inter_str);
    inter_str = toBase64((const uint8_t *) inter_str.data(), inter_str.size());
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

    // Generate code
    SIDMIDFeedback fb;
    std::array<uint8_t, 32> b;
    SHA256(digest.data(), digest.size(), b.data());
    fb.code = ((b[30] << 8) | b[31]) % 10000;
    result = showFeedback(fb);
    if (result != OK) return result;

    std::string query_str = query.serialize();
    std::vector<uint8_t> body(query_str.cbegin(), query_str.cend());
    std::map<std::string, std::string> headers = {
        {"x-cdoc2-session-token", session_token_disclosed},
        {"x-cdoc2-session-x5c", session.cert}
    };
    result = getSignResponse(url, "/sid/authenticate", body, headers, "/sid/session/");
    if (result != libcdoc::OK) return result;

    // Parse the COMPLETE response body
    std::string response_body(body.cbegin(), body.cend());
    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, response_body);
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!rsp_json.is<picojson::object>()) {
        error = "Invalid response";
        LOG_WARN("Invalid response");
        return NetworkBackend::NETWORK_ERROR;
    }

    // Check end result
    picojson::object result_obj = getJsonObject(rsp_json, "result", result);
    if (result != OK) return result;
    std::string endResult = getJsonString(picojson::value(result_obj), "endResult", result);
    if (result != OK) return result;
    result = parseMIDSIDResult(endResult);
    if (result == UNSPECIFIED_ERROR) {
        error = FORMAT("unknown endResult value: {}", endResult);
        LOG_WARN("{}", error);
        return NetworkBackend::NETWORK_ERROR;
    } else if (result != OK) {
        LOG_WARN("EndResult is not OK: {}", endResult);
        return result;
    }

    // Signature (optional field)
    std::string signature;
    picojson::object signature_json;
    if (picojson::value sig = rsp_json.get("signature"); sig.is<picojson::object>()) {
        signature = getJsonString(sig, "value", result);
        if (result != OK) return result;
        signature_json = sig.get<picojson::object>();
        signature_json.erase("value");
    }
    // Interaction type
    std::string inter_type_used = getJsonString(rsp_json, "interactionTypeUsed", result);
    if (result != OK) return result;

    // Certificate
    picojson::object cert_obj = getJsonObject(rsp_json, "cert", result);
    if (result != OK) return result;
    std::string cert_b64 = getJsonString(picojson::value(cert_obj), "value", result);
    if (result != OK) return result;

    LOG_DBG("Certificate: {}", cert_b64);
    LOG_DBG("Signature: {}", signature);

    SHA256((uint8_t *) inter_str.c_str(), inter_str.size(), b.data());
    std::string inter_hash_64 = toBase64(b.data(), b.size());

    picojson::object sig_parms = {
        {"interactionsDigest", picojson::value(inter_hash_64)},
        {"interactionTypeUsed", picojson::value(inter_type_used)},
        {"signature", picojson::value(signature_json)},
    };

    dst = fromBase64(signature);
    cert = fromBase64(cert_b64);
    params[X_CDOC2_SID_RPV3_SIGNATURE_PARAMETERS] = toBase64URL(picojson::value(sig_parms).serialize());

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::signMID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert, std::map<std::string, std::string>& params,
    const std::string& url, const std::string& phone, const SessionData& session,
    const std::string& rcpt_id, std::string& text, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo)
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

    SessionToken stoken(session.token);
    std::string session_token_disclosed = stoken.discloseForUrl(url);

    // S10: never send an empty session token header. A missing disclosure
    // means the token is malformed or the server is not authorized for this
    // session - fail before making the request.
    if (session_token_disclosed.empty()) {
        error = FORMAT("Session token has no disclosure for {}", url);
        LOG_WARN("{}", error);
        return libcdoc::DATA_FORMAT_ERROR;
    }

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
    result_t result = showFeedback(fb);
    if (result != OK) return result;

    // The confirmation text shown on the user's device (displayText).
    // Fall back to the generic prompt when no text was configured.
    const std::string display_text = text.empty() ? std::string(CDOC2_DEFAULT_DISPLAY_TEXT) : text;
    // Choose the encoding: GSM-7 when the text is fully representable in
    // the GSM 03.38 alphabet, UCS-2 otherwise. Per the MID API the field
    // is limited to 100 characters in GSM-7 (of which at most 5 from the
    // extension table) or 50 characters in UCS-2.
    size_t n_chars = 0, n_ext = 0;
    bool gsm7 = true, bmp = true;
    result = libcdoc::classifyDisplayText(display_text, n_chars, n_ext, gsm7, bmp);
    if (result != OK) {
        error = "Display text is not valid UTF-8";
        LOG_WARN("{}", error);
        return result;
    }
    const char *text_format;
    if (gsm7) {
        if (n_chars > 100 || n_ext > 5) {
            error = FORMAT("Display text too long for GSM-7 ({} characters, {} extension)", n_chars, n_ext);
            LOG_WARN("{}", error);
            return libcdoc::DATA_FORMAT_ERROR;
        }
        text_format = "GSM-7";
    } else {
        if (!bmp) {
            // UCS-2 cannot represent codepoints above U+FFFF.
            error = "Display text contains characters not representable in UCS-2";
            LOG_WARN("{}", error);
            return libcdoc::DATA_FORMAT_ERROR;
        }
        if (n_chars > 50) {
            error = FORMAT("Display text too long for UCS-2 ({} characters, max 50)", n_chars);
            LOG_WARN("{}", error);
            return libcdoc::DATA_FORMAT_ERROR;
        }
        text_format = "UCS-2";
    }

    picojson::object qobj = {
        {"phoneNumber", picojson::value(phone)},
        {"nationalIdentityNumber", picojson::value(id_num)},
        {"hash", picojson::value(toBase64(digest))},
        {"hashType", picojson::value(std::string(algo_name))},
        {"language", picojson::value("ENG")},
        {"displayText", picojson::value(display_text)},
        {"displayTextFormat", picojson::value(text_format)}
    };
    picojson::value query = picojson::value(qobj);
    LOG_DBG("JSON:{}", query.serialize());

    std::string query_str = query.serialize();
    std::vector<uint8_t> body(query_str.cbegin(), query_str.cend());
    std::map<std::string, std::string> headers = {
        {"x-cdoc2-session-token", session_token_disclosed},
        {"x-cdoc2-session-x5c", session.cert}
    };
    result = getSignResponse(url, "/mid/authenticate", body, headers, "/mid/session/");
    if (result != libcdoc::OK) return result;

    // Parse the COMPLETE response body
    std::string response_body(body.cbegin(), body.cend());
    picojson::value rsp_json;
    std::string parse_err = picojson::parse(rsp_json, response_body);
    if (!parse_err.empty()) {
        error = FORMAT("JSON parse error: {}", parse_err);
        LOG_ERROR("{}", error);
        return NETWORK_ERROR;
    }
    if (!rsp_json.is<picojson::object>()) {
        error = "Invalid response";
        LOG_WARN("Invalid response");
        return NetworkBackend::NETWORK_ERROR;
    }

    // Check end result
    std::string endResult = getJsonString(rsp_json, "result", result);
    if (result != OK) return result;
    result = parseMIDSIDResult(endResult);
    if (result == UNSPECIFIED_ERROR) {
        error = FORMAT("unknown endResult value: {}", endResult);
        LOG_WARN("{}", error);
        return NetworkBackend::NETWORK_ERROR;
    } else if (result != OK) {
        LOG_WARN("EndResult is not OK: {}", endResult);
        return result;
    }

    // Signature
    picojson::object sig_obj = getJsonObject(rsp_json, "signature", result);
    if (result != OK) return result;
    std::string signature = getJsonString(picojson::value(sig_obj), "value", result);
    if (result != OK) return result;
    std::string cert_b64 = getJsonString(rsp_json, "cert", result);
    if (result != OK) return result;

    LOG_DBG("Certificate: {}", cert_b64);
    LOG_DBG("Signature: {}", signature);

    // Extract MID-specific response headers
    auto get_hdr = [&](const std::string& name) -> std::string {
        if (auto it = headers.find(name); it != headers.end())
            return it->second;
        return {};
    };
    params[X_RP_SIGNED_HASH] = get_hdr("x-rp-signed-hash");
    params[X_RP_NAME] = get_hdr("x-rp-name");
    params[HDR_SIGNATURE_INPUT] = get_hdr("signature-input");
    params[HDR_SIGNATURE] = get_hdr("signature");

    LOG_DBG("x-rp-signed-hash: {}", params[X_RP_SIGNED_HASH]);
    LOG_DBG("x-rp-name: {}", params[X_RP_NAME]);
    LOG_DBG("Signature-Input: {}", params[HDR_SIGNATURE_INPUT]);
    LOG_DBG("Signature: {}", params[HDR_SIGNATURE]);

    dst = fromBase64(signature);
    cert = fromBase64(cert_b64);

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
