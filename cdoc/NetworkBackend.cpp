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

#include "Crypto.h"
#include "CryptoBackend.h"
#include "Utils.h"
#include "utils/memory.h"
#include "ILogger.h"

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

using namespace std::literals::chrono_literals;

using EC_KEY_sign = int (*)(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
using EC_KEY_sign_setup = int (*)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);

static ECDSA_SIG* ecdsa_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey);
static int rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const ::RSA *rsa);

struct Private {
    libcdoc::unique_free_t<X509> x509{nullptr, X509_free};
    EVP_PKEY *pkey = nullptr;

    RSA_METHOD *rsamethod = nullptr;
    EC_KEY_METHOD *ecmethod = nullptr;

    explicit Private(libcdoc::NetworkBackend *backend, std::vector<uint8_t> client_cert) {
        if (client_cert.empty()) return;
        x509 = libcdoc::Crypto::toX509(client_cert);
        if (!x509) return;
        pkey = X509_get_pubkey(x509.get());
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

struct MIDSIDResultData {
    int code;
    std::string_view str;
    std::string_view desc;
};

static constexpr auto midsid_results = std::to_array<MIDSIDResultData>({
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED, "USER_REFUSED", "User refused the session"},
    {libcdoc::NetworkBackend::MIDSID_TIMEOUT, "TIMEOUT", "User did not confirm action within the timeframe"},
    {libcdoc::NetworkBackend::MIDSID_DOCUMENT_UNUSABLE, "DOCUMENT_UNUSABLE", "Smart document unusable, please contact Smart ID customer support"},
    {libcdoc::NetworkBackend::MIDSID_WRONG_VC, "WRONG_VC", "User chose a wrong Smart ID verification code"},
    {libcdoc::NetworkBackend::MIDSID_REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP, "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP", "Smart ID app does not support current protocol"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_CERT_CHOICE, "USER_REFUSED_CERT_CHOICE", "User refused certificate choice"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_DISPLAYTEXTANDPIN, "USER_REFUSED_DISPLAYTEXTANDPIN", "User canceled the PIN choice"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_VC_CHOICE, "USER_REFUSED_VC_CHOICE", "User canceled the verification code choice"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_CONFIRMATIONMESSAGE, "USER_REFUSED_CONFIRMATIONMESSAGE", "User refused the confirmation message"},
    {libcdoc::NetworkBackend::MIDSID_USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE, "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE", "User refused the confirmation message and verification code choice"},
    {libcdoc::NetworkBackend::MIDSID_NOT_MID_CLIENT, "NOT_MID_CLIENT", "User is not a Mobile ID client"},
    {libcdoc::NetworkBackend::MIDSID_USER_CANCELLED, "USER_CANCELLED", "User canceled the Mobile ID operation"},
    {libcdoc::NetworkBackend::MIDSID_SIGNATURE_HASH_MISMATCH, "SIGNATURE_HASH_MISMATCH", "SIM card signature mismatch, please contact the mobile provider"},
    {libcdoc::NetworkBackend::MIDSID_PHONE_ABSENT, "PHONE_ABSENT", "SIM card is not available"},
    {libcdoc::NetworkBackend::MIDSID_DELIVERY_ERROR, "DELIVERY_ERROR", "SMS sending error"},
    {libcdoc::NetworkBackend::MIDSID_SIM_ERROR, "SIM_ERROR", "Invalid response from SIM card"}
});

static int
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

thread_local std::string error;

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
    std::string_view str = getMIDSIDDescription(code);
    if (!str.empty()) return std::string(str);
    return libcdoc::getErrorStr(code);
}

#if LIBCDOC_TESTING
int64_t
libcdoc::NetworkBackend::test(std::vector<std::vector<uint8_t>> &dst)
{
    LOG_TRACE("NetworkBackend::test::Native superclass");
    return OK;
}
#endif

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
    if (!certs.empty()) {
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            auto x509 = libcdoc::Crypto::toX509(c);
            if (!x509) return libcdoc::CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.get());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    } else {
        // TODO: Allow only if global parameter is set
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
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
// Post request and fetch response
//
static libcdoc::result_t
post(httplib::SSLClient& cli, const std::string& path, const std::string& req, httplib::Response& rsp)
{
    // Capture TLS and HTTP errors
    httplib::Result res = cli.Post(path, req, "application/json");
    if (!res) {
        error = FORMAT("Cannot connect to https://{}:{}{}", cli.host(), cli.port(), path);
        return libcdoc::NetworkBackend::NETWORK_ERROR;
    }
    int status = res->status;
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
get(httplib::SSLClient& cli, httplib::Headers& hdrs, const std::string& path, picojson::value& rsp_json)
{
    // Capture TLS and HTTP errors
    httplib::Result res = cli.Get(path, hdrs);
    if (!res) {
        error = FORMAT("Cannot connect to https://{}:{}{}", cli.host(), cli.port(), path);
        return libcdoc::NetworkBackend::NETWORK_ERROR;
    }
    httplib::Response rsp = res.value();
    auto status = rsp.status;
    if ((status < 200) || (status >= 300)) {
        error = FORMAT("Http status {}", status);
        return libcdoc::NetworkBackend::NETWORK_ERROR;
    }
    picojson::parse(rsp_json, rsp.body);
    error = {};
    return libcdoc::OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::sendKey (CapsuleInfo& dst, const std::string& url, const std::vector<uint8_t>& rcpt_key, const std::vector<uint8_t> &key_material, const std::string& type)
{
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
    if (path.ends_with('/')) path.resize(path.size() - 1);

    httplib::SSLClient cli(host, port);
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    std::string full = path + "/key-capsules";
    httplib::Response rsp;
    result = post(cli, full, req_str, rsp);
    if (result != libcdoc::OK) return result;

    std::string location = rsp.get_header_value("Location");
    if (location.empty()) {
        error = FORMAT("No Location header in response");
        return NETWORK_ERROR;
    }
    error = {};

    /* Remove /key-capsules/ */
    dst.transaction_id = location.substr(14);

    // Calculate expiry time
    auto now = std::chrono::system_clock::now();
    // Get a days-precision chrono::time_point
    auto sd = floor<std::chrono::days>(now);
    // Record the time of day
    auto time_of_day = now - sd;
    // Convert to a y/m/d calendar data structure
    std::chrono::year_month_day ymd = sd;
    // Add the months
    ymd += std::chrono::months{6};
    // Add some policy for overflowing the day-of-month if desired
    if (!ymd.ok())
        ymd = ymd.year()/ymd.month()/std::chrono::last;
    // Convert back to system_clock::time_point
    std::chrono::system_clock::time_point later = std::chrono::sys_days{ymd} + time_of_day;
    auto ttt = std::chrono::system_clock::to_time_t(later);

    dst.expiry_time = ttt;

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::sendShare(std::vector<uint8_t>& dst, const std::string& url, const std::string& recipient, const std::vector<uint8_t>& share)
{
    // Create KeyShare container
    picojson::object obj = {
        {"share", picojson::value(libcdoc::toBase64(share))},
        {"recipient", picojson::value(recipient)}
    };
    picojson::value req_json(obj);
    std::string req_str = req_json.serialize();
    LOG_DBG("POST keyshare to: {}", url);
    LOG_DBG("{}", req_str);

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path.ends_with('/')) path.resize(path.size() - 1);

    httplib::SSLClient cli(host, port);
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    std::string full = path + "/key-shares";
    httplib::Response rsp;
    result = post(cli, full, req_str, rsp);
    if (result != libcdoc::OK) return result;

    std::string location = rsp.get_header_value("Location");
    if (location.empty()) {
        error = FORMAT("No Location header in response");
        return NETWORK_ERROR;
    }
    error = {};

    /* Remove /key-shares/ */
    dst.assign(location.cbegin() + 12, location.cend());
    LOG_DBG("Share: {}", std::string((const char *) dst.data(), dst.size()));

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchKey (std::vector<uint8_t>& dst, const std::string& url, const std::string& transaction_id)
{
    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path.ends_with('/')) path.resize(path.size() - 1);

    std::vector<uint8_t> cert;
    result = getClientTLSCertificate(cert);
    if (result != OK) return result;
    std::unique_ptr<Private> d = std::make_unique<Private>(this, cert);
    if (!cert.empty() && (!d->x509 || !d->pkey)) return CRYPTO_ERROR;

    httplib::SSLClient cli(host, port, d->x509.get(), d->pkey);
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    std::string full = path + "/key-capsules/" + transaction_id;
    httplib::Headers hdrs;
    picojson::value rsp_json;
    result = get(cli, hdrs, full, rsp_json);
    if (result != libcdoc::OK) return result;

    picojson::value v = rsp_json.get("ephemeral_key_material");
    if (!v.is<std::string>()) {
        error = FORMAT("No 'ephemeral_key_material' in response");
        return NETWORK_ERROR;
    }
    error = {};
    std::string ks = v.get<std::string>();
    std::vector<uint8_t> key_material = fromBase64(ks);
    dst.assign(key_material.cbegin(), key_material.cend());

    return libcdoc::OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchNonce(std::vector<uint8_t>& dst, const std::string& url, const std::string& share_id)
{
    LOG_DBG("Get nonce from: {}", url);

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path.ends_with('/')) path.resize(path.size() - 1);

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    std::string full = path + "/key-shares/" + share_id + "/nonce";
    httplib::Response rsp;
    result = post(cli, full, "", rsp);
    if (result != libcdoc::OK) return result;

    LOG_DBG("Response: {}", rsp.body);
    picojson::value rsp_json;
    picojson::parse(rsp_json, rsp.body);
    picojson::value v = rsp_json.get("nonce");
    if (!v.is<std::string>()) {
        error = FORMAT("No 'nonce' in response");
        return NETWORK_ERROR;
    }
    std::string nonce_str = v.get<std::string>();
    dst.assign(nonce_str.cbegin(), nonce_str.cend());
    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchShare(ShareInfo& share, const std::string& url, const std::string& share_id, const std::string& ticket, const std::vector<uint8_t>& cert)
{
    LOG_DBG("Get share from: {}", url);

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path.ends_with('/')) path.resize(path.size() - 1);

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);

    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    std::string full = path + "/key-shares/" + share_id;
    LOG_DBG("Share url: {}", full);
    httplib::Headers hdrs;
    hdrs.insert({"x-cdoc2-auth-ticket", ticket});
    hdrs.insert({"x-cdoc2-auth-x5c", std::string("-----BEGIN CERTIFICATE-----") + toBase64(cert) + "-----END CERTIFICATE-----"});
    for (auto i = hdrs.cbegin(); i != hdrs.cend(); i++) {
        std::cerr << i->first << ": " << i->second << std::endl;
    }
    picojson::value rsp_json;
    result = get(cli, hdrs, full, rsp_json);
    if (result != libcdoc::OK) return result;

    picojson::value v = rsp_json.get("share");
    if (!v.is<std::string>()) {
        error = FORMAT("No 'share' in response");
        return NETWORK_ERROR;
    }
    std::string share64 = v.get<std::string>();
    LOG_DBG("Share64: {}", share64);
    v = rsp_json.get("recipient");
    if (!v.is<std::string>()) {
        error = FORMAT("No 'recipient' in response");
        return NETWORK_ERROR;
    }
    std::string recipient = v.get<std::string>();
    std::vector<uint8_t> shareval = fromBase64(share64);
    shareval.resize(32);
    LOG_DBG("Share: {}", toHex(shareval));
    share = {shareval, recipient};
    return OK;
}

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

libcdoc::result_t
libcdoc::NetworkBackend::showVerificationCode(unsigned int code)
{
    LOG_INFO("Verification code: {:04d}", code);
    return OK;
}

//
// https://github.com/SK-EID/smart-id-documentation
//

struct SIDResponse {
    // Signature value, base64 encoded
    std::string signature;
    // Signature algorithm, in the form of sha256WithRSAEncryption
    std::string algorithm;
    // Signer certificate, base64 encoded
    std::string cert;
};

namespace libcdoc {

static result_t
waitForResult(SIDResponse& dst, httplib::SSLClient& cli, const std::string& path, const std::string& session_id, double seconds, bool is_sid)
{
    httplib::Headers hdrs;

    double end = libcdoc::getTime() + seconds;
    std::string full = path + session_id + "?timeoutMs=" + std::to_string((int) (seconds * 1000));
    LOG_DBG("SID/MID session query path: {}", full);
    while (libcdoc::getTime() < end) {
        picojson::value rsp;
        result_t result = get(cli, hdrs, full, rsp);
        if (result != OK) return result;
        if (!rsp.is<picojson::object>()) {
            error = "Response is not a JSON object";
            LOG_WARN("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }
        // State
        picojson::value v = rsp.get("state");
        if (!v.is<std::string>()) {
            error = "State is not a string";
            LOG_WARN("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }
        std::string str = v.get<std::string>();
        if (str == "RUNNING") {
            // Pause for 0.5 seconds and repeat
            std::chrono::milliseconds duration(500);
            std::this_thread::sleep_for(duration);
            continue;
        } else if (str != "COMPLETE") {
            error = FORMAT("Invalid SmartID state: {}", str);
            LOG_WARN("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }
        // State is complete, check for end result
        v = rsp.get("result");
        picojson::value w;
        if (is_sid) {
            if (!v.is<picojson::object>()) {
                error = "Result is not a JSON object";
                LOG_WARN("{}", error);
                return NetworkBackend::NETWORK_ERROR;
            }
            w = v.get("endResult");
        } else {
            w = v;
        }
        if (!w.is<std::string>()) {
            error = "EndResult is not a string";
            LOG_WARN("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }
        str = w.get<std::string>();
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

        // Signature
        v = rsp.get("signature");
        if (v.is<picojson::object>()) {
            w = v.get("value");
            if (!w.is<std::string>()) {
                error = "Value is not a string";
                LOG_WARN("{}", error);
                return NetworkBackend::NETWORK_ERROR;
            }
            dst.signature = w.get<std::string>();
            w = v.get("algorithm");
            if (!w.is<std::string>()) {
                error = "Algorithm is not a string";
                LOG_WARN("{}", error);
                return NetworkBackend::NETWORK_ERROR;
            }
            dst.algorithm = w.get<std::string>();
        }
        // Certificate
        v = rsp.get("cert");
        if (is_sid) {
            if (!v.is<picojson::object>()) {
                error = "Certificate is not a JSON object";
                LOG_WARN("{}", error);
                return NetworkBackend::NETWORK_ERROR;
            }
            w = v.get("value");
        } else {
            w = rsp.get("cert");
        }
        if (!w.is<std::string>()) {
            error = "Certificate value is not a string";
            LOG_WARN("{}", error);
            return NetworkBackend::NETWORK_ERROR;
        }
        dst.cert = w.get<std::string>();
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
libcdoc::NetworkBackend::signSID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert,
    const std::string& url, const std::string& rp_uuid, const std::string& rp_name,
    const std::string& rcpt_id, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo)
{
    std::string certificateLevel = "QUALIFIED";
    std::string nonce = libcdoc::toBase64(Crypto::random(16));

    picojson::object obj = {
        {"relyingPartyUUID", picojson::value(rp_uuid)},
        {"relyingPartyName", picojson::value(rp_name)},
        {"certificateLevel", picojson::value(certificateLevel)},
        {"nonce", picojson::value(nonce)}
    };
    picojson::value query(obj);
    LOG_DBG("JSON:{}", query.serialize());

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path.ends_with('/')) path.resize(path.size() - 1);
    LOG_DBG("URL:{}", url);
    LOG_DBG("HOST:{}", host);
    LOG_DBG("PORT:{}", port);
    LOG_DBG("PATH:{}", path);

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    //
    // Let user choose certificate (if multiple)
    //
    std::string full = path + "/certificatechoice/" + rcpt_id;
    LOG_DBG("SmartID path: {}", full);
    httplib::Response rsp;
    result = post(cli, full, query.serialize(), rsp);
    if (result != libcdoc::OK) return result;


    LOG_DBG("Response: {}", rsp.body);
    picojson::value v;
    picojson::parse(v, rsp.body);
    if (!v.is<picojson::object>()) {
        error = "Invalid SmartID response";
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    picojson::value w = v.get("sessionID");
    if (!w.is<std::string>()) {
        error = "Invalid SmartID response";
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    std::string sessionID  = w.get<std::string>();
    LOG_DBG("SessionID: {}", sessionID);

    SIDResponse sidrsp;
    result = waitForResult(sidrsp, cli, path + "/session/", sessionID, 60, true);
    if (result != OK) return result;
    LOG_DBG("Certificate: {}", sidrsp.cert);

    //
    // Sign
    //
    std::string algo_names[] = {"SHA224", "SHA256", "SHA384", "SHA512"};
    std::string algo_name = algo_names[(int) algo];

    // Generate code
    uint8_t b[32];
    SHA256(digest.data(), digest.size(), b);
    unsigned int code = ((b[30] << 8) | b[31]) % 10000;
    result = showVerificationCode(code);
    if (result != OK) return result;

    picojson::object aio1 = {
        {"type", picojson::value("confirmationMessageAndVerificationCodeChoice")},
        {"displayText200", picojson::value("Do you want to decrypt the document")}
    };
    picojson::array aio = {
        picojson::value(aio1)
    };
    picojson::object qobj = {
        {"relyingPartyUUID", picojson::value(rp_uuid)},
        {"relyingPartyName", picojson::value(rp_name)},
        {"hash", picojson::value(toBase64(digest))},
        {"hashType", picojson::value(algo_name)},
        {"allowedInteractionsOrder",
            picojson::value(aio)
        }
    };
    query = picojson::value(qobj);
    LOG_DBG("JSON:{}", query.serialize());
    //
    // Sign digest
    //
    full = path + "/authentication/" + rcpt_id;
    LOG_DBG("SmartID path: {}", full);
    result = post(cli, full, query.serialize(), rsp);
    if (result != libcdoc::OK) return result;
    LOG_DBG("Response: {}", rsp.body);
    picojson::parse(v, rsp.body);
    if (!v.is<picojson::object>()) {
        error = "Invalid SmartID response";
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    w = v.get("sessionID");
    if (!w.is<std::string>()) {
        error = "Invalid SmartID response";
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    sessionID  = w.get<std::string>();
    LOG_DBG("SessionID: {}", sessionID);

    sidrsp = {};
    result = waitForResult(sidrsp, cli, path + "/session/", sessionID, 60, true);
    if (result != OK) return result;
    LOG_DBG("Certificate: {}", sidrsp.cert);
    LOG_DBG("Signature: {}", sidrsp.signature);

    dst = fromBase64(sidrsp.signature);
    cert = fromBase64(sidrsp.cert);

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::signMID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert,
    const std::string& url, const std::string& rp_uuid, const std::string& rp_name, const std::string& phone,
    const std::string& rcpt_id, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo)
{
    std::string certificateLevel = "QUALIFIED";
    std::string nonce = libcdoc::toBase64(Crypto::random(16));

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path.ends_with('/')) path.resize(path.size() - 1);
    LOG_DBG("URL:{}", url);
    LOG_DBG("HOST:{}", host);
    LOG_DBG("PORT:{}", port);
    LOG_DBG("PATH:{}", path);

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);
    result = setPeerCertificates(cli, this, buildURL(host, port));
    if (result != OK) return result;
    if (result = setProxy(cli, this); result != OK) return result;

    //
    // Authenticate
    //
    std::string algo_names[] = {"SHA224", "SHA256", "SHA384", "SHA512"};
    std::string algo_name = algo_names[(int) algo];

    // Generate code
    unsigned int code = (((digest[0] & 0xfc) << 5) | (digest[digest.size() - 1] & 0x7f));
    result = showVerificationCode(code);
    if (result != OK) return result;

    // etsi/PNOEE-01234567890
    std::string id_num = rcpt_id.substr(11, 11);
    picojson::object qobj = {
        {"relyingPartyUUID", picojson::value(rp_uuid)},
        {"relyingPartyName", picojson::value(rp_name)},
        {"phoneNumber", picojson::value(phone)},
        {"nationalIdentityNumber", picojson::value(id_num)},
        {"hash", picojson::value(toBase64(digest))},
        {"hashType", picojson::value(algo_name)},
        {"language", picojson::value("ENG")},
        {"displayText", picojson::value("Tahad dekryptida?")},
        {"displayTextFormat", picojson::value("GSM-7")}
    };
    picojson::value query = picojson::value(qobj);
    LOG_DBG("JSON:{}", query.serialize());
    //
    // Sign digest
    //
    std::string full = path + "/authentication";
    LOG_DBG("Mobile ID path: {}", full);
    httplib::Response rsp;
    result = post(cli, full, query.serialize(), rsp);
    if (result != libcdoc::OK) return result;
    LOG_DBG("Response: {}", rsp.body);

    picojson::value v;
    picojson::parse(v, rsp.body);
    if (!v.is<picojson::object>()) {
        error = "Invalid Mobile ID response";
        LOG_WARN("Invalid Monbile ID response");
    }
    picojson::value w = v.get("sessionID");
    if (!w.is<std::string>()) {
        error = "Invalid Mobile ID response";
        LOG_WARN("Invalid Monbile ID response");
    }
    std::string sessionID  = w.get<std::string>();
    LOG_DBG("SessionID: {}", sessionID);

    SIDResponse sidrsp;
    result = waitForResult(sidrsp, cli, path + "/authentication/session/", sessionID, 60, false);
    if (result != OK) return result;

    LOG_DBG("Certificate: {}", sidrsp.cert);
    LOG_DBG("Signature: {}", sidrsp.signature);

    dst = fromBase64(sidrsp.signature);
    cert = fromBase64(sidrsp.cert);

    return OK;
}
