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

#define keyserver_id "00000000-0000-0000-0000-000000000000";
#define GET_HOST "cdoc2-keyserver.test.riaint.ee"
#define GET_PORT 8444
#define POST_HOST "cdoc2-keyserver.test.riaint.ee"
#define POST_PORT 8443

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


std::string
libcdoc::NetworkBackend::getLastErrorStr(result_t code) const
{
	switch (code) {
	case OK:
		return "";
	case NOT_IMPLEMENTED:
		return "NetworkBackend: Method not implemented";
	case INVALID_PARAMS:
		return "NetworkBackend: Invalid parameters";
	case NETWORK_ERROR:
		return "NetworkBackend: Network error";
	default:
		break;
	}
	return "Internal error";
}

#if LIBCDOC_TESTING
int64_t
libcdoc::NetworkBackend::test(std::vector<std::vector<uint8_t>> &dst)
{
    LOG_TRACE("NetworkBackend::test::Native superclass");
    return OK;
}
#endif

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
    if (path == "/") path.clear();

    httplib::SSLClient cli(host, port);

    std::vector<std::vector<uint8_t>> certs;
    getPeerTLSCertificates(certs, buildURL(host, port));
    if (!certs.empty()) {
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            auto x509 = Crypto::toX509(c);
            if (!x509) return CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.get());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    } else {
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    std::string full = path + "/key-capsules";
    httplib::Result res = cli.Post(full, req_str, "application/json");
    if (!res) return NETWORK_ERROR;
    auto status = res->status;
    if ((status < 200) || (status >= 300)) return NETWORK_ERROR;

    httplib::Response rsp = res.value();
    std::string location = rsp.get_header_value("Location");
    if (location.empty()) return libcdoc::IO_ERROR;
    /* Remove /key-capsules/ */
    dst.transaction_id = location.substr(14);

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
    if (path == "/") path.clear();

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);

    std::vector<std::vector<uint8_t>> certs;
    LOG_DBG("Fetching certs");
    getPeerTLSCertificates(certs, buildURL(host, port));
    if (!certs.empty()) {
        LOG_DBG("Loading certs");
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            auto x509 = Crypto::toX509(c);
            if (!x509) return CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.get());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    } else {
        LOG_WARN("Share servers' certificate list is empty");
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    // Build url and send request
    std::string full = path + "/key-shares";
    LOG_DBG("Full url: {}", full);
    httplib::Result res = cli.Post(full, req_str, "application/json");
    if (!res) return NETWORK_ERROR;
    auto status = res->status;
    LOG_DBG("Status: {}", status);
    if ((status < 200) || (status >= 300)) return NETWORK_ERROR;

    httplib::Response rsp = res.value();
    std::string location = rsp.get_header_value("Location");
    LOG_DBG("Location: {}", location);
    if (location.empty()) return libcdoc::IO_ERROR;
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
    if (path == "/") path.clear();

    std::vector<uint8_t> cert;
    result = getClientTLSCertificate(cert);
    if (result != OK) return result;
    std::unique_ptr<Private> d = std::make_unique<Private>(this, cert);
    if (!cert.empty() && (!d->x509 || !d->pkey)) return CRYPTO_ERROR;

    httplib::SSLClient cli(host, port, d->x509.get(), d->pkey);

    std::vector<std::vector<uint8_t>> certs;
    getPeerTLSCertificates(certs, buildURL(host, port));
    if (!certs.empty()) {
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            auto x509 = Crypto::toX509(c);
            if (!x509) return CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.get());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    } else {
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    std::string full = path + "/key-capsules/" + transaction_id;
    httplib::Result res = cli.Get(full);
    if (!res) return NETWORK_ERROR;
    httplib::Response rsp = res.value();
    auto status = rsp.status;
    if ((status < 200) || (status >= 300)) return NETWORK_ERROR;
    picojson::value rsp_json;
    picojson::parse(rsp_json, rsp.body);
    std::string ks = rsp_json.get("ephemeral_key_material").get<std::string>();
    std::vector<uint8_t> key_material = Crypto::decodeBase64((const uint8_t *) ks.c_str());
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
    if (path == "/") path.clear();

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);

    std::vector<std::vector<uint8_t>> certs;
    LOG_DBG("Fetching certs");
    getPeerTLSCertificates(certs, buildURL(host, port));
    if (!certs.empty()) {
        LOG_DBG("Loading certs");
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            auto x509 = Crypto::toX509(c);
            if (!x509) return CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.get());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    } else {
        LOG_WARN("Share servers' certificate list is empty");
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    // Build url and send request
    std::string full = path + "/key-shares/" + share_id + "/nonce";
    LOG_DBG("Nonce url: {}", full);
    httplib::Result res = cli.Post(full, "", "application/json");
    if (!res) return NETWORK_ERROR;
    auto status = res->status;
    LOG_DBG("Status: {}", status);
    if ((status < 200) || (status >= 300)) return NETWORK_ERROR;
    httplib::Response rsp = res.value();
    LOG_DBG("Response: {}", rsp.body);
    picojson::value rsp_json;
    picojson::parse(rsp_json, rsp.body);
    std::string nonce_str = rsp_json.get("nonce").get<std::string>();
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
    if (path == "/") path.clear();

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);

    std::vector<std::vector<uint8_t>> certs;
    LOG_DBG("Fetching certs");
    getPeerTLSCertificates(certs, buildURL(host, port));
    if (!certs.empty()) {
        LOG_DBG("Loading certs");
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            auto x509 = Crypto::toX509(c);
            if (!x509) return CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.get());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    } else {
        LOG_WARN("Share servers' certificate list is empty");
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    // Build url and send request
    std::string full = path + "/key-shares/" + share_id;
    LOG_DBG("Share url: {}", full);
    httplib::Headers hdrs;
    hdrs.insert({"x-cdoc2-auth-ticket", ticket});
    hdrs.insert({"x-cdoc2-auth-x5c", std::string("-----BEGIN CERTIFICATE-----") + toBase64(cert) + "-----END CERTIFICATE-----"});
    for (auto i = hdrs.cbegin(); i != hdrs.cend(); i++) {
        std::cerr << i->first << ": " << i->second << std::endl;
    }
    httplib::Result res = cli.Get(full, hdrs);
    if (!res) return NETWORK_ERROR;
    auto status = res->status;
    LOG_DBG("Status: {}", status);
    if ((status < 200) || (status >= 300)) return NETWORK_ERROR;
    httplib::Response rsp = res.value();
    LOG_DBG("Response: {}", rsp.body);
    picojson::value rsp_json;
    picojson::parse(rsp_json, rsp.body);
    std::string share64 = rsp_json.get("share").get<std::string>();
    LOG_DBG("Share64: {}", share64);
    std::string recipient = rsp_json.get("recipient").get<std::string>();
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
    // End result of the transaction
    enum EndResult {
        NONE,
        // session was completed successfully, there is a certificate, document number and possibly signature in return structure
        OK,
        // user refused the session
        USER_REFUSED,
        // there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
        TIMEOUT,
        // for some reason, this RP request cannot be completed. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason
        DOCUMENT_UNUSABLE,
        // in case the multiple-choice verification code was requested, the user did not choose the correct verification code
        WRONG_VC,
        // user app version does not support any of the allowedInteractionsOrder interactions
        REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP,
        // user has multiple accounts and pressed Cancel on device choice screen on any device
        USER_REFUSED_CERT_CHOICE,
        // user pressed Cancel on PIN screen. Can be from the most common displayTextAndPIN flow or from verificationCodeChoice flow when user chosen the right code and then pressed cancel on PIN screen
        USER_REFUSED_DISPLAYTEXTANDPIN,
        // user cancelled verificationCodeChoice screen
        USER_REFUSED_VC_CHOICE,
        // user cancelled on confirmationMessage screen
        USER_REFUSED_CONFIRMATIONMESSAGE,
        // user cancelled on confirmationMessageAndVerificationCodeChoice screen
        USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE
    };

    static EndResult parseEndResult(std::string_view val) {
        if (val == "OK") return OK;
        if (val == "USER_REFUSED") return USER_REFUSED;
        if (val == "TIMEOUT") return TIMEOUT;
        if (val == "DOCUMENT_UNUSABLE") return DOCUMENT_UNUSABLE;
        if (val == "WRONG_VC") return WRONG_VC;
        if (val == "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP") return REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP;
        if (val == "USER_REFUSED_CERT_CHOICE") return USER_REFUSED_CERT_CHOICE;
        if (val == "USER_REFUSED_DISPLAYTEXTANDPIN") return USER_REFUSED_DISPLAYTEXTANDPIN;
        if (val == "USER_REFUSED_VC_CHOICE") return USER_REFUSED_VC_CHOICE;
        if (val == "USER_REFUSED_CONFIRMATIONMESSAGE") return USER_REFUSED_CONFIRMATIONMESSAGE;
        if (val == "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE") return USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE;
        return NONE;
    }

    struct Signature {
        std::string value;
    };

    // End result of the transaction
    EndResult endResult = NONE;

    // Signature value, base64 encoded
    std::string signature;
    // Signature algorithm, in the form of sha256WithRSAEncryption
    std::string algorithm;
    // Signer certificate, base64 encoded
    std::string cert;
};

namespace libcdoc {

static result_t
waitForResult(SIDResponse& dst, httplib::SSLClient& cli, const std::string& path, const std::string& session_id, double seconds)
{
    double end = libcdoc::getTime() + seconds;
    std::string full = path + session_id + "?timeoutMs=" + std::to_string((int) (seconds * 1000));
    LOG_DBG("SID dession query path: {}", full);
    while (libcdoc::getTime() < end) {
        httplib::Result res = cli.Get(full);
        if (!res) {
            LOG_WARN("SID session query failed");
            return UNSPECIFIED_ERROR;
        }
        auto status = res->status;
        LOG_DBG("SID session query status: {}", status);
        if ((status < 200) || (status >= 300)) return UNSPECIFIED_ERROR;
        httplib::Response response = res.value();
        LOG_DBG("SID session query response: {}", response.body);

        picojson::value rsp;
        picojson::parse(rsp, response.body);
        if (!rsp.is<picojson::object>()) {
            LOG_WARN("Response is not a JSON object");
            return UNSPECIFIED_ERROR;
        }
        // State
        picojson::value v = rsp.get("state");
        if (!v.is<std::string>()) {
            LOG_WARN("State is not a string");
            return UNSPECIFIED_ERROR;
        }
        std::string str = v.get<std::string>();
        if (str == "RUNNING") {
            // Puse for 0.5 seconds and repeat
            std::chrono::milliseconds duration(500);
            std::this_thread::sleep_for(duration);
            continue;
        } else if (str != "COMPLETE") {
            LOG_WARN("Invalid SmartID state: {}", str);
            return UNSPECIFIED_ERROR;
        }
        // State is complete, check for end result
        v = rsp.get("result");
        if (!v.is<picojson::object>()) {
            LOG_WARN("Result is not a JSON object");
            return UNSPECIFIED_ERROR;
        }
        picojson::value w = v.get("endResult");
        if (!w.is<std::string>()) {
            LOG_WARN("EndResult is not a string");
            return UNSPECIFIED_ERROR;
        }
        str = w.get<std::string>();
        dst.endResult = SIDResponse::parseEndResult(str);
        if (dst.endResult != SIDResponse::OK) {
            LOG_WARN("EndResult is not OK: {}", str);
            return UNSPECIFIED_ERROR;
        }
        // End result is OK
        // Signature
        v = rsp.get("signature");
        if (v.is<picojson::object>()) {
            w = v.get("value");
            if (!w.is<std::string>()) {
                LOG_WARN("value is not a string");
                return UNSPECIFIED_ERROR;
            }
            dst.signature = w.get<std::string>();
            w = v.get("algorithm");
            if (!w.is<std::string>()) {
                LOG_WARN("algorithm is not a string");
                return UNSPECIFIED_ERROR;
            }
            dst.algorithm = w.get<std::string>();
        }
        // Certificate
        v = rsp.get("cert");
        if (v.is<picojson::object>()) {
            w = v.get("value");
            if (!w.is<std::string>()) {
                LOG_WARN("value is not a string");
                return UNSPECIFIED_ERROR;
            }
            dst.cert = v.get("value").get<std::string>();
        }
        return OK;
    }
    // Timeout
    return UNSPECIFIED_ERROR;
}

static result_t
waitForResultMID(SIDResponse& dst, httplib::SSLClient& cli, const std::string& path, const std::string& session_id, double seconds)
{
    double end = libcdoc::getTime() + seconds;
    std::string full = path + session_id + "?timeoutMs=" + std::to_string((int) (seconds * 1000));
    LOG_DBG("SID dession query path: {}", full);
    while (libcdoc::getTime() < end) {
        httplib::Result res = cli.Get(full);
        if (!res) {
            LOG_WARN("SID session query failed");
            return UNSPECIFIED_ERROR;
        }
        auto status = res->status;
        LOG_DBG("SID session query status: {}", status);
        if ((status < 200) || (status >= 300)) return UNSPECIFIED_ERROR;
        httplib::Response response = res.value();
        LOG_DBG("SID session query response: {}", response.body);

        picojson::value rsp;
        picojson::parse(rsp, response.body);
        if (!rsp.is<picojson::object>()) {
            LOG_WARN("Response is not a JSON object");
            return UNSPECIFIED_ERROR;
        }
        // State
        picojson::value v = rsp.get("state");
        if (!v.is<std::string>()) {
            LOG_WARN("State is not a string");
            return UNSPECIFIED_ERROR;
        }
        std::string str = v.get<std::string>();
        if (str == "RUNNING") {
            // Puse for 0.5 seconds and repeat
            std::chrono::milliseconds duration(500);
            std::this_thread::sleep_for(duration);
            continue;
        } else if (str != "COMPLETE") {
            LOG_WARN("Invalid SmartID state: {}", str);
            return UNSPECIFIED_ERROR;
        }
        // State is complete, check for end result
        picojson::value w = v.get("result");
        if (!w.is<std::string>()) {
            LOG_WARN("result is not a string");
            return UNSPECIFIED_ERROR;
        }
        str = w.get<std::string>();
        dst.endResult = SIDResponse::parseEndResult(str);
        if (dst.endResult != SIDResponse::OK) {
            LOG_WARN("Result is not OK: {}", str);
            return UNSPECIFIED_ERROR;
        }
        // End result is OK
        // Signature
        v = rsp.get("signature");
        if (v.is<picojson::object>()) {
            w = v.get("value");
            if (!w.is<std::string>()) {
                LOG_WARN("value is not a string");
                return UNSPECIFIED_ERROR;
            }
            dst.signature = w.get<std::string>();
            w = v.get("algorithm");
            if (!w.is<std::string>()) {
                LOG_WARN("algorithm is not a string");
                return UNSPECIFIED_ERROR;
            }
            dst.algorithm = w.get<std::string>();
        }
        // Certificate
        w = v.get("cert");
        if (!w.is<std::string>()) {
            LOG_WARN("cert is not a string");
            return UNSPECIFIED_ERROR;
        }
        dst.cert = w.get<std::string>();
        return OK;
    }
    // Timeout
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
    if (path == "/") path.clear();
    LOG_DBG("URL:{}", url);
    LOG_DBG("HOST:{}", host);
    LOG_DBG("PORT:{}", port);
    LOG_DBG("PATH:{}", path);

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);

    std::vector<std::vector<uint8_t>> certs;
    LOG_DBG("Fetching certs");
    getPeerTLSCertificates(certs, buildURL(host, port));
    if (!certs.empty()) {
        LOG_DBG("Loading certs");
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            auto x509 = Crypto::toX509(c);
            if (!x509) return CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.get());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    } else {
        LOG_WARN("SmartID server's certificate list is empty");
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    //
    // Let user choose certificate (if multiple)
    //
    std::string full = path + "/certificatechoice/" + rcpt_id;
    LOG_DBG("SmartID path: {}", full);
    httplib::Result res = cli.Post(full, query.serialize(), "application/json");
    if (!res) {
        LOG_WARN("SmartID query failed");
        return NetworkBackend::NETWORK_ERROR;
    }
    auto status = res->status;
    LOG_DBG("Status: {}", status);
    if ((status < 200) || (status >= 300)) return UNSPECIFIED_ERROR;
    httplib::Response rsp = res.value();
    LOG_DBG("Response: {}", rsp.body);
    picojson::value v;
    picojson::parse(v, rsp.body);
    if (!v.is<picojson::object>()) {
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    picojson::value w = v.get("sessionID");
    if (!w.is<std::string>()) {
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    std::string sessionID  = w.get<std::string>();
    LOG_DBG("SessionID: {}", sessionID);

    SIDResponse sidrsp;
    result = waitForResult(sidrsp, cli, path + "/session/", sessionID, 60);
    if (result != OK) {
        LOG_WARN("Wait for response failed: {}", result);
        return result;
    }
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
    res = cli.Post(full, query.serialize(), "application/json");
    if (!res) {
        LOG_WARN("SmartID query failed");
        return UNSPECIFIED_ERROR;
    }
    status = res->status;
    LOG_DBG("Status: {}", status);
    if ((status < 200) || (status >= 300)) return UNSPECIFIED_ERROR;
    rsp = res.value();
    LOG_DBG("Response: {}", rsp.body);
    picojson::parse(v, rsp.body);
    if (!v.is<picojson::object>()) {
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    w = v.get("sessionID");
    if (!w.is<std::string>()) {
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    sessionID  = w.get<std::string>();
    LOG_DBG("SessionID: {}", sessionID);

    sidrsp = {};
    result = waitForResult(sidrsp, cli, path + "/session/", sessionID, 60);
    if (result != OK) {
        LOG_WARN("Wait for response failed: {}", result);
        return UNSPECIFIED_ERROR;
    }
    LOG_DBG("Certificate: {}", sidrsp.cert);
    LOG_DBG("Signature: {}", sidrsp.signature);
    LOG_DBG("Algorithm: {}", sidrsp.algorithm);

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
    if (path == "/") path.clear();
    LOG_DBG("URL:{}", url);
    LOG_DBG("HOST:{}", host);
    LOG_DBG("PORT:{}", port);
    LOG_DBG("PATH:{}", path);

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);

    std::vector<std::vector<uint8_t>> certs;
    LOG_DBG("Fetching certs");
    getPeerTLSCertificates(certs, buildURL(host, port));
    if (!certs.empty()) {
        LOG_DBG("Loading certs");
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            auto x509 = Crypto::toX509(c);
            if (!x509) return CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.get());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    } else {
        LOG_WARN("SmartID server's certificate list is empty");
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

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
    LOG_DBG("SmartID path: {}", full);
    httplib::Result res = cli.Post(full, query.serialize(), "application/json");
    if (!res) {
        LOG_WARN("SmartID query failed");
        return UNSPECIFIED_ERROR;
    }
    auto status = res->status;
    LOG_DBG("Status: {}", status);
    if ((status < 200) || (status >= 300)) return UNSPECIFIED_ERROR;
    httplib::Response rsp = res.value();
    LOG_DBG("Response: {}", rsp.body);
    picojson::value v;
    picojson::parse(v, rsp.body);
    if (!v.is<picojson::object>()) {
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    picojson::value w = v.get("sessionID");
    if (!w.is<std::string>()) {
        LOG_WARN("Invalid SmartID response");
        return NetworkBackend::NETWORK_ERROR;
    }
    std::string sessionID  = w.get<std::string>();
    LOG_DBG("SessionID: {}", sessionID);

    SIDResponse sidrsp;
    result = waitForResultMID(sidrsp, cli, path + "/authentication/session/", sessionID, 60);
    if (result != OK) {
        LOG_WARN("Wait for response failed: {}", result);
        return UNSPECIFIED_ERROR;
    }

    LOG_DBG("Certificate: {}", sidrsp.cert);
    LOG_DBG("Signature: {}", sidrsp.signature);
    LOG_DBG("Algorithm: {}", sidrsp.algorithm);

    dst = fromBase64(sidrsp.signature);
    cert = fromBase64(sidrsp.cert);

    return OK;
}
