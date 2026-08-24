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

#include "CDoc2Reader.h"

#include "Certificate.h"
#include "Configuration.h"
#include "Crypto.h"
#include "CryptoBackend.h"
#include "CDoc2.h"
#include "KeyShares.h"
#include "Lock.h"
#include "NetworkBackend.h"
#include "Tar.h"
#include "Utils.h"
#include "ZStream.h"

#include "header_generated.h"

// TODO: Port to new OpenSSL
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/evp.h>
#include <openssl/x509.h>

// fixme: Placeholder
#define t_(t) t

using namespace libcdoc;

// Get salt bitstring for HKDF expand method

std::string
libcdoc::CDoc2::getSaltForExpand(const std::string& label)
{
    std::ostringstream oss;
    oss << libcdoc::CDoc2::KEK << cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) << label;
    return oss.str();
}

// Get salt bitstring for HKDF expand method
std::string
libcdoc::CDoc2::getSaltForExpand(const std::vector<uint8_t>& key_material, const std::vector<uint8_t>& rcpt_key)
{
    std::ostringstream oss;
    oss << libcdoc::CDoc2::KEK
        << cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR)
        << std::string_view((const char*)rcpt_key.data(), rcpt_key.size())
        << std::string_view((const char*)key_material.data(), key_material.size());
    return oss.str();
}

struct CDoc2Reader::Private {
    Private(libcdoc::DataSource *src, bool take_ownership) : _src(src), _owned(take_ownership) {}

    ~Private() {
        if (_owned) delete _src;
    }

    libcdoc::DataSource *_src;
    bool _owned;
    size_t _nonce_pos = 0;
    bool _at_nonce = false;

    std::vector<uint8_t> header_data;
    std::vector<uint8_t> headerHMAC;

    std::vector<Lock> locks;

    std::unique_ptr<libcdoc::DecryptionSource> dec;
    std::unique_ptr<libcdoc::ZSource> zsrc;
    std::unique_ptr<libcdoc::TarSource> tar;

    result_t decryptAllAndClose() {
        std::array<uint8_t, 1024> buf;
        result_t rv = dec->read(buf.data(), buf.size());
        while (rv == buf.size()) {
            rv = dec->read(buf.data(), buf.size());
        }
        if (rv < 0) return rv;
        zsrc.reset();
        tar.reset();
        rv = dec->close();
        dec.reset();
        return rv;
    }

    static void buildLock(Lock& lock, const cdoc20::header::RecipientRecord& recipient);
};

CDoc2Reader::~CDoc2Reader() = default;

const std::vector<Lock>&
CDoc2Reader::getLocks()
{
    return priv->locks;
}

libcdoc::result_t
CDoc2Reader::getLockForCert(const std::vector<uint8_t>& cert){
    std::vector<uint8_t> other_key = libcdoc::Certificate(cert).getPublicKey();
    if (other_key.empty())
         return libcdoc::NOT_FOUND;
    LOG_TRACE("Cert public key: {}", toHex(other_key));
    int lock_idx = 0;
    for (const Lock &ll : priv->locks) {
        if (ll.isPKI() && ll.getBytes(libcdoc::Lock::RCPT_KEY) == other_key) {
            return lock_idx;
        }
        ++lock_idx;
    }
    setLastError("No lock found with certificate key");
    return libcdoc::NOT_FOUND;
}

libcdoc::result_t
CDoc2Reader::getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx)
{
    if (lock_idx >= priv->locks.size()) {
        setLastError(t_("Invalid lock index"));
        LOG_ERROR("{}", last_error);
        return libcdoc::WRONG_ARGUMENTS;
    }
    LOG_DBG("CDoc2Reader::getFMK: {}", lock_idx);
    LOG_DBG("CDoc2Reader::num locks: {}", priv->locks.size());
    const Lock& lock = priv->locks.at(lock_idx);
    LOG_DBG("Label: {}", lock.label);

    // RAII-cleanse `kek` on every exit from this function (including
    // exceptions). All early returns below previously had to remember to
    // call libcdoc::cleanse(kek) - which several of them did not. With the
    // guard the wipe is unconditional.
    SecureTarget kek;

    if (lock.type == Lock::Type::PASSWORD) {
        // Password
        LOG_DBG("Password-based lock");
        std::string info_str = libcdoc::CDoc2::getSaltForExpand(lock.label);
        LOG_TRACE("info: {}", toHex(info_str));
        SecureTarget kek_pm;
        if (auto rv = crypto->extractHKDF(kek_pm.getTarget(), lock.getBytes(Lock::SALT), lock.getBytes(Lock::PW_SALT), lock.getInt(Lock::KDF_ITER), lock_idx); rv != libcdoc::OK) {
            setLastError(crypto->getLastErrorStr(rv));
            LOG_ERROR("{}", last_error);
            return rv;
        }
        LOG_TRACE_KEY("salt: {}", lock.getBytes(Lock::SALT));
        LOG_TRACE_KEY("kek_pm: {}", kek_pm);
        kek = libcdoc::Crypto::expand(kek_pm, info_str, 32);
    } else if (lock.type == Lock::Type::SYMMETRIC_KEY) {
        // Symmetric key
        LOG_DBG("Symmetric-key based lock");
        std::string info_str = libcdoc::CDoc2::getSaltForExpand(lock.label);
        LOG_TRACE("info: {}", toHex(info_str));
        SecureTarget kek_pm;
        if (auto rv = crypto->extractHKDF(kek_pm.getTarget(), lock.getBytes(Lock::SALT), {}, 0, lock_idx); rv != libcdoc::OK) {
            setLastError(crypto->getLastErrorStr(rv));
            LOG_ERROR("{}", last_error);
            return rv;
        }
        LOG_TRACE_KEY("salt: {}", lock.getBytes(Lock::SALT));
        LOG_TRACE_KEY("kek_pm: {}", kek_pm);
        kek = libcdoc::Crypto::expand(kek_pm, info_str, 32);
    } else if ((lock.type == Lock::Type::PUBLIC_KEY) || (lock.type == Lock::Type::SERVER)) {
        LOG_DBG("Public/private key based lock");
        // Public/private key
        SecureTarget key_material;
        // SERVER path fetches key_material over the network; PUBLIC_KEY
        // takes it from the lock. Either way it gets fed into ECDH or RSA
        // and is sensitive enough to wipe in-scope.
        if(lock.type == Lock::Type::SERVER) {
            if(!conf) {
                setLastError("Configuration is missing");
                LOG_ERROR("{}", last_error);
                return libcdoc::CONFIGURATION_ERROR;
            }
            if(!network) {
                setLastError("Network backend is missing");
                LOG_ERROR("{}", last_error);
                return libcdoc::CONFIGURATION_ERROR;
            }
            std::string server_id = lock.getString(Lock::Params::KEYSERVER_ID);
            std::string fetch_url = conf->getValue(server_id, libcdoc::Configuration::KEYSERVER_FETCH_URL);
            if (fetch_url.empty()) {
                setLastError(FORMAT("No FETCH_URL found for server {}", server_id));
                LOG_ERROR("{}", last_error);
                return libcdoc::CONFIGURATION_ERROR;
            }
            std::string transaction_id = lock.getString(Lock::Params::TRANSACTION_ID);
            int result = network->fetchKey(key_material.getTarget(), fetch_url, transaction_id);
            if (result < 0) {
                setLastError(network->getLastErrorStr(result));
                return result;
            }
        } else if (lock.type == Lock::PUBLIC_KEY) {
            key_material = lock.getBytes(Lock::Params::KEY_MATERIAL);
        }

        LOG_TRACE_KEY("Public key: {}", lock.getBytes(Lock::Params::RCPT_KEY));
        LOG_TRACE_KEY("Key material: {}", key_material);

        if (lock.isRSA()) {
            int result = crypto->decryptRSA(kek.getTarget(), key_material, true, lock_idx);
            if (result < 0) {
                setLastError(crypto->getLastErrorStr(result));
                LOG_ERROR("{}", last_error);
                return result;
            }
        } else {
            SecureTarget kek_pm;
            int result = crypto->deriveHMACExtract(kek_pm.getTarget(), key_material, toUint8Vector(libcdoc::CDoc2::KEKPREMASTER), lock_idx);
            if (result < 0) {
                setLastError(crypto->getLastErrorStr(result));
                LOG_ERROR("{}", last_error);
                return result;
            }
            LOG_TRACE_KEY("Key kekPm: {}", kek_pm);
            std::string info_str = libcdoc::CDoc2::getSaltForExpand(key_material, lock.getBytes(Lock::Params::RCPT_KEY));
            LOG_TRACE("info: {}", toHex(info_str));
            kek = libcdoc::Crypto::expand(kek_pm, info_str, libcdoc::CDoc2::KEY_LEN);
        }
#ifdef HAS_KEYSHARES
    } else  if (lock.type == Lock::Type::SHARE_SERVER) {
        LOG_DBG("Share server based lock");
        /* SALT */
        std::vector<uint8_t> salt = lock.getBytes(Lock::SALT);
        /* RECIPIENT_ID */
        std::string rcpt_id = lock.getString(Lock::RECIPIENT_ID);
        /* SHARE_URLS */
        /* url,share_id;url,share_id... */
        std::string all = lock.getString(Lock::SHARE_URLS);
        std::vector<std::string> servers = split(all, ';');
        if (servers.empty()){
            setLastError("Lock does not contain server info");
            LOG_ERROR("{}", last_error);
            return libcdoc::DATA_FORMAT_ERROR;
        }
        std::vector<ShareData> shares;
        for (auto& server : servers) {
            std::vector<std::string> parts = split(server, ',');
            if (parts.size() != 2) {
                setLastError("Invalid server info in lock");
                LOG_ERROR("{}", last_error);
                return libcdoc::DATA_FORMAT_ERROR;
            }
            LOG_DBG("Share {} url {}", parts[1], parts[0]);
            shares.emplace_back(parts[0], parts[1]);
        }

        // Get authentication token
        std::string auth_url = conf->getValue({}, Configuration::AUTH_SERVER);
        if (auth_url.empty()) {
            setLastError(FORMAT("No AUTH_SERVER found"));
            LOG_ERROR("{}", last_error);
            return libcdoc::CONFIGURATION_ERROR;
        }
        // auth_url = "https://cdoc2-auth.dev.riaint.ee";
        // fixme:
        std::string signer_type = conf->getValue(Configuration::SHARE_SIGNER);
        LOG_DBG("Signer: {}", signer_type);
        bool mid = false;
        if (signer_type == Configuration::SHARE_SIGNER_MID) {
            mid = true;
        } else if (signer_type != Configuration::SHARE_SIGNER_SID) {
            setLastError(t_("Unknown or missing signer type"));
            LOG_ERROR("Unknown or missing signer type");
            return libcdoc::CONFIGURATION_ERROR;
        }
        std::string phone;
        if (mid) {
            phone = conf->getValue({}, Configuration::PHONE_NUMBER);
            if (phone.empty()) {
                setLastError(t_("Missing phone number"));
                LOG_ERROR("Missing phone number");
                return libcdoc::CONFIGURATION_ERROR;
            }
        }

        NetworkBackend::SessionData session;
        if (auto rv = network->authenticateForShares(auth_url, rcpt_id, phone, session); rv != OK) {
            setLastError(network->getLastErrorStr(rv));
            LOG_ERROR("{}", last_error);
            return rv;
        }

        // S1: only contact share servers that the authentication server has
        // authorized for this session. The session token carries one
        // disclosure per authorized server; a container pointing to any other
        // server would otherwise receive the session token and the user's
        // credentials (SSRF / credential exfiltration). N-of-N reconstruction
        // needs every share, so an unauthorized server rejects the container.
        {
            SessionToken stoken(session.token);
            for (const auto& share : shares) {
                if (!stoken.hasDisclosureForUrl(share.base_url)) {
                    setLastError(FORMAT("Share server {} is not authorized by the authentication session", share.base_url));
                    LOG_ERROR("{}", last_error);
                    return libcdoc::DATA_FORMAT_ERROR;
                }
            }
        }

        // S8: validate the authentication session client-side - the session
        // certificate must belong to the lock recipient and the session token
        // must not be expired. Also learns the schemeName/rpName claims needed
        // to verify the signed ticket later.
        std::string scheme_name, rp_name, v_err;
        if (auto rv = validateSessionData(crypto, rcpt_id, mid, session.token, session.cert, scheme_name, rp_name, v_err); rv != OK) {
            setLastError(v_err);
            LOG_ERROR("{}", last_error);
            return rv;
        }

        // Get nonces
        for (auto& share : shares) {
            std::vector<uint8_t> nonce;
            result_t result = network->fetchNonce(nonce, share.base_url, share.share_id, session);
            if (result != libcdoc::OK) {
                setLastError(network->getLastErrorStr(result));
                LOG_ERROR("Cannot fetch nonce {} from server {}", share.share_id, share.base_url);
                return result;
            }
            LOG_DBG("Nonce: {}", std::string(nonce.cbegin(), nonce.cend()));
            share.nonce = std::string(nonce.cbegin(), nonce.cend());
        }

        std::string rp_url = conf->getValue({}, Configuration::RP_SERVER);
        if (rp_url.empty()) {
            setLastError(FORMAT("No RP_SERVER found"));
            LOG_ERROR("{}", last_error);
            return libcdoc::CONFIGURATION_ERROR;
        }
        // rp_url = "https://cdoc2-rp.dev.riaint.ee/"
        /* Create tickets from shares */
        std::vector<std::string> auth_tokens;
        AuthenticationData auth;
        result_t result = NOT_IMPLEMENTED;

        // The text shown on the user's device in the SID/MID confirmation
        // dialog (Smart-ID displayText200 / Mobile-ID displayText).
        std::string display_text = conf ? conf->getValue(libcdoc::Configuration::DISPLAY_TEXT) : std::string{};

        if (!mid) {
            SIDSigner signer(rp_url, session, rcpt_id, network, display_text);
            result = signer.generateTickets(auth_tokens, shares);
            if (result != OK) {
                setLastError(signer.error);
            } else {
                auth.cert = std::move(signer.cert);
                auth.params = std::move(signer.params);
            }
        } else {
            MIDSigner signer(rp_url, phone, session, rcpt_id, network, display_text);
            result = signer.generateTickets(auth_tokens, shares);
            if (result != OK) {
                setLastError(signer.error);
            } else {
                auth.cert = std::move(signer.cert);
                auth.params = std::move(signer.params);
            }
        }
        if (result != libcdoc::OK) {
            LOG_ERROR("Cannot generate share tickets");
            return result;
        }
        // S8: verify the signed auth ticket client-side before spending it -
        // the signing certificate must belong to rcpt_id and the ticket
        // signature must verify (binds identity, the consent text shown to
        // the user, and freshness). All tickets share the same signed JWT,
        // so validating the first one covers them all.
        if (!auth_tokens.empty()) {
            if (!mid) {
                // Smart-ID: RSASSA-PSS over the ACSP_V2 payload
                std::vector params = fromBase64URL(auth.params[network->X_CDOC2_SID_RPV3_SIGNATURE_PARAMETERS]);
                if (auto rv = validateAuthTicket(crypto, rcpt_id, auth_tokens[0], auth.cert, std::string(params.cbegin(), params.cend()), scheme_name, rp_name, v_err); rv != OK) {
                    setLastError(v_err);
                    LOG_ERROR("{}", last_error);
                    return rv;
                }
            } else {
                // Mobile-ID: ECDSA (ES256) ticket signature plus the RP
                // server RFC9421 HTTP countersignature. The RP signing keys
                // are fetched from its well-known endpoint.
                std::string jwks;
                {
                    std::string jwks_url = joinUrl(rp_url, "/.well-known/jwks.jws");
                    std::map<std::string, std::string> headers;
                    std::vector<uint8_t> body;
                    if (auto rv = network->get(jwks_url, body, headers, false); rv != OK) {
                        setLastError(network->getLastErrorStr(rv));
                        LOG_ERROR("{}", last_error);
                        return rv;
                    }
                    jwks.assign(body.begin(), body.end());

                    // The endpoint name says .jws: accept both a plain JWK
                    // Set (what the servers currently return) and a JWS
                    // compact serialization (header64.payload64.signature64)
                    // whose payload is the JWK Set.
                    if (jwks.find("\"keys\"") == std::string::npos) {
                        std::vector<std::string> parts = split(jwks, '.');
                        if (parts.size() == 3) {
                            std::vector<uint8_t> payload = fromBase64URL(parts[1]);
                            jwks.assign(payload.begin(), payload.end());
                        }
                    }
                    if (jwks.find("\"keys\"") == std::string::npos) {
                        setLastError("Well-known keys response is not a JWK Set");
                        LOG_ERROR("{}", last_error);
                        return libcdoc::DATA_FORMAT_ERROR;
                    }
                }
                if (auto rv = validateAuthTicketMID(crypto, rcpt_id, auth_tokens[0], auth.cert, auth.params, jwks, v_err); rv != OK) {
                    setLastError(v_err);
                    LOG_ERROR("{}", last_error);
                    return rv;
                }
            }
        }
        std::vector<uint8_t>& kek_build = kek.getTarget(32);
        std::fill(kek_build.begin(), kek_build.end(), 0);
        // Build the auth SessionData once (cert and params are shared);
        // only the per-share ticket token changes between requests.
        NetworkBackend::SessionData auth_session;
        auth_session.cert = toBase64URL(auth.cert);
        auth_session.params = auth.params;
        for (unsigned int i = 0; i < auth_tokens.size(); i++) {
            NetworkBackend::ShareInfo share;
            auth_session.token = auth_tokens[i];
            result = network->fetchShare(share, shares[i].base_url, shares[i].share_id, session, auth_session);
            if (result != libcdoc::OK) {
                setLastError(network->getLastErrorStr(result));
                LOG_ERROR("Cannot fetch share {}", i);
                return result;
            }
            // Each individual share is itself sensitive: combined with the
            // remaining shares it reconstructs the KEK. Wipe it after
            // XOR-ing it into kek so it does not linger on the heap.
            libcdoc::Cleanser share_guard(share.share);
            if (auto err = libcdoc::Crypto::xor_data(kek_build, kek_build, share.share); err != libcdoc::OK) {
                setLastError("Failed to derive kek");
                LOG_ERROR("Failed to derive kek");
                return err;
            }
        }
        LOG_INFO("Fetched all shares");
#endif
    } else {
        setLastError(t_("Unknown lock type"));
        LOG_ERROR("Unknown lock type: %d", (int) lock.type);
        return libcdoc::UNSPECIFIED_ERROR;
    }

    LOG_TRACE_KEY("KEK: {}", kek);

    if(kek.empty()) {
        setLastError(t_("Failed to derive KEK"));
        LOG_ERROR("{}", last_error);
        return CRYPTO_ERROR;
    }
    if (auto err = libcdoc::Crypto::xor_data(fmk, lock.encrypted_fmk, kek); err != libcdoc::OK) {
        setLastError(t_("Failed to decrypt/derive fmk"));
        LOG_ERROR("{}", last_error);
        // Wipe any partial XOR result before surfacing the error.
        libcdoc::cleanse(fmk);
        fmk.clear();
        return err;
    }
    SecureTarget hhk = libcdoc::Crypto::expand(fmk, libcdoc::CDoc2::HMAC);

    LOG_TRACE_KEY("xor: {}", lock.encrypted_fmk);
    LOG_TRACE_KEY("fmk: {}", fmk);
    LOG_TRACE_KEY("hhk: {}", hhk);
    LOG_TRACE_KEY("hmac: {}", priv->headerHMAC);

    if(!libcdoc::constant_time_compare(libcdoc::Crypto::sign_hmac(hhk, priv->header_data), priv->headerHMAC)) {
        setLastError(t_("Wrong decryption key (user key)"));
        LOG_ERROR("{}", last_error);
        // Authentication failed: the FMK we computed is for the wrong
        // recipient. Wipe it before returning so the caller cannot leak
        // it (e.g. via a logging hook that sees "fmk" in scope).
        libcdoc::cleanse(fmk);
        fmk.clear();
        return libcdoc::WRONG_KEY;
    }
    setLastError({});
    return libcdoc::OK;
}

libcdoc::result_t
CDoc2Reader::decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *consumer)
{
    int64_t result = beginDecryption(fmk);
    if (result != libcdoc::OK) return result;
    std::string name;
    int64_t size;
    result = nextFile(name, size);
    while (result == libcdoc::OK) {
        result = consumer->open(name, size);
        if (result != libcdoc::OK) {
            setLastError(consumer->getLastErrorStr(result));
            LOG_ERROR("{}", last_error);
            return result;
        }
        result = consumer->writeAll(*priv->tar);
        if (result < 0) {
            setLastError(consumer->getLastErrorStr(result));
            LOG_ERROR("{}", last_error);
            return result;
        }
        result = nextFile(name, size);
    }
    if (result != libcdoc::END_OF_STREAM) {
        LOG_ERROR("{}", last_error);
        return result;
    }
    return finishDecryption();
}

libcdoc::result_t
CDoc2Reader::beginDecryption(const std::vector<uint8_t>& fmk)
{
    LOG_DBG("CDoc2Reader::beginDecryption");
    if(fmk.size() != 32) {
        setLastError("No decryption key provided or invalid key length");
        LOG_ERROR("{}", last_error);
        return libcdoc::WRONG_ARGUMENTS;
    }
    if (!priv->_at_nonce) {
        result_t result = priv->_src->seek(priv->_nonce_pos);
        if (result != libcdoc::OK) {
            setLastError(priv->_src->getLastErrorStr(result));
            LOG_ERROR("{}", last_error);
            return libcdoc::IO_ERROR;
        }
    }
    priv->_at_nonce = false;
    std::vector<uint8_t> cek = libcdoc::Crypto::expand(fmk, libcdoc::CDoc2::CEK);
    LOG_TRACE_KEY("cek: {}", cek);

    priv->dec = std::make_unique<libcdoc::DecryptionSource>(*priv->_src, EVP_chacha20_poly1305(), cek, libcdoc::CDoc2::NONCE_LEN);
    for(const auto &aad: {libcdoc::CDoc2::PAYLOAD, priv->header_data, priv->headerHMAC}) {
        if(auto rv = priv->dec->updateAAD(aad); rv != OK) {
            setLastError(priv->dec->getLastErrorStr(rv));
            LOG_ERROR("{}", last_error);
            return rv;
        }
    }

    // N7: cap decompressed size to prevent decompression bombs.
    // CDoc2 streams through TarSource to the consumer, so a larger default
    // (20 GiB) is used compared to CDoc1's in-memory default (2 GiB).
    static constexpr int64_t DEFAULT_MAX = 20LL * 1024 * 1024 * 1024;
    int64_t max_size = conf ? conf->getInt64(libcdoc::Configuration::CDOC2_MAX_DECOMPRESSED_SIZE, DEFAULT_MAX) : DEFAULT_MAX;
    priv->zsrc = std::make_unique<libcdoc::ZSource>(priv->dec.get(), false, max_size);
    priv->tar = std::make_unique<libcdoc::TarSource>(priv->zsrc.get(), false);

    return libcdoc::OK;
}

libcdoc::result_t
CDoc2Reader::nextFile(std::string& name, int64_t& size)
{
    LOG_DBG("CDoc2Reader::nextFile");
    if (!priv->tar) {
        setLastError("nextFile() called before beginDecryption()");
        LOG_ERROR("{}", last_error);
        return libcdoc::WORKFLOW_ERROR;
    }
    result_t result = priv->tar->next(name, size);
    if (result < 0) {
        // According to specification payload integrity should be reported even if there are parsing errors
        result_t sr = priv->decryptAllAndClose();
        if (sr != OK) {
            LOG_WARN("Crypto payload integrity check failed");
            setLastError("Crypto payload integrity check failed");
            return sr;
        }
        setLastError(priv->tar->getLastErrorStr(result));
    }
    LOG_DBG("CDoc2Reader::nextFile: result: {}, name: {} size: {}", result, name, size);
    return result;
}

libcdoc::result_t
CDoc2Reader::readData(uint8_t *dst, size_t size)
{
    if (!priv->tar) {
        setLastError("readData() called before beginDecryption()");
        LOG_ERROR("{}", last_error);
        return libcdoc::WORKFLOW_ERROR;
    }
    result_t result = priv->tar->read(dst, size);
    if (result < 0) {
        // According to specification payload integrity should be reported even if there are parsing errors
        result_t sr = priv->decryptAllAndClose();
        if (sr != OK) {
            LOG_WARN("Crypto payload integrity check failed");
            setLastError("Crypto payload integrity check failed");
            return sr;
        }
        setLastError(priv->tar->getLastErrorStr(result));
    }
    LOG_DBG("CDoc2Reader::readData: result {}", result);
    return result;
}

libcdoc::result_t
CDoc2Reader::finishDecryption()
{
    LOG_DBG("CDoc2Reader::finishDecryption");
    if (!priv->tar) {
        setLastError("finishDecryption() called before beginDecryption()");
        LOG_ERROR("{}", last_error);
        return libcdoc::WORKFLOW_ERROR;
    }
    if (!priv->zsrc->isEof()) {
        setLastError(t_("CDoc contains additional payload data that is not part of content"));
        LOG_WARN("{}", last_error);
    }
    setLastError({});
    priv->zsrc.reset();
    priv->tar.reset();
    auto rv = priv->dec->close();
    priv->dec.reset();
    if (rv != OK) {
        setLastError("Crypto payload integrity check failed");
    }
    return rv;
}

void
CDoc2Reader::Private::buildLock(Lock& lock, const cdoc20::header::RecipientRecord& recipient)
{
    using namespace cdoc20::recipients;
    using namespace cdoc20::header;

    if(recipient.fmk_encryption_method() != cdoc20::header::FMKEncryptionMethod::XOR) {
        LOG_WARN("Unsupported FMK encryption method");
        return;
    }
    lock.label = recipient.key_label()->str();
    lock.encrypted_fmk = toUint8Vector(recipient.encrypted_fmk());

    switch(recipient.capsule_type()) {
    case Capsule::recipients_ECCPublicKeyCapsule:
        if(const auto *capsule = recipient.capsule_as_recipients_ECCPublicKeyCapsule()) {
            lock.type = Lock::Type::PUBLIC_KEY;
            lock.pk_type = Algorithm::ECC;
            if(capsule->curve() == EllipticCurve::secp384r1) {
                lock.ec_type = Curve::SECP_384_R1;
            } else if (capsule->curve() == EllipticCurve::secp256r1) {
                lock.ec_type = Curve::SECP_256_R1;
            } else if (capsule->curve() == EllipticCurve::secp521r1) {
                lock.ec_type = Curve::SECP_521_R1;
            } else {
                LOG_WARN("Unknown ECC curve: {}", (int) capsule->curve());
                lock.ec_type = Curve::UNKNOWN_CURVE;
            }
            lock.setBytes(Lock::Params::RCPT_KEY, toUint8Vector(capsule->recipient_public_key()));
            lock.setBytes(Lock::Params::KEY_MATERIAL, toUint8Vector(capsule->sender_public_key()));
            LOG_TRACE("Load PK: {}", toHex(lock.getBytes(Lock::Params::RCPT_KEY)));
        }
        return;
    case Capsule::recipients_RSAPublicKeyCapsule:
        if(const auto *key = recipient.capsule_as_recipients_RSAPublicKeyCapsule())
        {
            lock.type = Lock::Type::PUBLIC_KEY;
            lock.pk_type = Algorithm::RSA;
            lock.setBytes(Lock::Params::RCPT_KEY, toUint8Vector(key->recipient_public_key()));
            lock.setBytes(Lock::Params::KEY_MATERIAL, toUint8Vector(key->encrypted_kek()));
        }
        return;
    case Capsule::recipients_KeyServerCapsule:
        if (const KeyServerCapsule *capsule = recipient.capsule_as_recipients_KeyServerCapsule()) {
            KeyDetailsUnion details = capsule->recipient_key_details_type();
            switch (details) {
            case KeyDetailsUnion::EccKeyDetails:
                if(const EccKeyDetails *eccDetails = capsule->recipient_key_details_as_EccKeyDetails()) {
                    lock.pk_type = Algorithm::ECC;
                    lock.setBytes(Lock::Params::RCPT_KEY, toUint8Vector(eccDetails->recipient_public_key()));
                    if(eccDetails->curve() == EllipticCurve::secp384r1) {
                        lock.ec_type = Curve::SECP_384_R1;
                    } else if (eccDetails->curve() == EllipticCurve::secp256r1) {
                        lock.ec_type = Curve::SECP_256_R1;
                    } else if (eccDetails->curve() == EllipticCurve::secp521r1) {
                        lock.ec_type = Curve::SECP_521_R1;
                    } else {
                        LOG_WARN("Unknown ECC curve: {}", (int) eccDetails->curve());
                        lock.ec_type = Curve::UNKNOWN_CURVE;
                    }
                }
                break;
            case KeyDetailsUnion::RsaKeyDetails:
                if(const RsaKeyDetails *rsaDetails = capsule->recipient_key_details_as_RsaKeyDetails()) {
                    lock.pk_type = Algorithm::RSA;
                    lock.setBytes(Lock::Params::RCPT_KEY, toUint8Vector(rsaDetails->recipient_public_key()));
                }
                break;
            default:
                LOG_ERROR("Unsupported Key Server Details");
                return;
            }
            lock.type = Lock::Type::SERVER;
            lock.setString(Lock::Params::KEYSERVER_ID, capsule->keyserver_id()->str());
            lock.setString(Lock::Params::TRANSACTION_ID, capsule->transaction_id()->str());
        }
        return;
    case Capsule::recipients_SymmetricKeyCapsule:
        if(const auto *capsule = recipient.capsule_as_recipients_SymmetricKeyCapsule())
        {
            lock.type = Lock::SYMMETRIC_KEY;
            lock.setBytes(Lock::SALT, toUint8Vector(capsule->salt()));
        }
        return;
    case Capsule::recipients_PBKDF2Capsule:
        if(const auto *capsule = recipient.capsule_as_recipients_PBKDF2Capsule()) {
            KDFAlgorithmIdentifier kdf_id = capsule->kdf_algorithm_identifier();
            if (kdf_id != KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256) {
                LOG_ERROR("Unsupported KDF algorithm: skipping");
                return;
            }
            lock.type = Lock::PASSWORD;
            lock.setBytes(Lock::SALT, toUint8Vector(capsule->salt()));
            lock.setBytes(Lock::PW_SALT, toUint8Vector(capsule->password_salt()));
            // N8: the container's kdf_iterations is attacker-controlled
            // int32. Reject out-of-range values at parse time to prevent
            // CPU-exhaustion DoS (2^31-1 iterations = hours of PBKDF2)
            // and sign-wrap confusion (values > INT32_MAX wrap negative
            // and would silently take the raw symmetric-key path).
            int32_t kdf_iter = capsule->kdf_iterations();
            if (kdf_iter < 1 || kdf_iter > libcdoc::CryptoBackend::KDF_ITER_MAX_DECRYPT) {
                LOG_ERROR("Invalid PBKDF2 iteration count: {}", kdf_iter);
                return;
            }
            lock.setInt(Lock::KDF_ITER, kdf_iter);
        }
        return;
#ifdef HAS_KEYSHARES
    case Capsule::recipients_KeySharesCapsule:
        if (const auto *capsule = recipient.capsule_as_recipients_KeySharesCapsule()) {
            if (capsule->recipient_type() != cdoc20::recipients::KeyShareRecipientType::SID_MID) {
                LOG_ERROR("Invalid keyshare recipient type: {}", (int) capsule->recipient_type());
                return;
            }
            if (capsule->shares_scheme() != cdoc20::recipients::SharesScheme::N_OF_N) {
                LOG_ERROR("Invalid keyshare scheme type: {}", (int) capsule->shares_scheme());
                return;
            }
            /* url,share_id;url,share_id... */
            std::vector<std::string> strs;
            for (auto cshare : *capsule->shares()) {
                std::string id = cshare->share_id()->str();
                std::string url = cshare->server_base_url()->str();
                std::string str = url + ',' + id;
            LOG_TRACE("Keyshare: {}", str);
            strs.push_back(std::move(str));
        }
        std::string urls = join(strs, ";");
        LOG_TRACE("Keyshare urls: {}", urls);
        std::vector<uint8_t> salt = toUint8Vector(capsule->salt());
        LOG_TRACE_KEY("Keyshare salt: {}", salt);
        std::string recipient_id = capsule->recipient_id()->str();
        LOG_TRACE("Keyshare recipient id: {}", recipient_id);
            lock.type = Lock::SHARE_SERVER;
            lock.setString(Lock::SHARE_URLS, urls);
            lock.setBytes(Lock::SALT, salt);
            lock.setString(Lock::RECIPIENT_ID, recipient_id);
        }
        return;
#endif
    default:
        LOG_ERROR("Unsupported capsule type");
    }
}

CDoc2Reader::CDoc2Reader(libcdoc::DataSource *src, bool take_ownership)
    : CDocReader(2), priv(std::make_unique<Private>(src, take_ownership))
{
    using namespace cdoc20::header;

    setLastError(t_("Invalid CDoc 2.0 header"));

    uint8_t in[libcdoc::CDoc2::LABEL.size()];
    if (std::cmp_not_equal(priv->_src->read(in, libcdoc::CDoc2::LABEL.size()) , libcdoc::CDoc2::LABEL.size())) {
        LOG_ERROR("{}", last_error);
        return;
    }
    if (memcmp(libcdoc::CDoc2::LABEL.data(), in, libcdoc::CDoc2::LABEL.size())) {
        LOG_ERROR("{}", last_error);
        return;
    }

    // Read 32-bit header length in big endian order
    std::array<uint8_t, 4> c{};
    if (std::cmp_not_equal(priv->_src->read(c.data(), c.size()) , c.size())) {
        LOG_ERROR("{}", last_error);
        return;
    }
    uint32_t header_len = (uint32_t(c[0]) << 24) | (uint32_t(c[1]) << 16) | uint32_t(c[2]) << 8 | c[3];
    if (constexpr uint32_t MAX_LEN = (1 << 20); header_len > MAX_LEN) {
        LOG_ERROR("{}", last_error);
        return;
    }
    priv->header_data.resize(header_len);
    if (priv->_src->read(priv->header_data.data(), header_len) != header_len) {
        LOG_ERROR("{}", last_error);
        return;
    }
    priv->headerHMAC.resize(libcdoc::CDoc2::KEY_LEN);
    if (priv->_src->read(priv->headerHMAC.data(), libcdoc::CDoc2::KEY_LEN) != libcdoc::CDoc2::KEY_LEN) {
        LOG_ERROR("{}", last_error);
        return;
    }

    priv->_nonce_pos = libcdoc::CDoc2::LABEL.size() + 4 + header_len + libcdoc::CDoc2::KEY_LEN;
    priv->_at_nonce = true;

    flatbuffers::Verifier verifier(priv->header_data.data(), priv->header_data.size());
    if(!VerifyHeaderBuffer(verifier)) {
        LOG_ERROR("{}", last_error);
        return;
    }
    const auto *header = GetHeader(priv->header_data.data());
    if(!header) {
        LOG_ERROR("{}", last_error);
        return;
    }
    if(header->payload_encryption_method() != PayloadEncryptionMethod::CHACHA20POLY1305) {
        LOG_ERROR("{}", last_error);
        return;
    }
    const auto *recipients = header->recipients();
    if(!recipients) {
        LOG_ERROR("{}", last_error);
        return;
    }

    setLastError({});

    for(const auto *recipient: *recipients){
        Private::buildLock(priv->locks.emplace_back(), *recipient);
    }
}

bool
CDoc2Reader::isCDoc2File(libcdoc::DataSource *src)
{
    std::array<uint8_t,libcdoc::CDoc2::LABEL.size()> in {};
    if (std::cmp_not_equal(src->read(in.data(), in.size()) , in.size())) {
        LOG_DBG("CDoc2Reader::isCDoc2File: Cannot read tag");
        return false;
    }
    if (libcdoc::CDoc2::LABEL.compare(0, in.size(), (char *) in.data(), in.size())) {
        LOG_DBG("CDoc2Reader::isCDoc2File: Invalid tag: {}", toHex(in));
        return false;
    }
    return true;
}
