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
#include "CryptoBackend.h"
#include "CDoc2.h"
#include "ILogger.h"
#include "KeyShares.h"
#include "Lock.h"
#include "NetworkBackend.h"
#include "Tar.h"
#include "Utils.h"
#include "ZStream.h"

#include "header_generated.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <fstream>

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
    Private(libcdoc::DataSource *src, bool take_ownership) : _src(src), _owned(take_ownership) {
    }

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

CDoc2Reader::~CDoc2Reader()
{
}

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
    LOG_DBG("Cert public key: {}", toHex(other_key));
    int lock_idx = 0;
    for (const Lock &ll : priv->locks) {
        LOG_DBG("Lock {} type {}", lock_idx, (int) ll.type);
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
    std::vector<uint8_t> kek;
    if (lock.type == Lock::Type::PASSWORD) {
        // Password
        LOG_DBG("password");
        std::string info_str = libcdoc::CDoc2::getSaltForExpand(lock.label);
        LOG_DBG("info: {}", toHex(info_str));
        std::vector<uint8_t> kek_pm;
        if (auto rv = crypto->extractHKDF(kek_pm, lock.getBytes(Lock::SALT), lock.getBytes(Lock::PW_SALT), lock.getInt(Lock::KDF_ITER), lock_idx); rv != libcdoc::OK) {
            setLastError(crypto->getLastErrorStr(rv));
            LOG_ERROR("{}", last_error);
            return rv;
        }
        LOG_TRACE_KEY("salt: {}", lock.getBytes(Lock::SALT));
        LOG_TRACE_KEY("kek_pm: {}", kek_pm);
        kek = libcdoc::Crypto::expand(kek_pm, info_str, 32);
    } else if (lock.type == Lock::Type::SYMMETRIC_KEY) {
        // Symmetric key
        LOG_DBG("symmetric");
        std::string info_str = libcdoc::CDoc2::getSaltForExpand(lock.label);
        LOG_DBG("info: {}", toHex(info_str));
        std::vector<uint8_t> kek_pm;
        if (auto rv = crypto->extractHKDF(kek_pm, lock.getBytes(Lock::SALT), {}, 0, lock_idx); rv != libcdoc::OK) {
            setLastError(crypto->getLastErrorStr(rv));
            LOG_ERROR("{}", last_error);
            return rv;
        }
        LOG_TRACE_KEY("salt: {}", lock.getBytes(Lock::SALT));
        LOG_TRACE_KEY("kek_pm: {}", kek_pm);
        kek = libcdoc::Crypto::expand(kek_pm, info_str, 32);
    } else if ((lock.type == Lock::Type::PUBLIC_KEY) || (lock.type == Lock::Type::SERVER)) {
        // Public/private key
        std::vector<uint8_t> key_material;
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
            int result = network->fetchKey(key_material, fetch_url, transaction_id);
            if (result < 0) {
                setLastError(network->getLastErrorStr(result));
                return result;
            }
        } else if (lock.type == Lock::PUBLIC_KEY) {
            key_material = lock.getBytes(Lock::Params::KEY_MATERIAL);
        }

        LOG_DBG("Public key: {}", toHex(lock.getBytes(Lock::Params::RCPT_KEY)));
        LOG_DBG("Key material: {}", toHex(key_material));

        if (lock.isRSA()) {
            int result = crypto->decryptRSA(kek, key_material, true, lock_idx);
            if (result < 0) {
                setLastError(crypto->getLastErrorStr(result));
                LOG_ERROR("{}", last_error);
                return result;
            }
        } else {
            std::vector<uint8_t> kek_pm;
            int result = crypto->deriveHMACExtract(kek_pm, key_material, toUint8Vector(libcdoc::CDoc2::KEKPREMASTER), lock_idx);
            if (result < 0) {
                setLastError(crypto->getLastErrorStr(result));
                LOG_ERROR("{}", last_error);
                return result;
            }
            LOG_TRACE_KEY("Key kekPm: {}", kek_pm);
            std::string info_str = libcdoc::CDoc2::getSaltForExpand(key_material, lock.getBytes(Lock::Params::RCPT_KEY));
            LOG_DBG("info: {}", toHex(info_str));
            kek = libcdoc::Crypto::expand(kek_pm, info_str, libcdoc::CDoc2::KEY_LEN);
        }
    } else  if (lock.type == Lock::Type::SHARE_SERVER) {
        /* SALT */
        std::vector<uint8_t> salt = lock.getBytes(Lock::SALT);
        /* RECIPIENT_ID */
        std::string rcpt_id = lock.getString(Lock::RECIPIENT_ID);
        /* SHARE_URLS */
        /* url,share_id;url,share_id... */
        std::string all = lock.getString(Lock::SHARE_URLS);
        std::vector<std::string> strs = split(all, ';');
        if (strs.empty()){
            setLastError("Lock does not contain server info");
            LOG_ERROR("{}", last_error);
            return libcdoc::DATA_FORMAT_ERROR;
        }
        std::vector<ShareData> shares;
        for (auto& str : strs) {
            std::vector<std::string> parts = split(str, ',');
            if (parts.size() != 2) {
                setLastError("Invalid server info in lock");
                LOG_ERROR("{}", last_error);
                return libcdoc::DATA_FORMAT_ERROR;
            }
            std::string url = parts[0];
            std::string id = parts[1];
            LOG_DBG("Share {} url {}", id, url);

            std::vector<uint8_t> nonce;
            result_t result = network->fetchNonce(nonce, url, id);
            if (result != libcdoc::OK) {
                setLastError(network->getLastErrorStr(result));
                LOG_ERROR("Cannot fetch nonce from server {}", url);
                return result;
            }
            LOG_DBG("Nonce: {}", std::string(nonce.cbegin(), nonce.cend()));
            ShareData acc(url, id, std::string(nonce.cbegin(), nonce.cend()));
            shares.push_back(std::move(acc));
        }
        /* Create tickets from shares */
        std::vector<std::string> tickets;
        std::vector<uint8_t> cert;
        result_t result = NOT_IMPLEMENTED;
        std::string signer = conf->getValue(Configuration::SHARE_SIGNER);
        LOG_DBG("Signer: {}", signer);
        if (signer == "SMART_ID") {
            // "https://sid.demo.sk.ee/smart-id-rp/v2"
            std::string url = conf->getValue(Configuration::SID_DOMAIN, Configuration::BASE_URL);
            // "00000000-0000-0000-0000-000000000000"
            std::string relyingPartyUUID = conf->getValue(Configuration::SID_DOMAIN, Configuration::RP_UUID);
            // "DEMO"
            std::string relyingPartyName = conf->getValue(Configuration::SID_DOMAIN, Configuration::RP_NAME);
            SIDSigner signer(url, relyingPartyUUID, relyingPartyName, rcpt_id, network);
            result = signer.generateTickets(tickets, shares);
            if (result != OK) {
                setLastError(signer.error);
            } else {
                cert = std::move(signer.cert);
            }
        } else if (signer == "MOBILE_ID") {
            // "https://sid.demo.sk.ee/smart-id-rp/v2"
            std::string url = conf->getValue(Configuration::MID_DOMAIN, Configuration::BASE_URL);
            // "00000000-0000-0000-0000-000000000000"
            std::string relyingPartyUUID = conf->getValue(Configuration::MID_DOMAIN, Configuration::RP_UUID);
            // "DEMO"
            std::string relyingPartyName = conf->getValue(Configuration::MID_DOMAIN, Configuration::RP_NAME);
            // "37200000566"
            std::string phone = conf->getValue(Configuration::MID_DOMAIN, Configuration::PHONE_NUMBER);
            MIDSigner signer(url, relyingPartyUUID, relyingPartyName, phone, rcpt_id, network);
            result = signer.generateTickets(tickets, shares);
            if (result != OK) {
                setLastError(signer.error);
            } else {
                cert = std::move(signer.cert);
            }
        } else {
            setLastError(t_("Unknown or missing signer type"));
            LOG_ERROR("Unknown or missing signer type");
            return result;
        }
        if (result != libcdoc::OK) {
            LOG_ERROR("Cannot generate share tickets");
            return result;
        }
        kek.resize(32);
        std::fill(kek.begin(), kek.end(), 0);
        for (unsigned int i = 0; i < tickets.size(); i++) {
            NetworkBackend::ShareInfo share;
            result = network->fetchShare(share, shares[i].base_url, shares[i].share_id, tickets[i], cert);
            if (result != libcdoc::OK) {
                setLastError(network->getLastErrorStr(result));
                LOG_ERROR("Cannot fetch share {}", i);
                return result;
            }
            if (Crypto::xor_data(kek, kek, share.share) != libcdoc::OK) {
                setLastError("Failed to derive kek");
                LOG_ERROR("Failed to derive kek");
                return libcdoc::CRYPTO_ERROR;
            }
        }
        LOG_INFO("Fetched all shares");
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
    if (libcdoc::Crypto::xor_data(fmk, lock.encrypted_fmk, kek) != libcdoc::OK) {
        setLastError(t_("Failed to decrypt/derive fmk"));
        LOG_ERROR("{}", last_error);
        return libcdoc::CRYPTO_ERROR;
    }
    std::vector<uint8_t> hhk = libcdoc::Crypto::expand(fmk, libcdoc::CDoc2::HMAC);

    LOG_TRACE_KEY("xor: {}", lock.encrypted_fmk);
    LOG_TRACE_KEY("fmk: {}", fmk);
    LOG_TRACE_KEY("hhk: {}", hhk);
    LOG_TRACE_KEY("hmac: {}", priv->headerHMAC);

    if(libcdoc::Crypto::sign_hmac(hhk, priv->header_data) != priv->headerHMAC) {
        setLastError(t_("Wrong decryption key (user key)"));
        LOG_ERROR("{}", last_error);
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
        setLastError(priv->tar->getLastErrorStr(result));
        LOG_ERROR("{}", last_error);
        return result;
    }
    return finishDecryption();
}

libcdoc::result_t
CDoc2Reader::beginDecryption(const std::vector<uint8_t>& fmk)
{
    if(fmk.size() != 32) {
        setLastError("No decryption key provided or invalid key length");
        LOG_ERROR("{}", last_error);
        return libcdoc::WRONG_ARGUMENTS;
    }
    if (!priv->_at_nonce) {
        int result = priv->_src->seek(priv->_nonce_pos);
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
    std::vector<uint8_t> aad = toUint8Vector(libcdoc::CDoc2::PAYLOAD);
    aad.insert(aad.end(), priv->header_data.cbegin(), priv->header_data.cend());
    aad.insert(aad.end(), priv->headerHMAC.cbegin(), priv->headerHMAC.cend());
    if(auto rv = priv->dec->updateAAD(aad); rv != OK) {
        setLastError(priv->dec->getLastErrorStr(rv));
        LOG_ERROR("{}", last_error);
        return rv;
    }

    priv->zsrc = std::make_unique<libcdoc::ZSource>(priv->dec.get(), false);
    priv->tar = std::make_unique<libcdoc::TarSource>(priv->zsrc.get(), false);

    return libcdoc::OK;
}

libcdoc::result_t
CDoc2Reader::nextFile(std::string& name, int64_t& size)
{
    if (!priv->tar) {
        setLastError("nextFile() called before beginDecryption()");
        LOG_ERROR("{}", last_error);
            return libcdoc::WORKFLOW_ERROR;
        }
    result_t result = priv->tar->next(name, size);
    if (result < 0) {
        result_t sr = priv->decryptAllAndClose();
        if (sr != OK) {
            setLastError("Crypto payload integrity check failed");
            return sr;
        }
        setLastError(priv->tar->getLastErrorStr(result));
    }
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
        result_t sr = priv->decryptAllAndClose();
        if (sr != OK) {
            setLastError("Crypto payload integrity check failed");
            return sr;
        }
        setLastError(priv->tar->getLastErrorStr(result));
    }
    return result;
}

libcdoc::result_t
CDoc2Reader::finishDecryption()
{
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

    lock.label = recipient.key_label()->str();
    lock.encrypted_fmk = toUint8Vector(recipient.encrypted_fmk());

    if(recipient.fmk_encryption_method() != cdoc20::header::FMKEncryptionMethod::XOR)
    {
        LOG_WARN("Unsupported FMK encryption method");
        return;
    }
    switch(recipient.capsule_type())
    {
    case Capsule::recipients_ECCPublicKeyCapsule:
        if(const auto *key = recipient.capsule_as_recipients_ECCPublicKeyCapsule()) {
            if(key->curve() == EllipticCurve::secp384r1) {
                lock.type = Lock::Type::PUBLIC_KEY;
                lock.pk_type = Lock::PKType::ECC;
                lock.setBytes(Lock::Params::RCPT_KEY, toUint8Vector(key->recipient_public_key()));
                lock.setBytes(Lock::Params::KEY_MATERIAL, toUint8Vector(key->sender_public_key()));
                LOG_DBG("Load PK: {}", toHex(lock.getBytes(Lock::Params::RCPT_KEY)));
            } else {
                LOG_ERROR("Unsupported ECC curve: skipping");
            }
        }
        return;
    case Capsule::recipients_RSAPublicKeyCapsule:
        if(const auto *key = recipient.capsule_as_recipients_RSAPublicKeyCapsule())
        {
            lock.type = Lock::Type::PUBLIC_KEY;
            lock.pk_type = Lock::PKType::RSA;
            lock.setBytes(Lock::Params::RCPT_KEY, toUint8Vector(key->recipient_public_key()));
            lock.setBytes(Lock::Params::KEY_MATERIAL, toUint8Vector(key->encrypted_kek()));
        }
        return;
    case Capsule::recipients_KeyServerCapsule:
        if (const KeyServerCapsule *server = recipient.capsule_as_recipients_KeyServerCapsule()) {
            KeyDetailsUnion details = server->recipient_key_details_type();
            switch (details) {
            case KeyDetailsUnion::EccKeyDetails:
                if(const EccKeyDetails *eccDetails = server->recipient_key_details_as_EccKeyDetails()) {
                    if(eccDetails->curve() != EllipticCurve::secp384r1) {
                        LOG_ERROR("Unsupported elliptic curve key type");
                        return;
                    }
                    lock.pk_type = Lock::PKType::ECC;
                    lock.setBytes(Lock::Params::RCPT_KEY, toUint8Vector(eccDetails->recipient_public_key()));
                }
                break;
            case KeyDetailsUnion::RsaKeyDetails:
                if(const RsaKeyDetails *rsaDetails = server->recipient_key_details_as_RsaKeyDetails()) {
                    lock.pk_type = Lock::PKType::RSA;
                    lock.setBytes(Lock::Params::RCPT_KEY, toUint8Vector(rsaDetails->recipient_public_key()));
                }
                break;
            default:
                LOG_ERROR("Unsupported Key Server Details");
                return;
            }
            lock.type = Lock::Type::SERVER;
            lock.setString(Lock::Params::KEYSERVER_ID, server->keyserver_id()->str());
            lock.setString(Lock::Params::TRANSACTION_ID, server->transaction_id()->str());
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
            lock.setInt(Lock::KDF_ITER, capsule->kdf_iterations());
        }
        return;
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
                std::string str = url + "," + id;
                LOG_DBG("Keyshare: {}", str);
                strs.push_back(std::move(str));
            }
            std::string urls = join(strs, ";");
            LOG_DBG("Keyshare urls: {}", urls);
            std::vector<uint8_t> salt = toUint8Vector(capsule->salt());
            LOG_DBG("Keyshare salt: {}", toHex(salt));
            std::string recipient_id = capsule->recipient_id()->str();
            LOG_DBG("Keyshare recipient id: {}", recipient_id);
            lock.type = Lock::SHARE_SERVER;
            lock.setString(Lock::SHARE_URLS, urls);
            lock.setBytes(Lock::SALT, salt);
            lock.setString(Lock::RECIPIENT_ID, recipient_id);
        }
        return;
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
    if (priv->_src->read(in, libcdoc::CDoc2::LABEL.size()) != libcdoc::CDoc2::LABEL.size()) {
        LOG_ERROR("{}", last_error);
        return;
    }
    if (memcmp(libcdoc::CDoc2::LABEL.data(), in, libcdoc::CDoc2::LABEL.size())) {
        LOG_ERROR("{}", last_error);
        return;
    }
    //if (libcdoc::CDoc2::LABEL.compare(0, libcdoc::CDoc2::LABEL.size(), (const char *) in)) return;

    // Read 32-bit header length in big endian order
    uint8_t c[4];
    if (priv->_src->read(c, 4) != 4) {
        LOG_ERROR("{}", last_error);
        return;
    }
    uint32_t header_len = (c[0] << 24) | (c[1] << 16) | c[2] << 8 | c[3];
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
    if (src->read(in.data(), in.size()) != in.size()) {
        LOG_DBG("CDoc2Reader::isCDoc2File: Cannot read tag");
        return false;
    }
    if (libcdoc::CDoc2::LABEL.compare(0, in.size(), (char *) in.data(), in.size())) {
        LOG_DBG("CDoc2Reader::isCDoc2File: Invalid tag: {}", toHex(in));
        return false;
    }
    return true;
}

bool
CDoc2Reader::isCDoc2File(const std::string& path)
{
    std::ifstream fb(path, std::ios_base::in | std::ios_base::binary);
    char in[libcdoc::CDoc2::LABEL.size()];
    constexpr size_t len = libcdoc::CDoc2::LABEL.size();
    if (!fb.read(&in[0], len) || (fb.gcount() != len)) return false;
    if (libcdoc::CDoc2::LABEL.compare(0, len, &in[0], len)) return false;
    return true;
}
