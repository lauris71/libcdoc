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
    oss << libcdoc::CDoc2::KEK.data() << cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) << label;
    return oss.str();
}

// Get salt bitstring for HKDF expand method
std::string
libcdoc::CDoc2::getSaltForExpand(const std::vector<uint8_t>& key_material, const std::vector<uint8_t>& rcpt_key)
{
    std::ostringstream oss;
    oss << libcdoc::CDoc2::KEK.data() << cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) <<
        std::string(rcpt_key.cbegin(), rcpt_key.cend()) <<
			std::string(key_material.cbegin(), key_material.cend());
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

	std::unique_ptr<libcdoc::Crypto::Cipher> cipher;
	std::unique_ptr<TaggedSource> tgs;
	std::unique_ptr<libcdoc::ZSource> zsrc;
	std::unique_ptr<libcdoc::TarSource> tar;

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
	libcdoc::Certificate cc(cert);
	std::vector<uint8_t> other_key = cc.getPublicKey();
	LOG_DBG("Cert public key: {}", toHex(other_key));
    for (int lock_idx = 0; lock_idx < priv->locks.size(); lock_idx++) {
        const Lock &ll = priv->locks.at(lock_idx);
        LOG_DBG("Lock {} type {}", lock_idx, (int) ll.type);
        if (ll.hasTheSameKey(other_key)) {
            return lock_idx;
		}
	}
    setLastError("No lock found with certificate key");
    return libcdoc::NOT_FOUND;
}

libcdoc::result_t
CDoc2Reader::getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx)
{
    LOG_DBG("CDoc2Reader::getFMK: {}", lock_idx);
    LOG_DBG("CDoc2Reader::num locks: {}", priv->locks.size());
    const Lock& lock = priv->locks.at(lock_idx);
    std::vector<uint8_t> kek;
    if (lock.type == Lock::Type::PASSWORD) {
		// Password
        LOG_DBG("password");
        std::string info_str = libcdoc::CDoc2::getSaltForExpand(lock.label);
		std::vector<uint8_t> kek_pm;
        crypto->extractHKDF(kek_pm, lock.getBytes(Lock::SALT), lock.getBytes(Lock::PW_SALT), lock.getInt(Lock::KDF_ITER), lock_idx);
        LOG_DBG("password2");
        kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);
		if (kek.empty()) return libcdoc::CRYPTO_ERROR;
        LOG_DBG("password3");
    } else if (lock.type == Lock::Type::SYMMETRIC_KEY) {
		// Symmetric key
        LOG_DBG("symmetric");
        std::string info_str = libcdoc::CDoc2::getSaltForExpand(lock.label);
		std::vector<uint8_t> kek_pm;
        crypto->extractHKDF(kek_pm, lock.getBytes(Lock::SALT), {}, 0, lock_idx);
		kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);

        LOG_DBG("Label: {}", lock.label);
        LOG_DBG("info: {}", toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())));
        LOG_TRACE_KEY("salt: {}", lock.getBytes(Lock::SALT));
        LOG_TRACE_KEY("kek_pm: {}", kek_pm);
        LOG_TRACE_KEY("kek: {}", kek);

        if (kek.empty()) return libcdoc::CRYPTO_ERROR;
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
            int result = crypto->deriveHMACExtract(kek_pm, key_material, std::vector<uint8_t>(libcdoc::CDoc2::KEKPREMASTER.cbegin(), libcdoc::CDoc2::KEKPREMASTER.cend()), lock_idx);
			if (result < 0) {
				setLastError(crypto->getLastErrorStr(result));
                LOG_ERROR("{}", last_error);
				return result;
			}

            LOG_TRACE_KEY("Key kekPm: {}", kek_pm);

            std::string info_str = libcdoc::CDoc2::getSaltForExpand(key_material, lock.getBytes(Lock::Params::RCPT_KEY));

            LOG_DBG("info: {}", toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())));

			kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), libcdoc::CDoc2::KEY_LEN);
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
			Crypto::xor_data(kek, kek, share.share);
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
	std::vector<uint8_t> hhk = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(libcdoc::CDoc2::HMAC.cbegin(), libcdoc::CDoc2::HMAC.cend()));

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
	std::vector<uint8_t> cek = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(libcdoc::CDoc2::CEK.cbegin(), libcdoc::CDoc2::CEK.cend()));
	std::vector<uint8_t> nonce(libcdoc::CDoc2::NONCE_LEN);
	if (priv->_src->read(nonce.data(), libcdoc::CDoc2::NONCE_LEN) != libcdoc::CDoc2::NONCE_LEN) {
		setLastError("Error reading nonce");
        LOG_ERROR("{}", last_error);
		return libcdoc::IO_ERROR;
	}

    LOG_TRACE_KEY("cek: {}", cek);
    LOG_TRACE_KEY("nonce: {}", nonce);

	priv->cipher = std::make_unique<libcdoc::Crypto::Cipher>(EVP_chacha20_poly1305(), cek, nonce, false);
	std::vector<uint8_t> aad(libcdoc::CDoc2::PAYLOAD.cbegin(), libcdoc::CDoc2::PAYLOAD.cend());
	aad.insert(aad.end(), priv->header_data.cbegin(), priv->header_data.cend());
	aad.insert(aad.end(), priv->headerHMAC.cbegin(), priv->headerHMAC.cend());
	if(!priv->cipher->updateAAD(aad)) {
        setLastError("Wrong decryption key (FMK)");
        LOG_ERROR("{}", last_error);
        return libcdoc::WRONG_KEY;
	}

	priv->tgs = std::make_unique<TaggedSource>(priv->_src, false, 16);
	libcdoc::CipherSource *csrc = new libcdoc::CipherSource(priv->tgs.get(), false, priv->cipher.get());
	priv->zsrc = std::make_unique<libcdoc::ZSource>(csrc, true);
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
    if (result != OK) {
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
    if (result != OK) {
        setLastError(priv->tar->getLastErrorStr(result));
    }
    return result;
}

libcdoc::result_t
CDoc2Reader::finishDecryption()
{
	if (!priv->zsrc->isEof()) {
		setLastError(t_("CDoc contains additional payload data that is not part of content"));
        LOG_WARN("{}", last_error);
	}

    LOG_TRACE_KEY("tag: {}", priv->tgs->tag);

	priv->cipher->setTag(priv->tgs->tag);
	if (!priv->cipher->result()) {
        setLastError("Stream tag is invalid");
        LOG_ERROR("{}", last_error);
        return HASH_MISMATCH;
	}
	setLastError({});
	priv->tar.reset();
    return OK;
}

CDoc2Reader::CDoc2Reader(libcdoc::DataSource *src, bool take_ownership)
    : CDocReader(2), priv(std::make_unique<Private>(src, take_ownership))
{

	using namespace cdoc20::recipients;
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
		if(recipient->fmk_encryption_method() != FMKEncryptionMethod::XOR)
		{
            LOG_WARN("Unsupported FMK encryption method: skipping");
			continue;
		}
        auto fillRecipientPK = [&recipient,&locks = priv->locks] (Lock::PKType pk_type, auto key) -> Lock& {
            Lock &k = locks.emplace_back(Lock::Type::PUBLIC_KEY);
            k.pk_type = pk_type;
            k.setBytes(Lock::Params::RCPT_KEY, std::vector<uint8_t>(key->recipient_public_key()->cbegin(), key->recipient_public_key()->cend()));
            k.label = recipient->key_label()->str();
            k.encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
            return k;
		};
		switch(recipient->capsule_type())
		{
        case Capsule::recipients_ECCPublicKeyCapsule:
            if(const auto *key = recipient->capsule_as_recipients_ECCPublicKeyCapsule()) {
				if(key->curve() != EllipticCurve::secp384r1) {
                    LOG_ERROR("Unsupported ECC curve: skipping");
					continue;
				}
                Lock &k = fillRecipientPK(Lock::PKType::ECC, key);
                k.setBytes(Lock::Params::KEY_MATERIAL, std::vector<uint8_t>(key->sender_public_key()->cbegin(), key->sender_public_key()->cend()));
                LOG_DBG("Load PK: {}", toHex(k.getBytes(Lock::Params::RCPT_KEY)));
			}
			break;
        case Capsule::recipients_RSAPublicKeyCapsule:
            if(const auto *key = recipient->capsule_as_recipients_RSAPublicKeyCapsule())
			{
                Lock &k = fillRecipientPK(Lock::PKType::ECC, key);
                k.setBytes(Lock::Params::KEY_MATERIAL, std::vector<uint8_t>(key->encrypted_kek()->cbegin(), key->encrypted_kek()->cend()));
			}
			break;
        case Capsule::recipients_KeyServerCapsule:
            if (const KeyServerCapsule *server = recipient->capsule_as_recipients_KeyServerCapsule()) {
				KeyDetailsUnion details = server->recipient_key_details_type();
                Lock ckey;
				switch (details) {
				case KeyDetailsUnion::EccKeyDetails:
					if(const EccKeyDetails *eccDetails = server->recipient_key_details_as_EccKeyDetails()) {
						if(eccDetails->curve() == EllipticCurve::secp384r1) {
                            ckey.type = Lock::Type::SERVER;
                            ckey.pk_type = Lock::PKType::ECC;
                            ckey.setBytes(Lock::Params::RCPT_KEY, std::vector<uint8_t>(eccDetails->recipient_public_key()->cbegin(), eccDetails->recipient_public_key()->cend()));
						} else {
                            LOG_ERROR("Unsupported elliptic curve key type");
						}
					} else {
                        LOG_ERROR("Invalid file format");
					}
					break;
				case KeyDetailsUnion::RsaKeyDetails:
					if(const RsaKeyDetails *rsaDetails = server->recipient_key_details_as_RsaKeyDetails()) {
                        ckey.type = Lock::Type::SERVER;
                        ckey.pk_type = Lock::PKType::RSA;
                        ckey.setBytes(Lock::Params::RCPT_KEY, std::vector<uint8_t>(rsaDetails->recipient_public_key()->cbegin(), rsaDetails->recipient_public_key()->cend()));
					} else {
                        LOG_ERROR("Invalid file format");
					}
					break;
				default:
                    LOG_ERROR("Unsupported Key Server Details: skipping");
				}
                if (ckey.type != Lock::Type::INVALID) {
                    ckey.label = recipient->key_label()->c_str();
                    ckey.encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
                    ckey.setString(Lock::Params::KEYSERVER_ID, server->keyserver_id()->str());
                    ckey.setString(Lock::Params::TRANSACTION_ID, server->transaction_id()->str());
                    priv->locks.push_back(std::move(ckey));
				}
			} else {
                LOG_ERROR("Invalid file format");
			}
			break;
        case Capsule::recipients_SymmetricKeyCapsule:
            if(const auto *capsule = recipient->capsule_as_recipients_SymmetricKeyCapsule())
			{
                Lock &key = priv->locks.emplace_back(Lock::SYMMETRIC_KEY);
                key.label = recipient->key_label()->str();
                key.encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
                key.setBytes(Lock::SALT, std::vector<uint8_t>(capsule->salt()->cbegin(), capsule->salt()->cend()));
			}
			break;
        case Capsule::recipients_PBKDF2Capsule:
            if(const auto *capsule = recipient->capsule_as_recipients_PBKDF2Capsule()) {
				KDFAlgorithmIdentifier kdf_id = capsule->kdf_algorithm_identifier();
				if (kdf_id != KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256) {
                    LOG_ERROR("Unsupported KDF algorithm: skipping");
					continue;
				}
                Lock &key = priv->locks.emplace_back(Lock::PASSWORD);
                key.label = recipient->key_label()->str();
                key.encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
                key.setBytes(Lock::SALT, std::vector<uint8_t>(capsule->salt()->cbegin(), capsule->salt()->cend()));
                key.setBytes(Lock::PW_SALT, std::vector<uint8_t>(capsule->password_salt()->cbegin(), capsule->password_salt()->cend()));
                key.setInt(Lock::KDF_ITER, capsule->kdf_iterations());
			}
			break;
		case Capsule::recipients_KeySharesCapsule:
			if (const auto *capsule = recipient->capsule_as_recipients_KeySharesCapsule()) {
				if (capsule->recipient_type() != cdoc20::recipients::KeyShareRecipientType::SID_MID) {
					LOG_ERROR("Invalid keyshare recipient type: {}", (int) capsule->recipient_type());
					continue;
				}
				if (capsule->shares_scheme() != cdoc20::recipients::SharesScheme::N_OF_N) {
					LOG_ERROR("Invalid keyshare scheme type: {}", (int) capsule->shares_scheme());
					continue;
				}
				/* url,share_id;url,share_id... */
				std::vector<std::string> strs;
				for (auto cshare = capsule->shares()->cbegin(); cshare != capsule->shares()->cend(); ++cshare) {
					std::string id = cshare->share_id()->str();
					std::string url = cshare->server_base_url()->str();
					std::string str = url + "," + id;
					LOG_DBG("Keyshare: {}", str);
					strs.push_back(str);
				}
				std::string urls = join(strs, ";");
				LOG_DBG("Keyshare urls: {}", urls);
				std::vector<uint8_t> salt(capsule->salt()->cbegin(), capsule->salt()->cend());
				LOG_DBG("Keyshare salt: {}", toHex(salt));
				std::string recipient_id = capsule->recipient_id()->str();
				LOG_DBG("Keyshare recipient id: {}", recipient_id);
                Lock &lock = priv->locks.emplace_back(Lock::SHARE_SERVER);
                lock.label = recipient->key_label()->str();
                lock.encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
                lock.setString(Lock::SHARE_URLS, urls);
                lock.setBytes(Lock::SALT, salt);
                lock.setString(Lock::RECIPIENT_ID, recipient_id);
			}
			break;
		default:
            LOG_ERROR("Unsupported Key Details: skipping");
		}
	}
}

CDoc2Reader::CDoc2Reader(const std::string &path)
	: CDoc2Reader(new libcdoc::IStreamSource(path), true)
{
}

bool
CDoc2Reader::isCDoc2File(libcdoc::DataSource *src)
{
    uint8_t in[libcdoc::CDoc2::LABEL.size()];
	constexpr size_t len = libcdoc::CDoc2::LABEL.size();
    if (src->read(&in[0], len) != len) return false;
    if (libcdoc::CDoc2::LABEL.compare(0, len, (char *) &in[0], len)) return false;
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
