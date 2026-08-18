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

#include "CDoc1Reader.h"

#include "Certificate.h"
#include "Configuration.h"
#include "Crypto.h"
#include "CryptoBackend.h"
#include "DDocReader.h"
#include "Lock.h"
#include "Utils.h"
#include "ZStream.h"
#include "utils/memory.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <array>
#include <map>
#include <span>

using namespace libcdoc;

constexpr std::string_view MIME_ZLIB = "http://www.isi.edu/in-noes/iana/assignments/media-types/application/zip";
constexpr std::string_view MIME_DDOC = "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd";
constexpr std::string_view MIME_DDOC_OLD = "http://www.sk.ee/DigiDoc/1.3.0/digidoc.xsd";

// CDoc 1.0 used AES-CBC; CDoc 1.1 switched to AES-GCM and all CDoc 1.0
// containers have long since expired. AES-CBC also has no authentication,
// which makes it a poor fit for the "reject at the body" FMK-oracle
// defence documented below. We therefore do not accept CBC containers.
constexpr std::array SUPPORTED_METHODS {
    libcdoc::Crypto::AES128GCM_MTH, libcdoc::Crypto::AES192GCM_MTH, libcdoc::Crypto::AES256GCM_MTH
};

constexpr std::array SUPPORTED_KWAES {
    libcdoc::Crypto::KWAES128_MTH, libcdoc::Crypto::KWAES192_MTH, libcdoc::Crypto::KWAES256_MTH
};

/*
 * @class CDoc1Reader
 * @brief CDoc1Reader is used for decrypt data.
 */

struct CDoc1Reader::Private
{
    libcdoc::DataSource *dsrc = nullptr;
    bool src_owned = false;
    std::string mime, method;
    std::vector<Lock> locks;
    std::map<std::string,std::string> properties;

    std::vector<DDOCReader::File> files;
    int64_t f_pos = -1;
    std::unique_ptr<libcdoc::VectorSource> src;

    // N10: RSA oracle throttle state. Set during getFMK when the lock is
    // RSA; empty otherwise (no throttle for ECC/AES-wrap paths).
    bool is_rsa = false;
    std::string throttle_key_id;

    ~Private()
    {
        if (src_owned) delete dsrc;
    }
};

const std::vector<Lock>&
CDoc1Reader::getLocks()
{
    return d->locks;
}

libcdoc::result_t
CDoc1Reader::getLockForCert(const std::vector<uint8_t>& cert)
{
    if (std::find(SUPPORTED_METHODS.cbegin(), SUPPORTED_METHODS.cend(), d->method) == SUPPORTED_METHODS.cend()) return libcdoc::NOT_SUPPORTED;
	libcdoc::Certificate cc(cert);
    for (size_t i = 0; i < d->locks.size(); i++) {
        const Lock &ll = d->locks.at(i);
        if (ll.getBytes(Lock::Params::CERT) != cert ||
            ll.encrypted_fmk.empty())
            continue;
        switch(cc.getAlgorithm()) {
        case libcdoc::Algorithm::RSA:
            if (ll.getString(Lock::Params::METHOD) == libcdoc::Crypto::RSA_MTH) {
                return i;
            }
            break;
        case libcdoc::Algorithm::ECC:
            if(!ll.getBytes(Lock::Params::KEY_MATERIAL).empty() &&
                std::find(SUPPORTED_KWAES.cbegin(), SUPPORTED_KWAES.cend(), ll.getString(Lock::Params::METHOD)) != SUPPORTED_KWAES.cend()) {
                return i;
            }
            break;
        default:
            setLastError("Method not supported");
            return libcdoc::NOT_SUPPORTED;
        }
	}
    setLastError("No lock found with certificate key");
    return libcdoc::NOT_FOUND;
}

libcdoc::result_t
CDoc1Reader::getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx)
{
    if (lock_idx >= d->locks.size()) return libcdoc::WRONG_ARGUMENTS;
    const Lock &lock = d->locks.at(lock_idx);
    setLastError({});

    // Determine the FMK length from the container's body cipher. The CDoc1
    // body uses AES-128/192/256 in GCM mode (CBC was only used by CDoc 1.0,
    // which we no longer accept), so the FMK is 16, 24 or 32 bytes long.
    // We pin this length up-front and pass it to the RSA decrypt path so
    // that an attacker observing this function cannot distinguish between
    //   (a) RSA padding failed
    //   (b) RSA padding succeeded but the resulting length was wrong
    //   (c) a wholly different recipient was used to derive a wrong key.
    //
    // All three cases must look the same: the function returns OK with a
    // candidate FMK of the right length, and the eventual AES decrypt at
    // the container body level either authenticates that FMK (success) or
    // rejects it. CDoc1 has no header HMAC, so the AES-GCM tag is the
    // only bit of authentication we can rely on.
    size_t expected_fmk_len = 0;
    if (const EVP_CIPHER *c = libcdoc::Crypto::cipher(d->method); c) {
        expected_fmk_len = size_t(EVP_CIPHER_key_length(c));
    }
    if (expected_fmk_len != 16 && expected_fmk_len != 24 && expected_fmk_len != 32) {
        // Method-level error - independent of key bits, so does NOT feed
        // an oracle.
        setLastError("Failed to derive FMK");
        LOG_ERROR("Unsupported CDoc1 encryption method: {}", d->method);
        return libcdoc::CRYPTO_ERROR;
    }

    // From this point on, every error path returns the SAME error code and
    // SAME last-error string, so that the only bit of information leaking
    // back to the caller is "this lock did/did not produce a usable FMK".
    constexpr auto FAIL_MSG = "Failed to derive FMK";

    if (lock.isRSA()) {
        // If OAEP = false and and fmk.size() != 0, the decryptRSA always
        // returns OK with synthetic bytes on padding failure; only a
        // fundamental error (e.g. ct size mismatch with modulus) yields a non-OK result.
        fmk.resize(expected_fmk_len);
        int result = crypto->decryptRSA(fmk, lock.encrypted_fmk, false, lock_idx);
        if (result != libcdoc::OK) {
            libcdoc::cleanse(fmk);
            fmk.clear();
            setLastError(FAIL_MSG);
            LOG_ERROR("{}", last_error);
            return libcdoc::CRYPTO_ERROR;
        }
        // Even on "OK" the contents may be synthetic - that is the point.
        // The downstream AES decrypt at the body level is what tells
        // success from failure.
        //
        // N10: mark this lock as RSA and compute a stable key identifier
        // for the oracle throttle. The identifier is a SHA-256 hash of the
        // recipient's public key, so different RSA keys have independent
        // throttle intervals and no cross-tenant DoS is possible.
        d->is_rsa = true;
        std::array<uint8_t, 32> hash{};
        SHA256(lock.getBytes(Lock::Params::RCPT_KEY).data(),
               lock.getBytes(Lock::Params::RCPT_KEY).size(), hash.data());
        d->throttle_key_id = toHex(hash);
    } else {
        d->is_rsa = false;
        d->throttle_key_id.clear();
        SecureTarget key;
        int result = crypto->deriveConcatKDF(key.getTarget(),
            lock.getBytes(Lock::Params::KEY_MATERIAL),
            lock.getString(Lock::Params::CONCAT_DIGEST),
            lock.getBytes(Lock::Params::ALGORITHM_ID),
            lock.getBytes(Lock::Params::PARTY_UINFO),
            lock.getBytes(Lock::Params::PARTY_VINFO),
            lock_idx);
        if (result < 0) {
            setLastError(FAIL_MSG);
            LOG_ERROR("{}", last_error);
            return libcdoc::CRYPTO_ERROR;
        }
        fmk = libcdoc::Crypto::AESWrap(key, lock.encrypted_fmk, false);
        key.cleanse();
        // AESWrap returns {} on failure. Pad the candidate to expected
        // length so the failure shape matches the RSA path; the bytes
        // are arbitrary because the body decrypt is going to reject
        // them anyway.
        if (fmk.size() != expected_fmk_len) {
            libcdoc::cleanse(fmk);
            fmk.assign(expected_fmk_len, 0);
        }
    }

    if (fmk.size() != expected_fmk_len) {
        libcdoc::cleanse(fmk);
        fmk.clear();
        setLastError(FAIL_MSG);
        LOG_ERROR("{}", last_error);
        return libcdoc::CRYPTO_ERROR;
    }
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Reader::decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *dst)
{
    return CDoc1Reader::decryptData(fmk, [&](DataSource &src, const std::string &mime) -> result_t {
        if(mime == MIME_DDOC || mime == MIME_DDOC_OLD) {
            LOG_DBG("Contains DDoc content {}", mime);
            auto rv = DDOCReader(src).parse(dst);
            if (rv != libcdoc::OK) {
                setLastError("Failed to parse DDOC file");
                LOG_ERROR("{}", last_error);
            }
            return rv;
        }
        if(auto rv = dst->open(d->properties["Filename"], -1/*data.size()*/); rv != OK)
            return rv;
        if(auto rv = dst->writeAll(src); rv < OK)
            return rv;
        return dst->close();
    });
}

libcdoc::result_t
CDoc1Reader::beginDecryption(const std::vector<uint8_t>& fmk)
{
    return CDoc1Reader::decryptData(fmk, [&](DataSource &src, const std::string &mime) -> result_t {
        if(mime == MIME_DDOC || mime == MIME_DDOC_OLD) {
            LOG_DBG("Contains DDoc content {}", mime);
            auto rv = DDOCReader(src).files(d->files);
            if (rv != libcdoc::OK) {
                setLastError("Failed to parse DDOC file");
                LOG_ERROR("{}", last_error);
                d->files.clear();
            }
            return rv;
        }
        std::vector<uint8_t> data;
        VectorConsumer vsrc(data);
        if(auto rv = vsrc.writeAll(src); rv < OK) {
            setLastError("Cannot parse container");
            LOG_ERROR("{}", last_error);
            return rv;
        }
        d->files.push_back({
            d->properties["Filename"],
            "application/octet-stream",
            std::move(data)
        });
        return OK;
    });
}

libcdoc::result_t
CDoc1Reader::finishDecryption()
{
    d->src.reset();
    d->files.clear();
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Reader::nextFile(std::string& name, int64_t& size)
{
    if (d->files.empty()) {
        setLastError("Cannot parse container");
        LOG_ERROR("{}", last_error);
        return libcdoc::WORKFLOW_ERROR;
    }
    d->f_pos += 1;
    if ((d->f_pos < 0) || (d->f_pos >= (int64_t) d->files.size())) {
        return libcdoc::END_OF_STREAM;
    }
    name = d->files[d->f_pos].name;
    size = d->files[d->f_pos].data.size();
    d->src = std::make_unique<libcdoc::VectorSource>(d->files[d->f_pos].data);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Reader::readData(uint8_t *dst, size_t size)
{
    if (!d->src) {
        setLastError("Cannot parse container");
        LOG_ERROR("{}", last_error);
        return libcdoc::WORKFLOW_ERROR;
    }
    return d->src->read(dst, size);
}

/*
 * CDoc1Reader constructor.
 * @param src A DataSource of container
 */
CDoc1Reader::CDoc1Reader(libcdoc::DataSource *src, bool delete_on_close)
    : CDocReader(1), d(new Private{.dsrc = src, .src_owned = delete_on_close})
{
    auto hex2bin = [](std::string_view in) {
        return fromHex(in.starts_with("00") ? in.substr(2) : in);
	};

    XMLReader reader(*d->dsrc);
    while (reader.read()) {
        if(reader.isEndElement())
			continue;
		// EncryptedData
        if(reader.isElement("EncryptedData"))
            d->mime = reader.attribute("MimeType");
		// EncryptedData/EncryptionMethod
        else if(reader.isElement("EncryptionMethod"))
            d->method = reader.attribute("Algorithm");
		// EncryptedData/EncryptionProperties/EncryptionProperty
        else if(reader.isElement("EncryptionProperty"))
        {
            auto name = reader.attribute("Name");
            d->properties[std::move(name)] = reader.readText();
        }
        // EncryptedData/KeyInfo/EncryptedKey
        else if(reader.isElement("EncryptedKey"))
		{
            Lock &key = d->locks.emplace_back(Lock::Type::CDOC1);
            key.label = reader.attribute("Recipient");
            while(reader.read())
			{
                if(reader.isElement("EncryptedKey") && reader.isEndElement())
					break;
                if(reader.isEndElement())
					continue;
				// EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod
                if(reader.isElement("EncryptionMethod"))
                    key.setString(Lock::Params::METHOD, reader.attribute("Algorithm"));
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams
                else if(reader.isElement("ConcatKDFParams"))
				{
                    key.setBytes(Lock::Params::ALGORITHM_ID, hex2bin(reader.attribute("AlgorithmID")));
                    key.setBytes(Lock::Params::PARTY_UINFO, hex2bin(reader.attribute("PartyUInfo")));
                    key.setBytes(Lock::Params::PARTY_VINFO, hex2bin(reader.attribute("PartyVInfo")));
				}
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams/DigestMethod
                else if(reader.isElement("DigestMethod"))
                    key.setString(Lock::Params::CONCAT_DIGEST, reader.attribute("Algorithm"));
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/OriginatorKeyInfo/KeyValue/ECKeyValue/PublicKey
                else if(reader.isElement("PublicKey"))
                    key.setBytes(Lock::Params::KEY_MATERIAL, reader.readBase64());
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/X509Data/X509Certificate
                else if(reader.isElement("X509Certificate"))
                {
                    auto cert = reader.readBase64();
                    Certificate ssl(cert);
                    key.setBytes(Lock::CERT, std::move(cert));
                    key.setBytes(Lock::RCPT_KEY, ssl.getPublicKey());
                    key.pk_type = ssl.getAlgorithm();
                }
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/CipherData/CipherValue
                else if(reader.isElement("CipherValue"))
                    key.encrypted_fmk = reader.readBase64();
			}
		}
	}
}

CDoc1Reader::~CDoc1Reader() noexcept
{
	delete d;
}

bool
CDoc1Reader::isCDoc1File(libcdoc::DataSource *src)
{
    static constexpr std::string_view XML_TAG("<?xml");
    static constexpr std::array<uint8_t, 3> UTF8_BOM{0xEF, 0xBB, 0xBF};
    std::array<uint8_t, UTF8_BOM.size() + XML_TAG.size()> buf;
    auto n = src->read(buf.data(), buf.size());
    if (n < 0)
        return false;
    size_t available = static_cast<size_t>(n);
    const uint8_t *start = buf.data();
    if (available >= UTF8_BOM.size() && std::equal(UTF8_BOM.begin(), UTF8_BOM.end(), start)) {
        start += UTF8_BOM.size();
        available -= UTF8_BOM.size();
    }
    if (available < XML_TAG.size()) {
        LOG_DBG("CDoc1Reader::isCDoc1File: Cannot read tag");
        return false;
    }
    if (XML_TAG.compare(0, XML_TAG.size(), (const char *) start, XML_TAG.size())) {
        LOG_DBG("CDoc1Reader::isCDoc1File: Invalid tag: {}", toHex(std::span{start, XML_TAG.size()}));
        LOG_DBG("CDoc1Reader::isCDoc1File: Should be  : {}", toHex(XML_TAG));
        return false;
    }
    return true;
}

/*
 * Returns decrypted data
 * @param key Transport key to used for decrypt data
 * @param f callback with DataSource and mime data
 */
result_t CDoc1Reader::decryptData(const std::vector<uint8_t>& fmk,
    const std::function<libcdoc::result_t(libcdoc::DataSource &src, const std::string &mime)>& f)
{
    if (fmk.empty()) {
        setLastError("FMK is missing");
        return libcdoc::WRONG_ARGUMENTS;
    }
    if (fmk.size() != 16 && fmk.size() != 24 && fmk.size() != 32) {
        setLastError("FMK must be AES key with size 128, 192, 256 bits");
        return libcdoc::WRONG_ARGUMENTS;
    }
    if (!d->files.empty() || (d->f_pos != -1)) {
        setLastError("Container is already parsed");
        LOG_ERROR("{}", last_error);
        return libcdoc::WORKFLOW_ERROR;
    }
    if (auto result = d->dsrc->seek(0); result != libcdoc::OK) {
        LOG_ERROR("{}", d->dsrc->getLastErrorStr(result));
        return result;
    }
    setLastError({});

    std::vector<unsigned char> b64;
    XMLReader reader(*d->dsrc);
    int skipKeyInfo = 0;
    while (reader.read()) {
        // EncryptedData/KeyInfo
        if(reader.isElement("KeyInfo") && reader.isEndElement())
            --skipKeyInfo;
        else if(reader.isElement("KeyInfo"))
            ++skipKeyInfo;
        else if(skipKeyInfo > 0)
            continue;
        // EncryptedData/CipherData/CipherValue
        else if(reader.isElement("CipherValue"))
        {
            b64 = reader.readBase64();
            break;
        }
    }

    if(b64.empty()) {
        setLastError("Failed to decode base64 data");
        return libcdoc::IO_ERROR;
    }

    // N10: the RSA oracle throttle is keyed by a hash of the recipient's
    // public key, and only fires for RSA locks (set in getFMK). ECC/
    // AES-wrap locks have no Bleichenbacher-style oracle to protect, so
    // they skip the throttle entirely.
    auto report_failure = [&]{
        if (d->is_rsa && !d->throttle_key_id.empty()) {
            libcdoc::Crypto::rsaOracleThrottle(d->throttle_key_id);
        }
    };

    VectorSource src(b64);
    libcdoc::DecryptionSource dec(src, d->method, fmk);
    if(dec.isError()) {
        setLastError("Failed to decrypt data");
        report_failure();
        return CRYPTO_ERROR;
    }
    libcdoc::result_t inner_rv = libcdoc::OK;
    if (d->mime == MIME_ZLIB) {
        // N7: cap decompressed size to prevent decompression bombs.
        // CDoc1 buffers whole files in memory, so a smaller default (2 GiB)
        // is used compared to CDoc2's streaming default (20 GiB).
        static constexpr int64_t DEFAULT_MAX = 2LL * 1024 * 1024 * 1024;
        int64_t max_size = conf ? conf->getInt64(libcdoc::Configuration::CDOC1_MAX_DECOMPRESSED_SIZE, DEFAULT_MAX) : DEFAULT_MAX;
        libcdoc::ZSource zsrc(&dec, false, max_size);
        inner_rv = f(zsrc, d->properties["OriginalMimeType"]);
    } else {
        inner_rv = f(dec, d->mime);
    }
    if (inner_rv < OK) {
        // Body parse/decrypt failure. Could be a real I/O glitch, or a
        // tampered container - we cannot tell, and on principle we treat
        // both alike to deny the attacker a distinguisher.
        setLastError("Failed to decrypt data");
        report_failure();
        return inner_rv;
    }
    libcdoc::result_t close_rv = dec.close();
    if (close_rv != libcdoc::OK) {
        setLastError("Failed to decrypt data");
        report_failure();
        return close_rv;
    }
    return libcdoc::OK;
}
