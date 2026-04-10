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

#include "CDoc1Writer.h"

#include "Certificate.h"
#include "Crypto.h"
#include "DDocWriter.h"
#include "Recipient.h"
#include "Utils.h"
#include "XmlWriter.h"
#include "utils/memory.h"

#include <openssl/x509.h>

using namespace libcdoc;

#define RET_ERROR(F) if (auto rv = F; rv < 0) return rv

constexpr XMLWriter::NS DENC{ "denc", "http://www.w3.org/2001/04/xmlenc#" };
constexpr XMLWriter::NS DS{ "ds", "http://www.w3.org/2000/09/xmldsig#" };
constexpr XMLWriter::NS XENC11{ "xenc11", "http://www.w3.org/2009/xmlenc11#" };
constexpr XMLWriter::NS DSIG11{ "dsig11", "http://www.w3.org/2009/xmldsig11#" };

struct FileEntry {
	std::string name;
	size_t size;
	std::vector<uint8_t> data;
};

/**
 * @class CDoc1Writer
 * @brief CDoc1Writer is used for encrypt data.
 */

struct CDoc1Writer::Private final: public XMLWriter
{
    Private(DataConsumer &dst, std::string &last_error)
        : XMLWriter(dst)
        , lastError(last_error)
    {}

    std::string method = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
    std::string documentFormat = "ENCDOC-XML|1.1";
    std::string &lastError;
    std::vector<FileEntry> files;

    int64_t writeDocument(bool use_ddoc, const std::vector<Recipient> &rcpts, const std::function<int64_t(DataConsumer&)> &f);
    int64_t writeRecipient(const std::vector<uint8_t> &recipient, const Crypto::Key& transportKey);
};

CDoc1Writer::CDoc1Writer(DataConsumer *dst, bool take_ownership)
    : CDocWriter(1, dst, take_ownership)
{}

CDoc1Writer::~CDoc1Writer() noexcept = default;

int64_t CDoc1Writer::Private::writeDocument(bool use_ddoc, const std::vector<Recipient> &rcpts, const std::function<int64_t(DataConsumer&)> &f)
{
    return writeElement(DENC, "EncryptedData",
            {{"MimeType", use_ddoc ? "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd" : "application/octet-stream"}}, [&] -> int64_t {
        RET_ERROR(writeElement(DENC, "EncryptionMethod", {{"Algorithm", method}}));
        libcdoc::Crypto::Key transportKey = libcdoc::Crypto::generateKey(method);
        if (transportKey.key.empty()) {
            lastError = "Failed to generate transport key";
            LOG_ERROR("{}", lastError);
            return CRYPTO_ERROR;
        }
        RET_ERROR(writeElement(DS, "KeyInfo", {}, [&] -> int64_t {
            for (const Recipient& key : rcpts) {
                if (!key.isCertificate()) {
                    lastError = "Invalid recipient type";
                    LOG_ERROR("{}", lastError);
                    return UNSPECIFIED_ERROR;
                }
                if(auto rv = writeRecipient(key.cert, transportKey); rv < 0) {
                    lastError = "Failed to write Recipient info";
                    LOG_ERROR("{}", lastError);
                    return rv;
                }
            }
            return OK;
        }));
        RET_ERROR(writeElement(DENC, "CipherData", [&] {
            return writeBase64Element(DENC, "CipherValue", [&](DataConsumer &dst) -> int64_t {
                EncryptionConsumer enc(dst, method, transportKey);
                RET_ERROR(f(enc));
                return enc.close();
            });
        }));
        return writeElement(DENC, "EncryptionProperties", [&] -> int64_t {
            RET_ERROR(writeTextElement(DENC, "EncryptionProperty", {{"Name", "LibraryVersion"}}, VERSION_STR));
            RET_ERROR(writeTextElement(DENC, "EncryptionProperty", {{"Name", "DocumentFormat"}}, documentFormat));
            RET_ERROR(writeTextElement(DENC, "EncryptionProperty", {{"Name", "Filename"}}, use_ddoc ? "tmp.ddoc" : files.at(0).name));
            for(const FileEntry &file: files)
            {
                RET_ERROR(writeTextElement(DENC, "EncryptionProperty", {{"Name", "orig_file"}},
                    file.name + "|" + std::to_string(file.size) + "|" + "application/octet-stream" + "|D0"));
            }
            return OK;
        });
    });
}

int64_t CDoc1Writer::Private::writeRecipient(const std::vector<uint8_t> &recipient, const Crypto::Key& transportKey)
{
    Certificate peerCert(recipient);
    if(!peerCert)
        return UNSPECIFIED_ERROR;
    return writeElement(DENC, "EncryptedKey",
            {{"Recipient", peerCert.getName(NID_commonName)}}, [&] -> int64_t {
		std::vector<uint8_t> encryptedData;
        auto *peerPKey = X509_get0_pubkey(peerCert.handle());
		switch(EVP_PKEY_base_id(peerPKey))
		{
		case EVP_PKEY_RSA:
		{
            encryptedData = Crypto::encrypt(peerPKey, RSA_PKCS1_PADDING, transportKey.key);
            RET_ERROR(writeElement(DENC, "EncryptionMethod", {{"Algorithm", Crypto::RSA_MTH}}));
            RET_ERROR(writeElement(DS, "KeyInfo", [&] {
                return writeElement(DS, "X509Data", [&] {
                    return writeBase64Element(DS, "X509Certificate", recipient);
				});
            }));
			break;
		}
		case EVP_PKEY_EC:
        {
            auto ephKey = libcdoc::Crypto::genECKey(peerPKey);
            std::vector<uint8_t> sharedSecret = libcdoc::Crypto::deriveSharedSecret(ephKey.get(), peerPKey);

            std::string groupName(25, 0);
            size_t len = 0;
            EVP_PKEY_get_group_name(ephKey.get(), groupName.data(), groupName.size(), &len);
            groupName.resize(len);
            auto obj = make_unique_ptr<ASN1_OBJECT_free>(OBJ_txt2obj(groupName.c_str(), 0));
            std::string oid(25, 0);
            oid.resize(size_t(OBJ_obj2txt(oid.data(), int(oid.size()), obj.get(), 1)));
            std::vector<uint8_t> SsDer = Crypto::toPublicKeyDer(ephKey.get());

            std::string encryptionMethod(libcdoc::Crypto::KWAES256_MTH);
            const std::string &concatDigest = [&] -> const std::string & {
                switch ((SsDer.size() - 1) / 2) {
                case 32: return libcdoc::Crypto::SHA256_MTH; break;
                case 48: return libcdoc::Crypto::SHA384_MTH; break;
                default: return libcdoc::Crypto::SHA512_MTH; break;
                }
            }();

            std::vector<uint8_t> AlgorithmID(documentFormat.cbegin(), documentFormat.cend());
            std::vector<uint8_t> encryptionKey = libcdoc::Crypto::concatKDF(concatDigest,
                libcdoc::Crypto::keySize(encryptionMethod), sharedSecret, AlgorithmID, SsDer, recipient);
            encryptedData = libcdoc::Crypto::AESWrap(encryptionKey, transportKey.key, true);

            LOG_TRACE_KEY("Ss {}", SsDer);
            LOG_TRACE_KEY("Ksr {}", sharedSecret);
            LOG_TRACE_KEY("ConcatKDF {}", encryptionKey);
            LOG_TRACE_KEY("iv {}", transportKey.iv);
            LOG_TRACE_KEY("transport {}", transportKey.key);

            RET_ERROR(writeElement(DENC, "EncryptionMethod", {{"Algorithm", encryptionMethod}}));
            RET_ERROR(writeElement(DS, "KeyInfo", [&] {
                return writeElement(DENC, "AgreementMethod", {{"Algorithm", Crypto::AGREEMENT_MTH}}, [&] {
                    RET_ERROR(writeElement(XENC11, "KeyDerivationMethod", {{"Algorithm", Crypto::CONCATKDF_MTH}}, [&] {
                        return writeElement(XENC11, "ConcatKDFParams", {
                            {"AlgorithmID", "00" + toHex(AlgorithmID)},
                            {"PartyUInfo", "00" + toHex(SsDer)},
                            {"PartyVInfo", "00" + toHex(recipient)}}, [&] {
                            return writeElement(DS, "DigestMethod", {{"Algorithm", concatDigest}});
                        });
                    }));
                    RET_ERROR(writeElement(DENC, "OriginatorKeyInfo", [&] {
                        return writeElement(DS, "KeyValue", [&] {
                            return writeElement(DSIG11, "ECKeyValue", [&] {
                                RET_ERROR(writeElement(DSIG11, "NamedCurve", {{"URI", "urn:oid:" + oid}}));
                                return writeBase64Element(DSIG11, "PublicKey", SsDer);
                            });
                        });
                    }));
                    return writeElement(DENC, "RecipientKeyInfo", [&] {
                        return writeElement(DS, "X509Data", [&] {
                            return writeBase64Element(DS, "X509Certificate", recipient);
                        });
                    });
                });
            }));
            break;
        }
        default:
            return UNSPECIFIED_ERROR;
        }

        if (encryptedData.empty())
            return UNSPECIFIED_ERROR;
        return writeElement(DENC, "CipherData", [&] {
            return writeBase64Element(DENC, "CipherValue", encryptedData);
        });
    });
}

/**
 * Encrypt data
 */
libcdoc::result_t
CDoc1Writer::encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
    if(keys.empty())
        return WORKFLOW_ERROR;
    rcpts = keys;
    RET_ERROR(beginEncryption());
	int n_components = src.getNumComponents();
	bool use_ddoc = (n_components > 1) || (n_components == libcdoc::NOT_IMPLEMENTED);
    RET_ERROR(d->writeDocument(use_ddoc, keys, [&](DataConsumer &dst) -> int64_t {
        std::string name;
        int64_t size;
        if(use_ddoc) {
            DDOCWriter ddoc(dst);
            result_t result;
            for (result = src.next(name, size); result == OK; result = src.next(name, size)) {
                RET_ERROR(ddoc.addFile(name, "application/octet-stream", size, src));
                d->files.push_back({name, size_t(size)});
            }
            if(result != END_OF_STREAM)
                return result;
        } else {
            RET_ERROR(src.next(name, size));
            if(auto rv = src.readAll(dst); rv >= 0)
                d->files.push_back({std::move(name), size_t(rv)});
            else
                return rv;
        }
        return OK;
    }));
    d.reset();
    if (owned) return dst->close();
    return OK;
}

libcdoc::result_t
CDoc1Writer::beginEncryption()
{
    if(rcpts.empty()) {
        setLastError("No recipients added");
        LOG_ERROR("{}", last_error);
        return WORKFLOW_ERROR;
    }
    if(d) {
        setLastError("Encryption already started");
        LOG_ERROR("{}", last_error);
        return WORKFLOW_ERROR;
    }
    d = std::make_unique<Private>(*dst, last_error);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::addRecipient(const libcdoc::Recipient& rcpt)
{
    if(d)
        return WORKFLOW_ERROR;
    if (!rcpt.isCertificate()) {
        setLastError("Invalid recipient type");
        LOG_ERROR("{}", last_error);
        return WRONG_ARGUMENTS;
    }
    rcpts.push_back(rcpt);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::addFile(const std::string& name, size_t size)
{
    if(!d)
        return WORKFLOW_ERROR;
    if (name.empty() || !libcdoc::isValidUtf8(name)) return libcdoc::DATA_FORMAT_ERROR;
	d->files.push_back({name, size, {}});
	return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::writeData(const uint8_t *src, size_t size)
{
    if(!d)
        return WORKFLOW_ERROR;
	d->files.back().data.insert(d->files.back().data.end(), src, src + size);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::finishEncryption()
{
    if(!d || d->files.empty())
        return WORKFLOW_ERROR;
	bool use_ddoc = d->files.size() > 1;
    RET_ERROR(d->writeDocument(use_ddoc, rcpts, [&, this](DataConsumer &dst) -> int64_t {
        if(!use_ddoc)
            return VectorSource(d->files.back().data).readAll(dst);
        for(DDOCWriter ddoc(dst); const FileEntry& file : d->files)
            RET_ERROR(ddoc.addFile(file.name, "application/octet-stream", file.data));
        return OK;
    }));
    d.reset();
    if (owned) return dst->close();
    return libcdoc::OK;
}
