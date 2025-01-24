#define __CDOC1WRITER_CPP__

#include "Crypto.h"
#include "DDocWriter.h"
#include "Utils.h"
#include "CDoc.h"
#include "XmlWriter.h"

#if defined(_WIN32) || defined(_WIN64)
#include <IntSafe.h>
#endif

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/x509.h>

#include "CDoc1Writer.h"

#define SCOPE(TYPE, VAR, DATA) std::unique_ptr<TYPE,decltype(&TYPE##_free)> VAR(DATA, TYPE##_free)

struct FileEntry {
	std::string name;
	size_t size;
	std::vector<uint8_t> data;
};

/**
 * @class CDoc1Writer
 * @brief CDoc1Writer is used for encrypt data.
 */

class CDoc1Writer::Private
{
public:
	std::unique_ptr<XMLWriter> _xml;
	std::vector<FileEntry> files;
	std::vector<libcdoc::Recipient> rcpts;

	static const XMLWriter::NS DENC, DS, XENC11, DSIG11;
	std::string method, documentFormat = "ENCDOC-XML|1.1", lastError;

	bool writeRecipient(XMLWriter *xmlw, const std::vector<uint8_t> &recipient, libcdoc::Crypto::Key transportKey);
};

const XMLWriter::NS CDoc1Writer::Private::DENC{ "denc", "http://www.w3.org/2001/04/xmlenc#" };
const XMLWriter::NS CDoc1Writer::Private::DS{ "ds", "http://www.w3.org/2000/09/xmldsig#" };
const XMLWriter::NS CDoc1Writer::Private::XENC11{ "xenc11", "http://www.w3.org/2009/xmlenc11#" };
const XMLWriter::NS CDoc1Writer::Private::DSIG11{ "dsig11", "http://www.w3.org/2009/xmldsig11#" };

CDoc1Writer::CDoc1Writer(libcdoc::DataConsumer *dst, bool take_ownership, const std::string &method)
	: CDocWriter(1, dst, take_ownership), d(new Private())
{
	d->method = method;
}

CDoc1Writer::~CDoc1Writer()
{
	delete d;
}

bool CDoc1Writer::Private::writeRecipient(XMLWriter *xmlw, const std::vector<uint8_t> &recipient, libcdoc::Crypto::Key transportKey)
{
	SCOPE(X509, peerCert, libcdoc::Crypto::toX509(recipient));
	if(!peerCert)
		return false;
	std::string cn = [&]{
		std::string cn;
		X509_NAME *name = X509_get_subject_name(peerCert.get());
		if(!name)
			return cn;
		int pos = X509_NAME_get_index_by_NID(name, NID_commonName, 0);
		if(pos == -1)
			return cn;
		X509_NAME_ENTRY *e = X509_NAME_get_entry(name, pos);
		if(!e)
			return cn;
		char *data = nullptr;
		int size = ASN1_STRING_to_UTF8((uint8_t**)&data, X509_NAME_ENTRY_get_data(e));

		cn.assign(data, size_t(size));
		OPENSSL_free(data);
		return cn;
	}();
	xmlw->writeElement(Private::DENC, "EncryptedKey", {{"Recipient", cn}}, [&]{
		std::vector<uint8_t> encryptedData;
		SCOPE(EVP_PKEY, peerPKey, X509_get_pubkey(peerCert.get()));
		switch(EVP_PKEY_base_id(peerPKey.get()))
		{
		case EVP_PKEY_RSA:
		{
			SCOPE(RSA, rsa, EVP_PKEY_get1_RSA(peerPKey.get()));
			encryptedData.resize(size_t(RSA_size(rsa.get())));
			RSA_public_encrypt(int(transportKey.key.size()), transportKey.key.data(),
				encryptedData.data(), rsa.get(), RSA_PKCS1_PADDING);
			xmlw->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", libcdoc::Crypto::RSA_MTH}});
			xmlw->writeElement(Private::DS, "KeyInfo", [&]{
				xmlw->writeElement(Private::DS, "X509Data", [&]{
					xmlw->writeBase64Element(Private::DS, "X509Certificate", recipient);
				});
			});
			break;
		}
		case EVP_PKEY_EC:
		{
			SCOPE(EC_KEY, peerECKey, EVP_PKEY_get1_EC_KEY(peerPKey.get()));
			int curveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(peerECKey.get()));
			SCOPE(EC_KEY, priv, EC_KEY_new_by_curve_name(curveName));
			EC_KEY_generate_key(priv.get());
			SCOPE(EVP_PKEY, pkey, EVP_PKEY_new());
			EVP_PKEY_set1_EC_KEY(pkey.get(), priv.get());
			std::vector<uint8_t> sharedSecret = libcdoc::Crypto::deriveSharedSecret(pkey.get(), peerPKey.get());

			std::string oid(50, 0);
			oid.resize(size_t(OBJ_obj2txt(&oid[0], int(oid.size()), OBJ_nid2obj(curveName), 1)));
			std::vector<uint8_t> SsDer(size_t(i2d_PublicKey(pkey.get(), nullptr)), 0);
			uint8_t *p = SsDer.data();
			i2d_PublicKey(pkey.get(), &p);

			std::string encryptionMethod(libcdoc::Crypto::KWAES256_MTH);
			std::string concatDigest = libcdoc::Crypto::SHA384_MTH;
			switch ((SsDer.size() - 1) / 2) {
			case 32: concatDigest = libcdoc::Crypto::SHA256_MTH; break;
			case 48: concatDigest = libcdoc::Crypto::SHA384_MTH; break;
			default: concatDigest = libcdoc::Crypto::SHA512_MTH; break;
			}

			std::vector<uint8_t> AlgorithmID(documentFormat.cbegin(), documentFormat.cend());
			std::vector<uint8_t> encryptionKey = libcdoc::Crypto::concatKDF(concatDigest, libcdoc::Crypto::keySize(encryptionMethod), sharedSecret,
				AlgorithmID, SsDer, recipient);
			encryptedData = libcdoc::Crypto::AESWrap(encryptionKey, transportKey.key, true);

#ifndef NDEBUG
            printf("Ss %s\n", libcdoc::toHex(SsDer).c_str());
            printf("Ksr %s\n", libcdoc::toHex(sharedSecret).c_str());
            printf("ConcatKDF %s\n", libcdoc::toHex(encryptionKey).c_str());
            printf("iv %s\n", libcdoc::toHex(transportKey.iv).c_str());
            printf("transport %s\n", libcdoc::toHex(transportKey.key).c_str());
#endif

			xmlw->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", encryptionMethod}});
			xmlw->writeElement(Private::DS, "KeyInfo", [&]{
				xmlw->writeElement(Private::DENC, "AgreementMethod", {{"Algorithm", libcdoc::Crypto::AGREEMENT_MTH}}, [&]{
					xmlw->writeElement(Private::XENC11, "KeyDerivationMethod", {{"Algorithm", libcdoc::Crypto::CONCATKDF_MTH}}, [&]{
						xmlw->writeElement(Private::XENC11, "ConcatKDFParams", {
                            {"AlgorithmID", "00" + libcdoc::toHex(AlgorithmID)},
                            {"PartyUInfo", "00" + libcdoc::toHex(SsDer)},
                            {"PartyVInfo", "00" + libcdoc::toHex(recipient)}}, [&]{
							xmlw->writeElement(Private::DS, "DigestMethod", {{"Algorithm", concatDigest}});
						});
					});
					xmlw->writeElement(Private::DENC, "OriginatorKeyInfo", [&]{
						xmlw->writeElement(Private::DS, "KeyValue", [&]{
							xmlw->writeElement(Private::DSIG11, "ECKeyValue", [&]{
								xmlw->writeElement(Private::DSIG11, "NamedCurve", {{"URI", "urn:oid:" + oid}});
								xmlw->writeBase64Element(Private::DSIG11, "PublicKey", SsDer);
							});
						});
					});
					xmlw->writeElement(Private::DENC, "RecipientKeyInfo", [&]{
						xmlw->writeElement(Private::DS, "X509Data", [&]{
							xmlw->writeBase64Element(Private::DS, "X509Certificate", recipient);
						});
					});
				});
			 });
			break;
		}
		default: break;
		}
		xmlw->writeElement(Private::DENC, "CipherData", [&]{
			xmlw->writeBase64Element(Private::DENC, "CipherValue", encryptedData);
		});
	});
	return true;
}

/**
 * Encrypt data
 */
int
CDoc1Writer::encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
	libcdoc::Crypto::Key transportKey = libcdoc::Crypto::generateKey(d->method);

	int n_components = src.getNumComponents();
	bool use_ddoc = (n_components > 1) || (n_components == libcdoc::NOT_IMPLEMENTED);

	d->_xml = std::make_unique<XMLWriter>(dst);
	d->_xml->writeStartElement(Private::DENC, "EncryptedData", {{"MimeType", use_ddoc ? "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd" : "application/octet-stream"}});
	d->_xml->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", d->method}});
	d->_xml->writeStartElement(Private::DS, "KeyInfo", {});
	for (const libcdoc::Recipient& key : keys) {
		if (!key.isCertificate()) {
			d->lastError = "Invalid recipient type";
			return libcdoc::UNSPECIFIED_ERROR;
		}
		if(!d->writeRecipient(d->_xml.get(), key.cert, transportKey)) {
			d->lastError = "Failed to write Recipient info";
			return libcdoc::IO_ERROR;
		}
	}
	d->_xml->writeEndElement(Private::DS); // KeyInfo

	std::vector<FileEntry> files;
    int64_t result = libcdoc::OK;
    d->_xml->writeElement(Private::DENC, "CipherData", [&]() -> void {
        std::vector<uint8_t> data;
        if(use_ddoc) {
            data.reserve(16384);
			DDOCWriter ddoc(data);
			std::string name;
			int64_t size;
            result = src.next(name, size);
            while (result == libcdoc::OK) {
				std::vector<uint8_t> contents;
				libcdoc::VectorConsumer vcons(contents);
                result = src.readAll(vcons);
                if (result < 0) return;
                files.push_back({name, (size_t) result});
                ddoc.addFile(name, "application/octet-stream", contents);
                result = src.next(name, size);
			}
			ddoc.close();
		} else {
			std::string name;
			int64_t size;
            result = src.next(name, size);
            if (result < 0) return;
			libcdoc::VectorConsumer vcons(data);
            result = src.readAll(vcons);
            if (result < 0) return;
            files.push_back({name, (size_t) result});
        }
        d->_xml->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, data));
    });
    if (result < 0) return result;
	d->_xml->writeElement(Private::DENC, "EncryptionProperties", [&]{
		d->_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "LibraryVersion"}}, "cdoc|0.0.1");
		d->_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "DocumentFormat"}}, d->documentFormat);
		d->_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "Filename"}}, files.size() == 1 ? files.at(0).name : "tmp.ddoc");
		for(const FileEntry &file: files)
		{
			d->_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "orig_file"}},
				file.name + "|" + std::to_string(file.size) + "|" + "application/octet-stream" + "|D0");
		}
	});
	d->_xml->writeEndElement(Private::DENC); // EncryptedData
	d->_xml->close();
	d->_xml.reset();
    if (owned) result = dst->close();
    return result;
}

int
CDoc1Writer::beginEncryption()
{
	d->_xml = std::make_unique<XMLWriter>(dst);
    return libcdoc::OK;
}

int
CDoc1Writer::addRecipient(const libcdoc::Recipient& rcpt)
{
	d->rcpts.push_back(rcpt);
    return libcdoc::OK;
}

int
CDoc1Writer::addFile(const std::string& name, size_t size)
{
	d->files.push_back({name, size, {}});
	return libcdoc::NOT_IMPLEMENTED;
}

int64_t
CDoc1Writer::writeData(const uint8_t *src, size_t size)
{
	if (d->files.empty()) return libcdoc::WORKFLOW_ERROR;
	d->files.back().data.insert(d->files.back().data.end(), src, src + size);
    return libcdoc::OK;
}

int
CDoc1Writer::finishEncryption()
{
	if (!d->_xml) return libcdoc::WORKFLOW_ERROR;
	if (d->rcpts.empty()) return libcdoc::WORKFLOW_ERROR;
	if (d->files.empty()) return libcdoc::WORKFLOW_ERROR;
	bool use_ddoc = d->files.size() > 1;

	libcdoc::Crypto::Key transportKey = libcdoc::Crypto::generateKey(d->method);

	d->_xml->writeStartElement(Private::DENC, "EncryptedData", {{"MimeType", use_ddoc ? "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd" : "application/octet-stream"}});
	d->_xml->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", d->method}});
	d->_xml->writeStartElement(Private::DS, "KeyInfo", {});
	for (const libcdoc::Recipient& key : d->rcpts) {
		if (!key.isCertificate()) {
			d->lastError = "Invalid recipient type";
			return libcdoc::UNSPECIFIED_ERROR;
		}
		if(!d->writeRecipient(d->_xml.get(), key.cert, transportKey)) {
			d->lastError = "Failed to write Recipient info";
			return libcdoc::IO_ERROR;
		}
	}
	d->_xml->writeEndElement(Private::DS); // KeyInfo

	d->_xml->writeElement(Private::DENC, "CipherData", [&]{
		if(use_ddoc) {
            std::vector<uint8_t> data;
            data.reserve(4096);
			DDOCWriter ddoc(data);
			for (const FileEntry& file : d->files) {
				std::vector<uint8_t> contents;
				ddoc.addFile(file.name, "application/octet-stream", file.data);
			}
			ddoc.close();
            d->_xml->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, data));
		} else {
            d->_xml->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, d->files.back().data));
		}
	});
	d->_xml->writeElement(Private::DENC, "EncryptionProperties", [&]{
		d->_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "LibraryVersion"}}, "cdoc|0.0.1");
		d->_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "DocumentFormat"}}, d->documentFormat);
		d->_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "Filename"}}, use_ddoc ? "tmp.ddoc" : d->files.at(0).name);
		for(const FileEntry &file: d->files)
		{
			d->_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "orig_file"}},
				file.name + "|" + std::to_string(file.size) + "|" + "application/octet-stream" + "|D0");
		}
	});
	d->_xml->writeEndElement(Private::DENC); // EncryptedData
	d->_xml->close();
	d->_xml.reset();
	if (owned) dst->close();
    return libcdoc::OK;
}
