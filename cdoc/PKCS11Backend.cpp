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

#include "PKCS11Backend.h"
#include "Certificate.h"
#include "Crypto.h"
#include "ILogger.h"
#include "Utils.h"

#include "pkcs11.h"

#if defined(_WIN32) || defined(_WIN64)
#include <IntSafe.h>
#endif

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include <functional>

#ifdef _WIN32
//#include <Windows.h>
//#include <wincrypt.h>
//#include <cryptuiapi.h>
#else
#include <dlfcn.h>
#endif

struct libcdoc::PKCS11Backend::Private
{
public:
    int login(int slot, const std::vector<uint8_t>& pin);
	int logout();
	std::vector<CK_BYTE> attribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type) const;

    std::vector<CK_OBJECT_HANDLE> findObjects(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls, const std::vector<CK_BYTE> &id, const std::string& label, const std::function<bool(CK_SESSION_HANDLE, CK_OBJECT_HANDLE)> &validate) const;
    std::vector<libcdoc::PKCS11Backend::Handle> findAllObjects(CK_OBJECT_CLASS klass, const std::vector<uint8_t>& id, const std::string& label, const std::function<bool(CK_SESSION_HANDLE, CK_OBJECT_HANDLE)> &validate = nullptr);


#ifdef _WIN32
	bool load(const std::string &driver)
	{
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
		return (h = LoadLibraryW(std::filesystem::u8path(driver).c_str())) != 0;
#else
		return false;
#endif
	}

	void* resolve(const char *symbol) const
	{ return h ? (void*)GetProcAddress(h, symbol) : nullptr; }

	void unload()
	{ if(h) FreeLibrary(h); h = {}; }

	HINSTANCE h {};
#else
	bool load(const std::string &driver) {
		return (h = dlopen(driver.c_str(), RTLD_LAZY));
	}

	void *resolve(const char *symbol) const {
		return h ? dlsym(h, symbol) : nullptr;
	}

	void unload() {
		if(h) dlclose(h); h = {};
	}

	void *h {};
#endif

	CK_FUNCTION_LIST *f {};
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
};

int
libcdoc::PKCS11Backend::Private::login(int slot, const std::vector<uint8_t>& pin)
{
	if (!f || session) return PKCS11_ERROR;
	unsigned long result = f->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session);
	if(result != CKR_OK) {
        LOG_DBG("PKCS11:C_OpenSession failed, error code: {0:X} ({0:d})", result);
		return PKCS11_ERROR;
	}
	if (!pin.empty()) {
        result = f->C_Login(session, CKU_USER, CK_BYTE_PTR(pin.data()), CK_ULONG(pin.size()));
		switch(result) {
        case CKR_OK:
            LOG_DBG("PKCS11:C_Login OK");
			break;
		case CKR_USER_ALREADY_LOGGED_IN:
            LOG_DBG("PKCS11:C_Login USER_ALREADY_LOGGED_IN");
			break;
		case CKR_CANCEL:
		case CKR_FUNCTION_CANCELED:
            LOG_DBG("PKCS11:C_Login CANCELED");
			break;
		default:
      LOG_DBG("PKCS11:C_Login {}", result);
			f->C_CloseSession(session);
			session = CK_INVALID_HANDLE;
			return PKCS11_ERROR;
		}
	}
    return OK;
}

int
libcdoc::PKCS11Backend::Private::logout()
{
	if (!f || !session) return PKCS11_ERROR;
	f->C_Logout(session);
	f->C_CloseSession(session);
	session = CK_INVALID_HANDLE;
	key = CK_INVALID_HANDLE;
    return OK;
}

std::vector<CK_BYTE>
libcdoc::PKCS11Backend::Private::attribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type) const
{
	CK_ATTRIBUTE attr { type, nullptr, 0 };
	if(f->C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK)
		return {};
	std::vector<CK_BYTE> value(size_t(attr.ulValueLen));
	attr.pValue = value.data();
	if(f->C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK)
		return {};
	return value;
}

std::vector<CK_OBJECT_HANDLE>
libcdoc::PKCS11Backend::Private::findObjects(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls, const std::vector<CK_BYTE> &id, const std::string& label, const std::function<bool(CK_SESSION_HANDLE, CK_OBJECT_HANDLE)> &validate) const
{
	CK_BBOOL _true = CK_TRUE;
	std::vector<CK_ATTRIBUTE> attrs {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_TOKEN, &_true, sizeof(_true) }
	};
	if(!id.empty()) {
		attrs.push_back({ CKA_ID, CK_VOID_PTR(id.data()), CK_ULONG(id.size()) });
	}
	if(!label.empty()) {
		attrs.push_back({ CKA_LABEL, CK_VOID_PTR(label.data()), CK_ULONG(label.size()) });
	}
	CK_RV err = f->C_FindObjectsInit(session, attrs.data(), CK_ULONG(attrs.size()));
    if(err != CKR_OK) {
        LOG_DBG("PKCS11: C_FindObjectsInit {}", err);
		return {};
	}
    CK_ULONG count = 32;
	std::vector<CK_OBJECT_HANDLE> result(count);
	err = f->C_FindObjects(session, result.data(), CK_ULONG(result.size()), &count);
	if(err != CKR_OK) {
        LOG_DBG("PKCS11: C_FindObjects {}", err);
		result.clear();
	} else {
		result.resize(count);
	}
    f->C_FindObjectsFinal(session);
    if (validate) {
        std::vector<CK_OBJECT_HANDLE> tmp;
        for (auto obj : result) {
            if (validate(session, obj)) tmp.push_back(obj);
        }
        result = std::move(tmp);
    }
	return result;
}

std::vector<libcdoc::PKCS11Backend::Handle>
libcdoc::PKCS11Backend::Private::findAllObjects(CK_OBJECT_CLASS klass, const std::vector<uint8_t>& id, const std::string& label, const std::function<bool(CK_SESSION_HANDLE, CK_OBJECT_HANDLE)> &validate)
{
	// Load all slots.
	CK_ULONG size = 0;
	if(f->C_GetSlotList(true, nullptr, &size) != CKR_OK) return {};
	std::vector<CK_SLOT_ID> slots(size);
	if(size && f->C_GetSlotList(true, slots.data(), &size) != CKR_OK) return {};

	std::vector<libcdoc::PKCS11Backend::Handle> objs;
	// Iterate over all found slots
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	for(const CK_SLOT_ID &slot: slots) {
		if(session) f->C_CloseSession(session);
		if(f->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session) != CKR_OK) continue;
        for(CK_OBJECT_HANDLE obj: findObjects(session, klass, id, label, validate)) {
            std::vector<CK_BYTE> obj_id = attribute(session, obj, CKA_ID);
            if (!id.empty()) {
                std::vector<uint8_t> uv(obj_id.cbegin(), obj_id.cend());
                if (uv != id) continue;
            }
            if (!label.empty()) {
                std::vector<CK_BYTE> v = attribute(session, obj, CKA_LABEL);
                if (label.compare(0, label.size(), (const char *) v.data(), v.size())) continue;
            }
            // Id and label match
            if (obj_id.empty()) continue;
            objs.push_back({(uint32_t) slot, std::vector<uint8_t>(obj_id.cbegin(), obj_id.cend())});
		}
	}
	if(session) f->C_CloseSession(session);
	return std::move(objs);
}

/*
 * Loads PKCS#11 token.
 *
 * @param path full path to the PKCS#11 driver (e.g. /usr/lib/opensc-pkcs11.so)
 * @param password token password
 */
libcdoc::PKCS11Backend::PKCS11Backend(const std::string &driver)
	: d(nullptr)
{
	std::unique_ptr<Private> p = std::make_unique<Private>();
	if(!p->load(driver)) return;
    LOG_DBG("PKCS11: driver loaded");
	CK_C_GetFunctionList l = CK_C_GetFunctionList(p->resolve("C_GetFunctionList"));
	if (!l || l(&p->f) != CKR_OK || !p->f) return;
    LOG_DBG("PKCS11: function list loaded");
	unsigned long result = p->f->C_Initialize(nullptr);
	if (result != CKR_OK) {
        LOG_DBG("PKCS11: C_Initialize {}", result);
		return;
	}
    LOG_DBG("PKCS11: C_Initialize OK");
	d = std::move(p);
}

libcdoc::PKCS11Backend::~PKCS11Backend()
{
	if(d->f) {
		d->f->C_Finalize(nullptr);
		d->f = nullptr;
	}
#ifdef _WIN32
	if(d->h) FreeLibrary(d->h);
#else
    if(d->h)
    {
        dlclose(d->h);
    }
#endif
}

std::vector<libcdoc::PKCS11Backend::Handle>
libcdoc::PKCS11Backend::findCertificates(const std::string& label)
{
	if (!d) return {};
	return d->findAllObjects(CKO_CERTIFICATE, {}, label);
}

std::vector<libcdoc::PKCS11Backend::Handle>
libcdoc::PKCS11Backend::findSecretKeys(const std::string& label)
{
	if (!d) return {};
	return d->findAllObjects(CKO_SECRET_KEY, {}, label);
}

std::vector<libcdoc::PKCS11Backend::Handle>
libcdoc::PKCS11Backend::findCertificates(const std::vector<uint8_t>& public_key)
{
    if(!d) return {};
    return d->findAllObjects(CKO_CERTIFICATE, {}, {}, [&](CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object){
        std::vector<uint8_t> val = d->attribute(session, object, CKA_VALUE);
        if (val.empty()) return false;
        Certificate cert(val);
        std::vector<uint8_t> cert_key = cert.getPublicKey();
        return cert_key == public_key;
    });
}

libcdoc::result_t
libcdoc::PKCS11Backend::useSecretKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label)
{
	if(!d) return CRYPTO_ERROR;
    if (!d->session) {
        int result = d->login(slot, pin);
        if (result != OK) return result;
    }
    std::vector<CK_OBJECT_HANDLE> handles = d->findObjects(d->session, CKO_SECRET_KEY, id, label, nullptr);
    LOG_DBG("PKCS11: useSecretKey id={}; label={}; found {} keys", toHex(id), label, handles.size());
    if (handles.empty() || (handles.size() != 1)) return CRYPTO_ERROR;
    d->key = handles[0];
    LOG_DBG("PKCS11: useSecretKey Using key ", d->key);
    return OK;
}

libcdoc::result_t
libcdoc::PKCS11Backend::usePrivateKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label)
{
    if(!d) return CRYPTO_ERROR;
    if (!d->session) {
        int result = d->login(slot, pin);
        if (result != OK) return result;
    }
    std::vector<CK_OBJECT_HANDLE> handles = d->findObjects(d->session, CKO_PRIVATE_KEY, id, label, nullptr);
    LOG_DBG("PKCS11: usePrivateKey id={}; label={}; found {} keys", toHex(id), label, handles.size());
    if (handles.size() != 1) return CRYPTO_ERROR;
    d->key = handles[0];
    LOG_DBG("PKCS11: usePrivateKey Using key {}", d->key);
    return OK;
}

libcdoc::result_t
libcdoc::PKCS11Backend::getCertificate(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label)
{
    if(!d) return CRYPTO_ERROR;
    if (!d->session) {
        int result = d->login(slot, pin);
        if (result != OK) return result;
    }
    std::vector<CK_OBJECT_HANDLE> handles = d->findObjects(d->session, CKO_CERTIFICATE, id, label, nullptr);
    LOG_DBG("PKCS11: getCertificate id={}; label={}; found {} certificates", toHex(id), label, handles.size());
    if (handles.empty() || (handles.size() != 1)) return CRYPTO_ERROR;
    CK_OBJECT_HANDLE handle = handles[0];
    val = d->attribute(d->session, handle, CKA_VALUE);
    if (val.empty()) {
        LOG_DBG("PKCS11: getCertificate CKA_VALUE error");
        return CRYPTO_ERROR;
    }
    return OK;
}

libcdoc::result_t
libcdoc::PKCS11Backend::getPublicKey(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label)
{
	if(!d) return CRYPTO_ERROR;
    if (!d->session) {
        int result = d->login(slot, pin);
        if (result != OK) return result;
    }
    std::vector<CK_OBJECT_HANDLE> handles = d->findObjects(d->session, CKO_PUBLIC_KEY, id, label, nullptr);
    LOG_DBG("PKCS11: usePublicKey id={}; label={}; found {} objects", toHex(id), label, handles.size());
	if (handles.empty() || (handles.size() != 1)) return CRYPTO_ERROR;
	CK_OBJECT_HANDLE handle = handles[0];
	std::vector<uint8_t> v = d->attribute(d->session, handle, CKA_KEY_TYPE);
	if (v.empty()) {
        LOG_DBG("PKCS11: getValue CKA_KEY_TYPE error");
		return CRYPTO_ERROR;
	}
	rsa = (*((CK_KEY_TYPE *) v.data()) == CKK_RSA);
    if (rsa) return libcdoc::NOT_IMPLEMENTED;
    v = d->attribute(d->session, handle, CKA_EC_PARAMS);
	if (v.empty()) {
        LOG_DBG("PKCS11: getValue CKA_EC_PARAMS error");
		return CRYPTO_ERROR;
	}
    std::vector<uint8_t> w = d->attribute(d->session, handle, CKA_EC_POINT);
    if (w.empty()) {
        LOG_DBG("PKCS11: getValue CKA_EC_POINT error");
        return CRYPTO_ERROR;
    }
    const uint8_t *p = v.data();
    EC_GROUP *group = d2i_ECPKParameters(nullptr, &p, v.size());
    if (!group) {
        LOG_DBG("PKCS11: getValue d2i_ECPKParameters error");
        return CRYPTO_ERROR;
    }
    EC_POINT *pub_key_point = EC_POINT_new(group);
    int result =  EC_POINT_oct2point(group, pub_key_point, w.data() + 2, w.size() - 2, NULL);
    // Associate the Point with an EC_KEY: Finally, set up an EC_KEY structure and assign the point as the public key.
    EC_KEY *key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    EC_KEY_set_public_key(key, pub_key_point);
    EVP_PKEY *evp_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(evp_pkey, key);
    val = Crypto::toPublicKeyDer(evp_pkey);
    EVP_PKEY_free(evp_pkey);
    EC_POINT_free(pub_key_point);
    EC_GROUP_free(group);
    return OK;
}

libcdoc::result_t
libcdoc::PKCS11Backend::decryptRSA(std::vector<uint8_t> &dst, const std::vector<uint8_t> &data, bool oaep, unsigned int idx)
{
	if(!d) return CRYPTO_ERROR;

    int result = connectToKey(idx, true);
    if (result != OK) return result;

	CK_RSA_PKCS_OAEP_PARAMS params { CKM_SHA256, CKG_MGF1_SHA256, 0, nullptr, 0 };
	auto mech = oaep ? CK_MECHANISM{ CKM_RSA_PKCS_OAEP, &params, sizeof(params) } : CK_MECHANISM{ CKM_RSA_PKCS, nullptr, 0 };
	if(d->f->C_DecryptInit(d->session, &mech, d->key) != CKR_OK) {
		d->logout();
		return CRYPTO_ERROR;
	}
	CK_ULONG size = 0;
	if(d->f->C_Decrypt(d->session, CK_CHAR_PTR(data.data()), CK_ULONG(data.size()), 0, &size) != CKR_OK) {
		d->logout();
		return CRYPTO_ERROR;
	}
	dst.resize(size);
	if(d->f->C_Decrypt(d->session, CK_CHAR_PTR(data.data()), CK_ULONG(data.size()), dst.data(), &size) != CKR_OK) return CRYPTO_ERROR;
	d->logout();
    return OK;
}

libcdoc::result_t
libcdoc::PKCS11Backend::deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx)
{
	if(!d) return CRYPTO_ERROR;

    int result = connectToKey(idx, true);
    if (result != OK) return result;

	std::vector<uint8_t> sharedSecret;

	CK_ECDH1_DERIVE_PARAMS ecdh_parms = { CKD_NULL, 0, nullptr, CK_ULONG(public_key.size()), CK_BYTE_PTR(public_key.data()) };
	CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &ecdh_parms, sizeof(CK_ECDH1_DERIVE_PARAMS) };
	CK_BBOOL _false = CK_FALSE;
	CK_OBJECT_CLASS newkey_class = CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	std::vector<CK_ATTRIBUTE> newkey_template{
		{CKA_TOKEN, &_false, sizeof(_false)},
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)}
	};
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	unsigned long p11result = d->f->C_DeriveKey(d->session, &mech, d->key, newkey_template.data(), CK_ULONG(newkey_template.size()), &newkey);
	if(p11result != CKR_OK) {
        LOG_DBG("PKCS11:deriveECDH1() C_DeriveKey {}", p11result);
		d->logout();
		return CRYPTO_ERROR;
	}

    dst = d->attribute(d->session, newkey, CKA_VALUE);
    LOG_DBG("PKCS11:deriveECDH1() derived key: {}", toHex(dst));
	d->logout();
    return dst.empty() ? CRYPTO_ERROR : OK;
}

libcdoc::result_t
libcdoc::PKCS11Backend::extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)
{
	if (kdf_iter > 0) return libcdoc::NOT_IMPLEMENTED;

	if(!d) return CRYPTO_ERROR;

    int result = connectToKey(idx, false);
    if (result != OK) return result;

	CK_HKDF_PARAMS hkdf_params = {
		1, // bExtract
		0, // bExpand
		CKM_SHA256, // prfHashMechanism
		CKF_HKDF_SALT_DATA, // ulSaltType
		(CK_BYTE_PTR) salt.data(), // pSalt
		(CK_ULONG) salt.size(), // ulSaltLen
		0, // hSaltKey
		nullptr, // pInfo
		0 // ulInfoLen
	};
	CK_MECHANISM mech = {
		CKM_HKDF_DERIVE,
		&hkdf_params,
		sizeof(CK_HKDF_PARAMS)
	};
	CK_BBOOL _false = CK_FALSE;
	CK_OBJECT_CLASS newkey_class = CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	std::vector<CK_ATTRIBUTE> newkey_template{
		{CKA_TOKEN, &_false, sizeof(_false)},
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
	};
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	unsigned long p11result = d->f->C_DeriveKey(d->session, &mech, d->key, newkey_template.data(), CK_ULONG(newkey_template.size()), &newkey);
	if(p11result != CKR_OK) {
        LOG_DBG("PKCS11:extractHKDF() C_DeriveKey {}", p11result);
		d->logout();
		return CRYPTO_ERROR;
	}

    kek = d->attribute(d->session, newkey, CKA_VALUE);
    LOG_DBG("PKCS11:extractHKDF() derived key: {}", toHex(kek));
	d->logout();
    return kek.empty() ? CRYPTO_ERROR : OK;
}

libcdoc::result_t
libcdoc::PKCS11Backend::sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, unsigned int idx)
{
    if(!d) return CRYPTO_ERROR;

    int result = connectToKey(idx, true);
    if (result != OK) return result;

    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ATTRIBUTE attribute { CKA_KEY_TYPE, &keyType, sizeof(keyType) };
    d->f->C_GetAttributeValue(d->session, d->key, &attribute, 1);

    CK_RSA_PKCS_PSS_PARAMS pssParams { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_MECHANISM mech { keyType == CKK_ECDSA ? CKM_ECDSA : CKM_RSA_PKCS, nullptr, 0 };
    std::vector<uint8_t> data;
    if(keyType == CKK_RSA) {
        switch(algorithm) {
        case libcdoc::CryptoBackend::HashAlgorithm::SHA_224:
            data = libcdoc::fromHex("302d300d06096086480165030402040500041c");
            pssParams = { CKM_SHA224, CKG_MGF1_SHA224, 24 };
            break;
        case libcdoc::CryptoBackend::HashAlgorithm::SHA_256:
            data = libcdoc::fromHex("3031300d060960864801650304020105000420");
            pssParams = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
            break;
        case libcdoc::CryptoBackend::HashAlgorithm::SHA_384:
            data = libcdoc::fromHex("3041300d060960864801650304020205000430");
            pssParams = { CKM_SHA384, CKG_MGF1_SHA384, 48 };
            break;
        case libcdoc::CryptoBackend::HashAlgorithm::SHA_512:
            data = libcdoc::fromHex("3051300d060960864801650304020305000440");
            pssParams = { CKM_SHA512, CKG_MGF1_SHA512, 64 };
            break;
        default:
            break;
        }
        if(usePSS(idx)) {
            mech = { CKM_RSA_PKCS_PSS, &pssParams, sizeof(CK_RSA_PKCS_PSS_PARAMS) };
            data.clear();
        }
    }
    data.insert(data.end(), digest.begin(), digest.end());

    if(d->f->C_SignInit(d->session, &mech, d->key) != CKR_OK) {
        return PKCS11_ERROR;
    }
    CK_ULONG size = 0;
    if(d->f->C_Sign(d->session, CK_BYTE_PTR(data.data()), CK_ULONG(data.size()), nullptr, &size) != CKR_OK) {
        return PKCS11_ERROR;
    }
    dst.resize(int(size));
    if(d->f->C_Sign(d->session, CK_BYTE_PTR(data.data()), CK_ULONG(data.size()), CK_BYTE_PTR(dst.data()), &size) != CKR_OK) {
        return PKCS11_ERROR;
    }
    return OK;
}
