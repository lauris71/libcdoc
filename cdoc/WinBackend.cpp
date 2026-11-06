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

#include "WinBackend.h"

#include "CDoc2.h"
#include "Crypto.h"
#include "Logger.h"
#include "Utils.h"
#include "utils/memory.h"

#include <Windows.h>
#include <wincrypt.h>

// Convert a UTF-8 std::string to a std::wstring (UTF-16) using the Windows
// API. The previous implementation zero-extended each byte into a wchar_t,
// which silently mangled any non-ASCII input - in particular non-ASCII PINs
// and key names. A single mis-converted PIN byte is enough to fail
// authentication; on smart cards this consumes a retry slot and can
// permanently lock the card after exhausting the retry counter.
static std::wstring toWide(const std::string &in)
{
    if (in.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     in.data(), int(in.size()),
                                     nullptr, 0);
    if (needed <= 0) {
        LOG_ERROR("WinBackend::toWide: invalid UTF-8 input (GetLastError={})",
                  DWORD(GetLastError()));
        return {};
    }
    std::wstring out(size_t(needed), L'\0');
    int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                      in.data(), int(in.size()),
                                      out.data(), needed);
    if (written != needed) {
        LOG_ERROR("WinBackend::toWide: MultiByteToWideChar mismatch "
                  "(GetLastError={})", DWORD(GetLastError()));
        // Wipe the partially-populated buffer before discarding it.
        SecureZeroMemory(out.data(), out.size() * sizeof(wchar_t));
        return {};
    }
    return out;
}

struct libcdoc::WinBackend::Private {
    NCRYPT_PROV_HANDLE  prov = 0;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;

    Private(const std::string& name) {
        std::wstring wname;
        if (name.empty()) {
            wname = MS_SMART_CARD_KEY_STORAGE_PROVIDER;
        } else {
            wname = toWide(name);
        }
        NCryptOpenStorageProvider(&prov, wname.c_str(), 0);
        if (prov) {
            NCryptKeyName *wkeyname = NULL;
            void *state = NULL;
            SECURITY_STATUS result = NCryptEnumKeys(prov, NULL, &wkeyname, &state, NCRYPT_SILENT_FLAG);
            while (result == ERROR_SUCCESS) {
                std::string_view name{(const char*)wkeyname->pszName, wcslen(wkeyname->pszName)};
                std::string_view algo{(const char*)wkeyname->pszAlgid, wcslen(wkeyname->pszAlgid)};
                LOG_DBG("Name: {} Algo: {}", name, algo);
                NCryptFreeBuffer(wkeyname);
                result = NCryptEnumKeys(prov, NULL, &wkeyname, &state, NCRYPT_SILENT_FLAG);
            }
        }
    }
    ~Private() {
        if (key) NCryptFreeObject(key);
        if (prov) NCryptFreeObject(prov);
    }

    int derive(NCRYPT_PROV_HANDLE &prov, NCRYPT_KEY_HANDLE &publicKeyHandle, NCRYPT_SECRET_HANDLE &sharedSecret, const std::vector<uint8_t> &public_key);
};

int
libcdoc::WinBackend::Private::derive(NCRYPT_PROV_HANDLE &prov, NCRYPT_KEY_HANDLE &publicKeyHandle, NCRYPT_SECRET_HANDLE &sharedSecret, const std::vector<uint8_t> &public_key)
{
    uint32_t key_size = (public_key.size() - 1) / 2;
	BCRYPT_ECCKEY_BLOB oh = { BCRYPT_ECDH_PUBLIC_P384_MAGIC, key_size };
	switch (key_size * 8) {
	case 256:
        oh.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        break;
	case 384:
        oh.dwMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
        break;
	case 521:
        oh.dwMagic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
        break;
	default:
        return libcdoc::WRONG_ARGUMENTS;
	}
	std::vector<uint8_t> blob((uint8_t *)&oh, (uint8_t *)&oh + sizeof(BCRYPT_ECCKEY_BLOB));
	blob.insert(blob.cend(), public_key.cbegin() + 1, public_key.cend());

    SECURITY_STATUS err = 0;

	DWORD size = 0;
	err = NCryptGetProperty(key, NCRYPT_PROVIDER_HANDLE_PROPERTY, PBYTE(&prov), sizeof(prov), &size, 0);
    if (err != ERROR_SUCCESS) {
        return libcdoc::CRYPTO_ERROR;
    }

    err = NCryptImportKey(prov, 0, BCRYPT_ECCPUBLIC_BLOB, 0, &publicKeyHandle, PBYTE(blob.data()), DWORD(blob.size()), 0);
    if (err != ERROR_SUCCESS) {
		NCryptFreeObject(prov);
        return libcdoc::CRYPTO_ERROR;
    }
    err = NCryptSecretAgreement(key, publicKeyHandle, &sharedSecret, 0);
    if (err != ERROR_SUCCESS) {
		NCryptFreeObject(publicKeyHandle);
		NCryptFreeObject(prov);
		return libcdoc::CRYPTO_ERROR;
	}
    return libcdoc::OK;
}

libcdoc::WinBackend::WinBackend(const std::string& provider)
: d(std::make_unique<Private>(provider))
{
}

libcdoc::WinBackend::~WinBackend()
{
}

libcdoc::result_t
libcdoc::WinBackend::useKey(const std::string& name, const std::string& pin)
{
    if (!d->prov) return CRYPTO_ERROR;
    if (d->key) {
        NCryptFreeObject(d->key);
        d->key = 0;
    }

    // Reject invalid UTF-8 in the key name early instead of silently
    // truncating it. toWide() returns an empty string both for an empty
    // input and for invalid UTF-8 - distinguish the two.
    if (name.empty()) {
        LOG_ERROR("WinBackend::useKey: empty key name");
        return WRONG_ARGUMENTS;
    }
    std::wstring wname = toWide(name);
    if (wname.empty()) {
        LOG_ERROR("WinBackend::useKey: invalid UTF-8 in key name");
        return WRONG_ARGUMENTS;
    }

    SECURITY_STATUS err = NCryptOpenKey(d->prov, &d->key, wname.c_str(), 0, NCRYPT_SILENT_FLAG);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR("WinBackend::useKey: NCryptOpenKey failed (status={:#x})", DWORD(err));
        return CRYPTO_ERROR;
    }

    if (pin.empty()) {
        return OK;
    }

    std::wstring wpin = toWide(pin);
    if (wpin.empty()) {
        // toWide() already logged the reason. Treat invalid UTF-8 in the PIN
        // as a hard failure so we do NOT submit a partial / mangled PIN to
        // the card and consume a retry slot.
        NCryptFreeObject(d->key);
        d->key = 0;
        return WRONG_ARGUMENTS;
    }

    // NCryptSetProperty(NCRYPT_PIN_PROPERTY) expects cbInput in *bytes*,
    // not wide-character count. The previous code passed wpin.size(), which
    // is the WCHAR count - i.e. half the actual byte length - so only half
    // of the PIN was forwarded to the card. Pass the byte length explicitly,
    // and include the trailing NUL since CNG documents the PIN as a
    // null-terminated wide string.
    const DWORD pin_bytes = DWORD((wpin.size() + 1) * sizeof(wchar_t));
    err = NCryptSetProperty(d->key, NCRYPT_PIN_PROPERTY,
                            PBYTE(wpin.data()), pin_bytes,
                            NCRYPT_SILENT_FLAG);
    // Wipe the wide PIN buffer regardless of the outcome before discarding
    // it. std::wstring::data() is contiguous and writeable since C++17.
    SecureZeroMemory(wpin.data(), wpin.size() * sizeof(wchar_t));

    if (err != ERROR_SUCCESS) {
        LOG_ERROR("WinBackend::useKey: NCryptSetProperty(PIN) failed (status={:#x})", DWORD(err));
        NCryptFreeObject(d->key);
        d->key = 0;
        return CRYPTO_ERROR;
    }
    return OK;
}

libcdoc::result_t
libcdoc::WinBackend::decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx)
{
	if(!d->prov) return CRYPTO_ERROR;
    int result = connectToKey(idx, true);
    if (result != OK) return result;

    if (!oaep) {
        // If oaep is false, dst must be pre-allocated to the expected length.
        // This is required to apply the implicit-rejection countermeasure on padding failure.
        if (dst.empty()) {
            LOG_ERROR("WinBackend::decryptRSA: dst must be pre-allocated for PKCS#1 v1.5 decryption");
            return CRYPTO_ERROR;
        };
        // Raw RSA decrypt: ask CNG NOT to strip the padding so we can apply the
        // implicit-rejection countermeasure in user space. CNG exposes raw
        // (textbook) RSA via paddingInfo=NULL and flags=0.
        DWORD em_size = 0;
        SECURITY_STATUS err = NCryptDecrypt(d->key, PBYTE(data.data()), DWORD(data.size()), nullptr, nullptr, 0, &em_size, 0);
        if (err != ERROR_SUCCESS) {
            LOG_ERROR("WinBackend::decryptRSA: NCryptDecrypt(size) failed (status={:#x})", DWORD(err));
            return CRYPTO_ERROR;
        }
        std::vector<uint8_t> em(em_size, 0);
        err = NCryptDecrypt(d->key, PBYTE(data.data()), DWORD(data.size()), nullptr, PBYTE(em.data()), em_size, &em_size, 0);
        if (err != ERROR_SUCCESS) {
            libcdoc::cleanse(em);
            LOG_ERROR("WinBackend::decryptRSA: NCryptDecrypt failed (status={:#x})", DWORD(err));
            return CRYPTO_ERROR;
        }
        em.resize(em_size);

        // Derive a per-(key, ct) synthetic plaintext from the raw RSA
        // output (EM). EM is private-key-dependent and unpredictable to
        // attackers who do not know the private key.
        std::vector<uint8_t> synth = libcdoc::Crypto::syntheticPlaintextFromEM(em, data, dst.size());

        int rv = libcdoc::Crypto::rsaImplicitRejectFromEM(dst, em, data, synth, dst.size());
        libcdoc::cleanse(em);
        libcdoc::cleanse(synth);
        return rv;
    }
    // With oaep == true CNG will apply OAEP padding and the implicit-rejection countermeasure internally,
    // so we can just call NCryptDecrypt directly with the right flags.
	BCRYPT_OAEP_PADDING_INFO padding {BCRYPT_SHA256_ALGORITHM, nullptr, 0};
	PVOID paddingInfo = oaep ? &padding : nullptr;
	DWORD flags = oaep ? NCRYPT_PAD_OAEP_FLAG : NCRYPT_PAD_PKCS1_FLAG;
	DWORD size = 0;
	SECURITY_STATUS err = NCryptDecrypt(d->key, PBYTE(data.data()), DWORD(data.size()), paddingInfo, nullptr, 0, &size, flags);
    if (err != ERROR_SUCCESS) return CRYPTO_ERROR;
	dst.resize(size);
	err = NCryptDecrypt(d->key, PBYTE(data.data()), DWORD(data.size()), paddingInfo, PBYTE(dst.data()), DWORD(dst.size()), &size, flags);
    if (err != ERROR_SUCCESS) {
        libcdoc::cleanse(dst);
        dst.clear();
        return CRYPTO_ERROR;
    }
    return OK;
}

libcdoc::result_t
libcdoc::WinBackend::deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string &digest,
								 const std::vector<uint8_t> &algorithm_id, const std::vector<uint8_t> &party_uinfo,
                                 const std::vector<uint8_t> &party_vinfo, unsigned int idx)
{
	if(!d->prov) return CRYPTO_ERROR;
    int result = connectToKey(idx, true);
    if (result != OK) return result;

	NCRYPT_PROV_HANDLE prov = 0;
	NCRYPT_KEY_HANDLE publicKeyHandle = 0;
	NCRYPT_SECRET_HANDLE sharedSecret = 0;

    result = d->derive(prov, publicKeyHandle, sharedSecret, public_key);
    if (result != OK) return result;

	std::vector<BCryptBuffer> paramValues{
		{ULONG(algorithm_id.size()), KDF_ALGORITHMID, PBYTE(algorithm_id.data())},
		{ULONG(party_uinfo.size()), KDF_PARTYUINFO, PBYTE(party_uinfo.data())},
		{ULONG(party_vinfo.size()), KDF_PARTYVINFO, PBYTE(party_vinfo.data())},
	};
	if(digest == "http://www.w3.org/2001/04/xmlenc#sha256") {
		paramValues.push_back({ULONG(sizeof(BCRYPT_SHA256_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA256_ALGORITHM)});
    } else if(digest == "http://www.w3.org/2001/04/xmlenc#sha384") {
		paramValues.push_back({ULONG(sizeof(BCRYPT_SHA384_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA384_ALGORITHM)});
    } else if(digest == "http://www.w3.org/2001/04/xmlenc#sha512") {
		paramValues.push_back({ULONG(sizeof(BCRYPT_SHA512_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA512_ALGORITHM)});
    } else {
        NCryptFreeObject(publicKeyHandle);
        NCryptFreeObject(sharedSecret);
        NCryptFreeObject(prov);
        return CRYPTO_ERROR;
    }
	BCryptBufferDesc params;
	params.ulVersion = BCRYPTBUFFER_VERSION;
	params.cBuffers = ULONG(paramValues.size());
	params.pBuffers = paramValues.data();

    result = CRYPTO_ERROR;
	DWORD size = 0;
	SECURITY_STATUS err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_SP80056A_CONCAT, &params, nullptr, 0, &size, 0);
    if (err == ERROR_SUCCESS) {
		dst.resize(int(size));
		err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_SP80056A_CONCAT, &params, PBYTE(dst.data()), size, &size, 0);
        if (err == ERROR_SUCCESS) {
		    dst.resize(32);
            result = OK;
        }
	}

	NCryptFreeObject(publicKeyHandle);
	NCryptFreeObject(sharedSecret);
	NCryptFreeObject(prov);

    return result;
}

libcdoc::result_t
libcdoc::WinBackend::deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &salt, unsigned int idx)
{
	if(!d->prov) return CRYPTO_ERROR;
    int result = connectToKey(idx, true);
    if (result != OK) return result;

	NCRYPT_PROV_HANDLE prov = 0;
	NCRYPT_KEY_HANDLE publicKeyHandle = 0;
	NCRYPT_SECRET_HANDLE sharedSecret = 0;

    result = d->derive(prov, publicKeyHandle, sharedSecret, public_key);
    if (result != OK) return result;

    result = CRYPTO_ERROR;

	std::vector<BCryptBuffer> paramValues {
		{ULONG(salt.size()), KDF_HMAC_KEY, PBYTE(salt.data())},
		{ULONG(sizeof(BCRYPT_SHA256_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA256_ALGORITHM)},
	};
	BCryptBufferDesc params{BCRYPTBUFFER_VERSION};
	params.cBuffers = ULONG(paramValues.size());
	params.pBuffers = paramValues.data();

	DWORD size = 0;
	SECURITY_STATUS err = 0;
	err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_HMAC, &params, nullptr, 0, &size, 0);
    if (err == ERROR_SUCCESS) {
		dst.resize(int(size));
		err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_HMAC, &params, PBYTE(dst.data()), size, &size, 0);
        if (err == ERROR_SUCCESS) {
		    dst.resize(CDoc2::KEY_LEN);
            result = OK;
        }
    }

	NCryptFreeObject(publicKeyHandle);
	NCryptFreeObject(sharedSecret);
	NCryptFreeObject(prov);

    return result;
}

libcdoc::result_t
libcdoc::WinBackend::sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, unsigned int idx)
{
	if(!d->prov) return CRYPTO_ERROR;
    int result = connectToKey(idx, true);
    if (result != OK) return result;

    // BCRYPT_PSS_PADDING_INFO::pszAlgId selects BOTH the PSS hash and MGF1
    // hash. It must match the hash that produced `digest`, otherwise CNG
    // either rejects the call (when the digest length disagrees with the
    // declared hash) or silently produces a signature that no verifier
    // will accept. Salt length conventionally equals the hash output size.
    //
    // Note: CNG (BCrypt/NCrypt) does not expose a SHA-224 PSS algorithm
    // identifier, so SHA-224 is rejected here rather than silently
    // forwarded with a non-standard string.
    BCRYPT_PSS_PADDING_INFO rsaPSS { BCRYPT_SHA256_ALGORITHM, 32 };
    switch(algorithm) {
        case libcdoc::CryptoBackend::HashAlgorithm::SHA_256:
            rsaPSS = { NCRYPT_SHA256_ALGORITHM, 32 }; break;
        case libcdoc::CryptoBackend::HashAlgorithm::SHA_384:
            rsaPSS = { NCRYPT_SHA384_ALGORITHM, 48 }; break;
        case libcdoc::CryptoBackend::HashAlgorithm::SHA_512:
            rsaPSS = { NCRYPT_SHA512_ALGORITHM, 64 }; break;
        case libcdoc::CryptoBackend::HashAlgorithm::SHA_224:
            // SHA-224 is not supported by CNG's RSA-PSS implementation.
            LOG_ERROR("WinBackend: RSA-PSS with SHA-224 is not supported by CNG");
            return NOT_IMPLEMENTED;
        default:
            return INVALID_PARAMS;
    }
	DWORD size;
	NCryptGetProperty(d->key, NCRYPT_ALGORITHM_GROUP_PROPERTY, nullptr, 0, &size, 0);
    std::wstring algo(5, 0);
	NCryptGetProperty(d->key, NCRYPT_ALGORITHM_GROUP_PROPERTY, PBYTE(algo.data()), DWORD((algo.size() + 1) * 2), &size, 0);
	algo.resize(size/2 - 1);
	bool isRSA = (algo == L"RSA");
	DWORD padding {};
	PVOID paddingInfo {};
	if(isRSA) {
		padding = BCRYPT_PAD_PSS;
		paddingInfo = &rsaPSS;
	}
	SECURITY_STATUS err = NCryptSignHash(d->key, paddingInfo, PBYTE(digest.data()), DWORD(digest.size()), nullptr, 0, &size, padding);
    if (err != ERROR_SUCCESS) return CRYPTO_ERROR;
	dst.resize(size);
	err = NCryptSignHash(d->key, paddingInfo, PBYTE(digest.data()), DWORD(digest.size()), PBYTE(dst.data()), DWORD(dst.size()), &size, padding);
    if (err != ERROR_SUCCESS) return CRYPTO_ERROR;
    return OK;
}
