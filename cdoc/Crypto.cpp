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

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#endif

#include "CDoc.h"
#include "Crypto.h"
#include "ILogger.h"
#include "Utils.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <cstring>

using namespace libcdoc;

const std::string Crypto::SHA256_MTH = "http://www.w3.org/2001/04/xmlenc#sha256";
const std::string Crypto::SHA384_MTH = "http://www.w3.org/2001/04/xmlenc#sha384";
const std::string Crypto::SHA512_MTH = "http://www.w3.org/2001/04/xmlenc#sha512";
const char *Crypto::AES128CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const char *Crypto::AES192CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
const char *Crypto::AES256CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const char *Crypto::AES128GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const char *Crypto::AES192GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
const char *Crypto::AES256GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const std::string Crypto::RSA_MTH = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const std::string Crypto::CONCATKDF_MTH = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
const std::string Crypto::AGREEMENT_MTH = "http://www.w3.org/2009/xmlenc11#ECDH-ES";


Crypto::Cipher::Cipher(const EVP_CIPHER *cipher, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, bool encrypt)
	: ctx(EVP_CIPHER_CTX_new())
{
	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
	EVP_CipherInit_ex(ctx, cipher, nullptr, key.data(), iv.empty() ? nullptr : iv.data(), int(encrypt));
}

Crypto::Cipher::~Cipher()
{
	EVP_CIPHER_CTX_free(ctx);
}

bool Crypto::Cipher::updateAAD(const std::vector<uint8_t> &data) const
{
	int len = 0;
    return !SSL_FAILED(EVP_CipherUpdate(ctx, nullptr, &len, data.data(), int(data.size())), "EVP_CipherUpdate");
}

bool
Crypto::Cipher::update(uint8_t *data, int size) const
{
	int len = 0;
    return !SSL_FAILED(EVP_CipherUpdate(ctx, data, &len, data, size), "EVP_CipherUpdate");
}

bool Crypto::Cipher::result() const
{
	std::vector<uint8_t> result(EVP_CIPHER_CTX_block_size(ctx), 0);
	int len = int(result.size());
    if(SSL_FAILED(EVP_CipherFinal(ctx, result.data(), &len), "EVP_CipherFinal"))
        return false;
    if(result.size() != len)
        result.resize(len);
	return true;
}

std::vector<uint8_t>
Crypto::Cipher::tag() const
{
	std::vector<uint8_t> result(tagLen(), 0);
    if (SSL_FAILED(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, int(result.size()), result.data()), "EVP_CIPHER_CTX_ctrl"))
        return {};
    return result;
}

bool Crypto::Cipher::setTag(const std::vector<uint8_t> &data) const
{
    return !SSL_FAILED(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, int(data.size()), (void *) data.data()), "EVP_CIPHER_CTX_ctrl");
}

int
Crypto::Cipher::blockSize() const
{
	return EVP_CIPHER_CTX_get_block_size(ctx);
}

std::vector<uint8_t> Crypto::AESWrap(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data, bool encrypt)
{
	AES_KEY aes;
    // fixme: Fix SSL_FAILED, current solution is idiotic
    if (encrypt && !SSL_FAILED(AES_set_encrypt_key(key.data(), int(key.size()) * 8, &aes), "AES_set_encrypt_key") ||
        !encrypt && !SSL_FAILED(AES_set_decrypt_key(key.data(), int(key.size()) * 8, &aes), "AES_set_decrypt_key"))
        return {};

	std::vector<uint8_t> result(data.size() + 8);
	int size = encrypt ?
		AES_wrap_key(&aes, nullptr, result.data(), data.data(), data.size()) :
		AES_unwrap_key(&aes, nullptr, result.data(), data.data(), data.size());
	if(size > 0)
		result.resize(size_t(size));
	else
		result.clear();
	return result;
}

const EVP_CIPHER *Crypto::cipher(const std::string &algo)
{
	if(algo == AES128CBC_MTH) return EVP_aes_128_cbc();
	if(algo == AES192CBC_MTH) return EVP_aes_192_cbc();
	if(algo == AES256CBC_MTH) return EVP_aes_256_cbc();
	if(algo == AES128GCM_MTH) return EVP_aes_128_gcm();
	if(algo == AES192GCM_MTH) return EVP_aes_192_gcm();
	if(algo == AES256GCM_MTH) return EVP_aes_256_gcm();
	return nullptr;
}

std::vector<uint8_t> Crypto::concatKDF(const std::string &hashAlg, uint32_t keyDataLen,
	const std::vector<uint8_t> &z, const std::vector<uint8_t> &otherInfo)
{
	std::vector<uint8_t> key;
	uint32_t hashLen = SHA384_DIGEST_LENGTH;
	if(hashAlg == SHA256_MTH) hashLen = SHA256_DIGEST_LENGTH;
	else if(hashAlg == SHA384_MTH) hashLen = SHA384_DIGEST_LENGTH;
	else if(hashAlg == SHA512_MTH) hashLen = SHA512_DIGEST_LENGTH;
	else return key;

	SHA256_CTX sha256;
	SHA512_CTX sha512;
    std::vector<uint8_t> hash(hashLen, 0);
    uint8_t intToFourBytes[4];

    uint32_t reps = keyDataLen / hashLen;
    if (keyDataLen % hashLen > 0)
        reps++;

	for(uint32_t i = 1; i <= reps; i++)
	{
		intToFourBytes[0] = uint8_t(i >> 24);
		intToFourBytes[1] = uint8_t(i >> 16);
		intToFourBytes[2] = uint8_t(i >> 8);
		intToFourBytes[3] = uint8_t(i >> 0);
		switch(hashLen)
		{
		case SHA256_DIGEST_LENGTH:
            if (SSL_FAILED(SHA256_Init(&sha256), "SHA256_Init") ||
                SSL_FAILED(SHA256_Update(&sha256, intToFourBytes, 4), "SHA256_Update") ||
                SSL_FAILED(SHA256_Update(&sha256, z.data(), z.size()), "SHA256_Update") ||
                SSL_FAILED(SHA256_Update(&sha256, otherInfo.data(), otherInfo.size()), "SHA256_Update") ||
                SSL_FAILED(SHA256_Final(hash.data(), &sha256), "SHA256_Final"))
                return {};
			break;
		case SHA384_DIGEST_LENGTH:
            if (SSL_FAILED(SHA384_Init(&sha512), "SHA384_Init") ||
                SSL_FAILED(SHA384_Update(&sha512, intToFourBytes, 4), "SHA384_Update") ||
                SSL_FAILED(SHA384_Update(&sha512, z.data(), z.size()), "SHA384_Update") ||
                SSL_FAILED(SHA384_Update(&sha512, otherInfo.data(), otherInfo.size()), "SHA384_Update") ||
                SSL_FAILED(SHA384_Final(hash.data(), &sha512), "SHA384_Final"))
                return {};
			break;
		case SHA512_DIGEST_LENGTH:
            if (SSL_FAILED(SHA512_Init(&sha512), "SHA512_Init") ||
                SSL_FAILED(SHA512_Update(&sha512, intToFourBytes, 4), "SHA512_Update") ||
                SSL_FAILED(SHA512_Update(&sha512, otherInfo.data(), otherInfo.size()), "SHA512_Update") ||
                SSL_FAILED(SHA512_Final(hash.data(), &sha512), "SHA512_Update"))
                return {};
			break;
        default:
            LOG_WARN("Usnupported hash length {}", hashLen);
            return key;
		}
		key.insert(key.cend(), hash.cbegin(), hash.cend());
	}
	key.resize(size_t(keyDataLen));
	return key;
}

std::vector<uint8_t> Crypto::concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uint8_t> &z,
	const std::vector<uint8_t> &AlgorithmID, const std::vector<uint8_t> &PartyUInfo, const std::vector<uint8_t> &PartyVInfo)
{
    LOG_DBG("Ksr {}", toHex(z));
    LOG_DBG("AlgorithmID {}", toHex(AlgorithmID));
    LOG_DBG("PartyUInfo {}", toHex(PartyUInfo));
    LOG_DBG("PartyVInfo {}", toHex(PartyVInfo));

	std::vector<uint8_t> otherInfo;
	otherInfo.insert(otherInfo.cend(), AlgorithmID.cbegin(), AlgorithmID.cend());
	otherInfo.insert(otherInfo.cend(), PartyUInfo.cbegin(), PartyUInfo.cend());
	otherInfo.insert(otherInfo.cend(), PartyVInfo.cbegin(), PartyVInfo.cend());
	return concatKDF(hashAlg, keyDataLen, z, otherInfo);
}

std::vector<uint8_t> Crypto::encrypt(const std::string &method, const Key &key, const std::vector<uint8_t> &data)
{
	const EVP_CIPHER *c = cipher(method);
    auto ctx = make_unique_ptr<EVP_CIPHER_CTX_free>(EVP_CIPHER_CTX_new());
    if (SSL_FAILED(EVP_CipherInit(ctx.get(), c, key.key.data(), key.iv.data(), 1), "EVP_CipherInit"))
        return {};

    std::vector<uint8_t> result(data.size() + size_t(EVP_CIPHER_CTX_block_size(ctx.get())), 0);

	std::vector<char> buf(10 * 1024, 0);
    size_t total = 0;
    int sizeIn = 0;
    if (SSL_FAILED(EVP_CipherUpdate(ctx.get(), result.data(), &sizeIn, data.data(), data.size()), "EVP_CipherUpdate"))
        return {};
    total += sizeIn;
    if (SSL_FAILED(EVP_CipherFinal(ctx.get(), result.data() + sizeIn, &sizeIn), "EVP_CipherFinal"))
        return {};
    total += sizeIn;
    result.resize(total);
	result.insert(result.cbegin(), key.iv.cbegin(), key.iv.cend());
    if(EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE) {
		std::vector<uint8_t> tag(16, 0);
        if (SSL_FAILED(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, int(tag.size()), tag.data()), "EVP_CIPHER_CTX_ctrl"))
            return {};

		result.insert(result.cend(), tag.cbegin(), tag.cend());
        LOG_DBG("GCM TAG {}", toHex(tag));
	}
	return result;
}

std::vector<uint8_t>
Crypto::encrypt(EVP_PKEY *pub, int padding, const std::vector<uint8_t> &data)
{
    auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new(pub, nullptr));
	size_t size = 0;
    if (SSL_FAILED(EVP_PKEY_encrypt_init(ctx.get()), "EVP_PKEY_encrypt_init") ||
        SSL_FAILED(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding), "EVP_PKEY_CTX_set_rsa_padding") ||
        SSL_FAILED(EVP_PKEY_encrypt(ctx.get(), nullptr, &size, data.data(), data.size()), "EVP_PKEY_encrypt"))
		return {};
	if(padding == RSA_PKCS1_OAEP_PADDING) {
        if (SSL_FAILED(EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()), "EVP_PKEY_CTX_set_rsa_oaep_md") ||
            SSL_FAILED(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()), "EVP_PKEY_CTX_set_rsa_mgf1_md"))
			return {};
	}
	std::vector<uint8_t> result(int(size), 0);
    if(SSL_FAILED(EVP_PKEY_encrypt(ctx.get(), result.data(), &size,
            data.data(), data.size()), "EVP_PKEY_encrypt"))
		return {};
	return result;
}

std::vector<uint8_t> Crypto::decrypt(const std::string &method, const std::vector<uint8_t> &key, const std::vector<uint8_t> &data)
{
	const EVP_CIPHER *cipher = Crypto::cipher(method);
	size_t dataSize = data.size();
	std::vector<uint8_t> iv(data.cbegin(), data.cbegin() + EVP_CIPHER_iv_length(cipher));
	dataSize -= iv.size();

    LOG_TRACE_KEY("iv {}", iv);
    LOG_TRACE_KEY("transport {}", key);

    auto ctx = make_unique_ptr<EVP_CIPHER_CTX_free>(EVP_CIPHER_CTX_new());
    if (!ctx)
    {
        LOG_SSL_ERROR("EVP_CIPHER_CTX_new");
        return {};
    }

    if (SSL_FAILED(EVP_CipherInit(ctx.get(), cipher, key.data(), iv.data(), 0), "EVP_CipherInit"))
    {
        return {};
    }

	if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
	{
		std::vector<uint8_t> tag(data.cend() - 16, data.cend());
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, int(tag.size()), tag.data());
		dataSize -= tag.size();
        LOG_DBG("GCM TAG {}", toHex(tag));
	}

	int size = 0;
	std::vector<uint8_t> result(dataSize + size_t(EVP_CIPHER_CTX_block_size(ctx.get())), 0);
    if (SSL_FAILED(EVP_CipherUpdate(ctx.get(), result.data(), &size, &data[iv.size()], int(dataSize)), "EVP_CipherUpdate"))
    {
        return {};
    }

	int size2 = 0;
    if (SSL_FAILED(EVP_CipherFinal(ctx.get(), result.data() + size, &size2), "EVP_CipherFinal"))
    {
        return {};
    }
	result.resize(size_t(size + size2));
	return result;
}

std::vector<uint8_t> Crypto::decodeBase64(const uint8_t *data)
{
	std::vector<uint8_t> result;
	if (!data)
    {
        LOG_ERROR("decodeBase64: null pointer was provided as input data");
		return result;
    }
	result.resize(strlen((const char*)data));
    auto ctx = make_unique_ptr<EVP_ENCODE_CTX_free>(EVP_ENCODE_CTX_new());
    if (!ctx)
    {
        LOG_SSL_ERROR("EVP_ENCODE_CTX_new");
        return {};
    }

	EVP_DecodeInit(ctx.get());
	int size1 = 0, size2 = 0;
	if(EVP_DecodeUpdate(ctx.get(), result.data(), &size1, data, int(result.size())) == -1)
	{
        LOG_SSL_ERROR("EVP_DecodeUpdate");
		result.clear();
		return result;
	}

    if(SSL_FAILED(EVP_DecodeFinal(ctx.get(), result.data(), &size2), "EVP_DecodeFinal"))
        result.clear();
	else
        result.resize(size_t(size1 + size2));

	return result;
}

std::vector<uint8_t> Crypto::deriveSharedSecret(EVP_PKEY *pkey, EVP_PKEY *peerPKey)
{
	std::vector<uint8_t> sharedSecret;
	size_t sharedSecretLen = 0;
    auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new(pkey, nullptr));
    if (!ctx)
    {
        LOG_SSL_ERROR("EVP_PKEY_CTX_new");
        return sharedSecret;
    }
    if (SSL_FAILED(EVP_PKEY_derive_init(ctx.get()), "EVP_PKEY_derive_init") ||
        SSL_FAILED(EVP_PKEY_derive_set_peer(ctx.get(), peerPKey), "EVP_PKEY_derive_set_peer") ||
        SSL_FAILED(EVP_PKEY_derive(ctx.get(), nullptr, &sharedSecretLen), "EVP_PKEY_derive"))
		return sharedSecret;

	sharedSecret.resize(sharedSecretLen);
	if(EVP_PKEY_derive(ctx.get(), sharedSecret.data(), &sharedSecretLen) <= 0)
		sharedSecret.clear();
	return sharedSecret;
}

Crypto::Key Crypto::generateKey(const std::string &method)
{
	const EVP_CIPHER *c = cipher(method);
#ifdef WIN32
	RAND_screen();
#else
	RAND_load_file("/dev/urandom", 1024);
#endif
    Key key(EVP_CIPHER_key_length(c), EVP_CIPHER_iv_length(c));
	uint8_t salt[PKCS5_SALT_LEN], indata[128];
	RAND_bytes(salt, sizeof(salt));
	RAND_bytes(indata, sizeof(indata));
    if (SSL_FAILED(EVP_BytesToKey(c, EVP_sha256(), salt, indata, sizeof(indata), 1, key.key.data(), key.iv.data()), "EVP_BytesToKey"))
        return {};
    else
        return key;
}

uint32_t Crypto::keySize(const std::string &algo)
{
	if(algo == KWAES128_MTH) return 16;
	if(algo == KWAES192_MTH) return 24;
	if(algo == KWAES256_MTH) return 32;
	return 0;
}

std::vector<uint8_t>
Crypto::hkdf(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, const std::vector<uint8_t> &info, int len, int mode)
{
    auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx)
    {
        LOG_SSL_ERROR("EVP_PKEY_CTX_new_id");
        return {};
    }
	std::vector<uint8_t> out(len, 0);
    size_t outlen = out.size();
	if(!ctx ||
        SSL_FAILED(EVP_PKEY_derive_init(ctx.get()), "EVP_PKEY_derive_init") ||
        SSL_FAILED(EVP_PKEY_CTX_hkdf_mode(ctx.get(), mode), "EVP_PKEY_CTX_hkdf_mode") ||
        SSL_FAILED(EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()), "EVP_PKEY_CTX_set_hkdf_md") ||
        SSL_FAILED(EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), key.data(), int(key.size())), "EVP_PKEY_CTX_set1_hkdf_key") ||
        SSL_FAILED(EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), int(salt.size())), "EVP_PKEY_CTX_set1_hkdf_salt") ||
        SSL_FAILED(EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), int(info.size())), "EVP_PKEY_CTX_add1_hkdf_info") ||
        SSL_FAILED(EVP_PKEY_derive(ctx.get(), out.data(), &outlen), "EVP_PKEY_derive"))
		return {};

	return out;
}

std::vector<uint8_t>
Crypto::expand(const std::vector<uint8_t> &key, const std::vector<uint8_t> &info, int len)
{
	return hkdf(key, {}, info, len, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
}

std::vector<uint8_t>
Crypto::extract(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, int len)
{
	return hkdf(key, salt, {}, len, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
}

std::vector<uint8_t>
Crypto::sign_hmac(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> sig;
    auto pkey = make_unique_ptr<EVP_PKEY_free>(EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, key.data(), int(key.size())));
    if (!pkey)
    {
        LOG_SSL_ERROR("EVP_PKEY_new_mac_key");
        return sig;
    }

    auto ctx = make_unique_ptr<EVP_MD_CTX_free>(EVP_MD_CTX_new());
    if (!ctx)
    {
        LOG_SSL_ERROR("EVP_MD_CTX_new");
        return sig;
    }

	size_t req = 0;
    if (SSL_FAILED(EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()), "EVP_DigestSignInit") ||
        SSL_FAILED(EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()), "EVP_DigestSignUpdate") ||
        SSL_FAILED(EVP_DigestSignFinal(ctx.get(), nullptr, &req), "EVP_DigestSignFinal"))
		return sig;

    sig.resize(req);
    if(SSL_FAILED(EVP_DigestSignFinal(ctx.get(), sig.data(), &req), "EVP_DigestSignFinal"))
		sig.clear();
	return sig;
}

std::vector<uint8_t>
Crypto::pbkdf2_sha256(const std::vector<uint8_t>& pw, const std::vector<uint8_t>& salt, uint32_t iter)
{
	std::vector<uint8_t> key(32, 0);
    if(SSL_FAILED(PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(pw.data()), pw.size(),
                                    (const unsigned char *) salt.data(), int(salt.size()),
                                    iter, EVP_sha256(), int(key.size()), (unsigned char *)key.data()), "PKCS5_PBKDF2_HMAC"))
        key.clear();
	return key;
}

Crypto::EVP_PKEY_ptr
Crypto::fromRSAPublicKeyDer(const std::vector<uint8_t> &der)
{
	const uint8_t *p = der.data();
	EVP_PKEY *key = d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, long(der.size()));
    if (!key)
        LOG_SSL_ERROR("d2i_PublicKey");

    return EVP_PKEY_ptr(key, EVP_PKEY_free);
}

Crypto::EVP_PKEY_ptr
Crypto::fromECPublicKeyDer(const std::vector<uint8_t> &der, int curveName)
{
	EVP_PKEY *params = nullptr;
    auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx)
        LOG_SSL_ERROR("EVP_PKEY_CTX_new_id");

    if(!ctx ||
        SSL_FAILED(EVP_PKEY_paramgen_init(ctx.get()), "EVP_PKEY_paramgen_init") ||
        SSL_FAILED(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), curveName), "EVP_PKEY_CTX_set_ec_paramgen_curve_nid") ||
        SSL_FAILED(EVP_PKEY_CTX_set_ec_param_enc(ctx.get(), OPENSSL_EC_NAMED_CURVE), "EVP_PKEY_CTX_set_ec_param_enc") ||
        SSL_FAILED(EVP_PKEY_paramgen(ctx.get(), &params), "EVP_PKEY_paramgen"))
		return std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>(nullptr, EVP_PKEY_free);

	const uint8_t *p = der.data();
	EVP_PKEY *key = d2i_PublicKey(EVP_PKEY_EC, &params, &p, long(der.size()));
    if (!key)
        LOG_SSL_ERROR("d2i_PublicKey");

    return EVP_PKEY_ptr(key, EVP_PKEY_free);
}

Crypto::EVP_PKEY_ptr
Crypto::fromECPublicKeyDer(const std::vector<uint8_t> &der)
{
    const uint8_t *p = der.data();
    EVP_PKEY *key = d2i_PUBKEY(nullptr, &p, (long) der.size());
    if (!key)
        LOG_SSL_ERROR("d2i_PUBKEY");

    return EVP_PKEY_ptr(key, EVP_PKEY_free);
}

Crypto::EVP_PKEY_ptr
Crypto::genECKey(EVP_PKEY *params)
{
	EVP_PKEY *key = nullptr;
    auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new(params, nullptr));
    if(ctx && !SSL_FAILED(EVP_PKEY_keygen_init(ctx.get()), "EVP_PKEY_keygen_init"))
        SSL_FAILED(EVP_PKEY_keygen(ctx.get(), &key), "EVP_PKEY_keygen");
    return EVP_PKEY_ptr(key, EVP_PKEY_free);
}

std::vector<uint8_t>
Crypto::toPublicKeyDer(EVP_PKEY *key)
{
	if(!key) return {};
	std::vector<uint8_t> der(i2d_PublicKey(key, nullptr), 0);
    if(auto *p = der.data(); i2d_PublicKey(key, &p) != der.size())
    {
        LOG_SSL_ERROR("i2d_PublicKey");
        der.clear();
    }
	return der;
}

std::vector<uint8_t>
Crypto::random(uint32_t len)
{
	std::vector<uint8_t> out(len, 0);
    if(SSL_FAILED(RAND_bytes(out.data(), len), "RAND_bytes"))
		out.clear();
	return out;
}

int
Crypto::xor_data(std::vector<uint8_t>& dst, const std::vector<uint8_t> &lhs, const std::vector<uint8_t> &rhs)
{
    if(lhs.size() != rhs.size())
    {
        LOG_ERROR("xor_data: left-side and right-side vector's length differ. Left-side length: {}, right-side length: {}", lhs.size(), rhs.size());
        return CRYPTO_ERROR;
    }

	dst.resize(lhs.size());
    for(size_t i = 0; i < lhs.size(); ++i)
        dst[i] = lhs[i] ^ rhs[i];
    return OK;
}

unique_free_t<X509> Crypto::toX509(const std::vector<uint8_t> &data)
{
	const uint8_t *p = data.data();
    auto x509 = make_unique_ptr(d2i_X509(nullptr, &p, int(data.size())), X509_free);
    if (!x509)
    {
        LOG_SSL_ERROR("d2i_X509");
    }
    return x509;
}

void Crypto::LogSslError(const char* funcName, const char* file, int line)
{
    constexpr size_t errorStrBufLen = 256;
    char sslErrorStr[errorStrBufLen + 1]{};

    unsigned long errorCode = ERR_get_error();
    while (errorCode != 0)
    {
        ERR_error_string_n(errorCode, sslErrorStr, errorStrBufLen);
        get_logger()->LogMessage(LogLevelError, file, line, FORMAT("{} failed: {}", funcName, sslErrorStr));

        // Get next error code
        errorCode = ERR_get_error();
    }
}
