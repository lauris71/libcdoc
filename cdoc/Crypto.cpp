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

#include "CDoc.h"
#include "Crypto.h"
#include "Utils.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#ifdef _WIN32
#include <windows.h> // For RAND_screen
#endif

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <array>
#include <cstring>

using namespace libcdoc;

const std::string Crypto::SHA256_MTH = "http://www.w3.org/2001/04/xmlenc#sha256";
const std::string Crypto::SHA384_MTH = "http://www.w3.org/2001/04/xmlenc#sha384";
const std::string Crypto::SHA512_MTH = "http://www.w3.org/2001/04/xmlenc#sha512";
const std::string Crypto::RSA_MTH = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const std::string Crypto::CONCATKDF_MTH = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
const std::string Crypto::AGREEMENT_MTH = "http://www.w3.org/2009/xmlenc11#ECDH-ES";

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
    const EVP_MD *md {};
    if(hashAlg == SHA256_MTH) md = EVP_sha256();
    else if(hashAlg == SHA384_MTH) md = EVP_sha384();
    else if(hashAlg == SHA512_MTH) md = EVP_sha512();
    else {
        LOG_WARN("Usnupported hash algo {}", hashAlg);
        return key;
    }

    uint32_t hashLen = EVP_MD_get_size(md);
    uint32_t reps = keyDataLen / hashLen;
    if (keyDataLen % hashLen > 0)
        reps++;

    auto ctx = make_unique_ptr<EVP_MD_CTX_free>(EVP_MD_CTX_new());
    if(!ctx)
    {
        LOG_SSL_ERROR("EVP_MD_CTX_new");
        return key;
    }

    std::vector<uint8_t> hash(hashLen, 0);
    for(uint32_t i = 1; i <= reps; i++)
    {
        uint8_t intToFourBytes[4] { uint8_t(i >> 24), uint8_t(i >> 16), uint8_t(i >> 8), uint8_t(i >> 0) };
        unsigned int size = hashLen;
        if (SSL_FAILED(EVP_DigestInit(ctx.get(), md), "EVP_DigestInit") ||
            SSL_FAILED(EVP_DigestUpdate(ctx.get(), intToFourBytes, 4), "EVP_DigestUpdate") ||
            SSL_FAILED(EVP_DigestUpdate(ctx.get(), z.data(), z.size()), "EVP_DigestUpdate") ||
            SSL_FAILED(EVP_DigestUpdate(ctx.get(), otherInfo.data(), otherInfo.size()), "EVP_DigestUpdate") ||
            SSL_FAILED(EVP_DigestFinal(ctx.get(), hash.data(), &size), "EVP_DigestFinal"))
            return {};
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
Crypto::hkdf(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, std::string_view info, int len, int mode)
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
        (!salt.empty() && SSL_FAILED(EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), int(salt.size())), "EVP_PKEY_CTX_set1_hkdf_salt")) ||
        (!info.empty() && SSL_FAILED(EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), (uint8_t*)info.data(), int(info.size())), "EVP_PKEY_CTX_add1_hkdf_info")) ||
        SSL_FAILED(EVP_PKEY_derive(ctx.get(), out.data(), &outlen), "EVP_PKEY_derive"))
		return {};

	return out;
}

std::vector<uint8_t>
Crypto::expand(const std::vector<uint8_t> &key, std::string_view info, int len)
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
    if(auto key = d2i<d2i_PublicKey,EVP_PKEY_free>(der, EVP_PKEY_RSA, nullptr))
        return key;
    auto key = d2i<d2i_PUBKEY,EVP_PKEY_free>(der, nullptr);
    if(!key)
        LOG_SSL_ERROR("d2i_PublicKey");
    return key;
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
		return {nullptr, EVP_PKEY_free};

    auto key = d2i<d2i_PublicKey,EVP_PKEY_free>(der, EVP_PKEY_EC, &params);
    if (!key)
        LOG_SSL_ERROR("d2i_PublicKey");
    return key;
}

Crypto::EVP_PKEY_ptr
Crypto::fromECPublicKeyDer(const std::vector<uint8_t> &der)
{
    auto key = d2i<d2i_PUBKEY, EVP_PKEY_free>(der, nullptr);
    if(!key)
        LOG_SSL_ERROR("d2i_PUBKEY");
    return key;
}

Crypto::EVP_PKEY_ptr
Crypto::genECKey(EVP_PKEY *params)
{
	EVP_PKEY *key = nullptr;
    if(auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new(params, nullptr));
        !ctx ||
        SSL_FAILED(EVP_PKEY_keygen_init(ctx.get()), "EVP_PKEY_keygen_init") ||
        SSL_FAILED(EVP_PKEY_keygen(ctx.get(), &key), "EVP_PKEY_keygen"))
        return {nullptr, EVP_PKEY_free};
    return {key, EVP_PKEY_free};
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

void Crypto::LogSslError(const char* funcName, const char* file, int line)
{
    constexpr size_t errorStrBufLen = 256;
    char sslErrorStr[errorStrBufLen + 1]{};

    unsigned long errorCode = ERR_get_error();
    while (errorCode != 0)
    {
        ERR_error_string_n(errorCode, sslErrorStr, errorStrBufLen);
        LOG_ERROR("{} failed: {}", funcName, sslErrorStr);

        // Get next error code
        errorCode = ERR_get_error();
    }
}

EncryptionConsumer::EncryptionConsumer(DataConsumer &dst, const std::string &method, const Crypto::Key &key)
    : EncryptionConsumer(dst, Crypto::cipher(method), key)
{}

EncryptionConsumer::EncryptionConsumer(DataConsumer &dst, const EVP_CIPHER *cipher, const Crypto::Key &key)
    : ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free}
    , dst(dst)
{
    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if(SSL_FAILED(EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key.key.data(), key.iv.data(), 1), "EVP_CipherInit_ex"))
        error = CRYPTO_ERROR;
    if(auto rv = dst.write(key.iv); rv != key.iv.size())
        error = rv;
}

result_t
EncryptionConsumer::write(const uint8_t *src, size_t size) noexcept try
{
    if(!src || size == 0)
        return OK;
    if(error != OK)
        return error;
    buf.resize(std::max<size_t>(buf.size(), size + EVP_CIPHER_CTX_block_size(ctx.get()) - 1));
    int len = int(buf.size());
    if(SSL_FAILED(EVP_CipherUpdate(ctx.get(), buf.data(), &len, src, int(size)), "EVP_CipherUpdate"))
        return CRYPTO_ERROR;
    return dst.write(buf.data(), size_t(len));
} catch(...) {
    return OUTPUT_STREAM_ERROR;
}

result_t
EncryptionConsumer::writeAAD(const std::vector<uint8_t> &data) noexcept
{
    int len = 0;
    if(SSL_FAILED(EVP_CipherUpdate(ctx.get(), nullptr, &len, data.data(), int(data.size())), "EVP_CipherUpdate"))
        return CRYPTO_ERROR;
    return OK;
}

result_t
EncryptionConsumer::close() noexcept try
{
    buf.resize(std::max<size_t>(buf.size(), size_t(EVP_CIPHER_CTX_block_size(ctx.get()))));
    int len = int(buf.size());
    if(SSL_FAILED(EVP_CipherFinal(ctx.get(), buf.data(), &len), "EVP_CipherFinal"))
        return CRYPTO_ERROR;
    if(auto rv = dst.write(buf.data(), size_t(len)); rv < 0)
        return rv;
    std::array<uint8_t, 16> tag {};
    if(EVP_CIPHER_CTX_mode(ctx.get()) == EVP_CIPH_GCM_MODE)
    {
        if(SSL_FAILED(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, int(tag.size()), tag.data()), "EVP_CIPHER_CTX_ctrl"))
            return CRYPTO_ERROR;
        LOG_DBG("tag: {}", toHex(tag));
        if (dst.write(tag.data(), tag.size()) != tag.size())
            return IO_ERROR;
    }
    else if(EVP_CIPHER_CTX_flags(ctx.get()) & EVP_CIPH_FLAG_AEAD_CIPHER)
    {
        if(SSL_FAILED(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, int(tag.size()), tag.data()), "EVP_CIPHER_CTX_ctrl"))
            return CRYPTO_ERROR;
        LOG_DBG("tag: {}", toHex(tag));
        if (dst.write(tag.data(), tag.size()) != tag.size())
            return IO_ERROR;
    }
    return OK;
} catch(...) {
    return OUTPUT_STREAM_ERROR;
}

DecryptionSource::DecryptionSource(DataSource &src, const std::string &method, const std::vector<unsigned char> &key, size_t ivLen)
    : DecryptionSource(src, Crypto::cipher(method), key, ivLen)
{}

DecryptionSource::DecryptionSource(DataSource &src, const EVP_CIPHER *cipher, const std::vector<unsigned char> &key, size_t ivLen)
    : ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free}
    , src(src)
{
    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (ivLen == 0)
        ivLen = EVP_CIPHER_iv_length(cipher);
    std::array<uint8_t, EVP_MAX_IV_LENGTH> iv {};
    if(auto rv = src.read(iv.data(), ivLen); size_t(rv) != ivLen)
        error = rv < 0 ? rv : IO_ERROR;
    else if(SSL_FAILED(EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data(), 0), "EVP_CipherInit_ex"))
        error = CRYPTO_ERROR;
    else if(rv = src.read(tag.data(), tag.size()); size_t(rv) != tag.size())
        error = rv < 0 ? rv : IO_ERROR;
    LOG_TRACE_KEY("IV: {}", iv);
}

result_t DecryptionSource::updateAAD(const std::vector<uint8_t> &data)
{
    if (error != OK)
        return error;
    int len = 0;
    if(SSL_FAILED(EVP_CipherUpdate(ctx.get(), nullptr, &len, data.data(), int(data.size())), "EVP_CipherUpdate"))
        return CRYPTO_ERROR;
    return OK;
}

result_t DecryptionSource::read(unsigned char *dst, size_t size) noexcept
{
    if (error != OK)
        return error;
    if (!dst || size == 0)
        return OK;
    if(size <= tag.size())
    {
        decltype(tag) tmp;
        auto rv = src.read(tmp.data(), size);
        if (rv <= 0) {
            return rv;
        }
        size = static_cast<size_t>(rv);

        // Construct new tag value
        std::move_backward(tmp.begin(), tmp.begin() + size, tmp.end()); // Move existing tag data to the end of tmp
        std::copy(tag.begin() + size, tag.end(), tmp.begin()); // Fill the beginning of tmp with remaining tag data

        // Copy data to dst and update tag
        std::copy_n(tag.begin(), size, dst);
        tag = tmp;

        if (int out = 0;
            SSL_FAILED(EVP_CipherUpdate(ctx.get(), dst, &out, dst, size), "EVP_CipherUpdate") ||
            size != out) {
            return error = CRYPTO_ERROR;
        }
        return size;
    }

    auto rv = src.read(dst + tag.size(), size - tag.size());
    if (rv <= 0) {
        return rv;
    }
    auto nread = static_cast<size_t>(rv);

    // Prepend tag data to the beginning of dst
    std::copy(tag.begin(), tag.end(), dst);

    // Handle case where less data was read than requested
    if (nread < size - tag.size()) {
        // Copy tag data from the end of dst to the tag and adjust size
        std::copy_n(std::next(dst, nread), tag.size(), tag.begin());
        size = nread;
    } else if (rv = src.read(tag.data(), tag.size()); rv < 0) {
        return rv;
    } else if (auto tagSize = static_cast<size_t>(rv); tagSize < tag.size()) {
        // Handle case where less tag data was read than expected
        // Move read tag data to the end of tag and fill the beginning with data from dst
        std::move_backward(tag.begin(), tag.begin() + tagSize, tag.end());
        size_t more = tag.size() - tagSize;
        std::copy_n(std::next(dst, size - more), more, tag.data());
        size -= more;
    }

    if (int out = 0;
        SSL_FAILED(EVP_CipherUpdate(ctx.get(), dst, &out, dst, size), "EVP_CipherUpdate") ||
        size != out) {
        return error = CRYPTO_ERROR;
    }
    return size;
}

result_t DecryptionSource::close()
{
    if (error != OK)
        return error;

    if (EVP_CIPHER_CTX_mode(ctx.get()) == EVP_CIPH_GCM_MODE) {
        LOG_DBG("tag: {}", toHex(tag));
        if (SSL_FAILED(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, int(tag.size()), tag.data()), "EVP_CIPHER_CTX_ctrl")) {
            return error = CRYPTO_ERROR;
        }
    }
    else if(EVP_CIPHER_CTX_flags(ctx.get()) & EVP_CIPH_FLAG_AEAD_CIPHER)
    {
        LOG_DBG("tag: {}", toHex(tag));
        if (SSL_FAILED(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, int(tag.size()), tag.data()), "EVP_CIPHER_CTX_ctrl")) {
            return error = CRYPTO_ERROR;
        }
    }

    int len = 0;
    std::vector<uint8_t> buffer(EVP_CIPHER_CTX_block_size(ctx.get()), 0);
    if (SSL_FAILED(EVP_CipherFinal_ex(ctx.get(), buffer.data(), &len), "EVP_CipherFinal_ex"))
        return error = HASH_MISMATCH;
    return OK;
}
