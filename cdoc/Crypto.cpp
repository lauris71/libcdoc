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
#include "utils/ct.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#ifdef _WIN32
#include <windows.h> // For RAND_screen
#endif

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

#include <array>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

using namespace libcdoc;

const std::string Crypto::SHA256_MTH = "http://www.w3.org/2001/04/xmlenc#sha256";
const std::string Crypto::SHA384_MTH = "http://www.w3.org/2001/04/xmlenc#sha384";
const std::string Crypto::SHA512_MTH = "http://www.w3.org/2001/04/xmlenc#sha512";
const std::string Crypto::RSA_MTH = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const std::string Crypto::CONCATKDF_MTH = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
const std::string Crypto::AGREEMENT_MTH = "http://www.w3.org/2009/xmlenc11#ECDH-ES";

std::vector<uint8_t> Crypto::AESWrap(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data, bool encrypt)
{
    // Note: AES_set_{encrypt,decrypt}_key return 0 on success and a negative
    // value on failure - the opposite convention from OpenSSL's EVP_* APIs that
    // SSL_FAILED is designed for. Check the return value directly.
    AES_KEY aes;
    const int key_bits = int(key.size()) * 8;
    const int key_init_rv = encrypt
        ? AES_set_encrypt_key(key.data(), key_bits, &aes)
        : AES_set_decrypt_key(key.data(), key_bits, &aes);
    if (key_init_rv != 0) {
        LOG_SSL_ERROR(encrypt ? "AES_set_encrypt_key" : "AES_set_decrypt_key");
        return {};
    }

    std::vector<uint8_t> result(data.size() + 8);
    const int size = encrypt
        ? AES_wrap_key(&aes, nullptr, result.data(), data.data(), data.size())
        : AES_unwrap_key(&aes, nullptr, result.data(), data.data(), data.size());
    if (size <= 0) {
        result.clear();
        return result;
    }
    result.resize(size_t(size));
    return result;
}

const EVP_CIPHER *Crypto::cipher(const std::string &algo)
{
	// AES-CBC was only used by CDoc 1.0; all CDoc 1.0 containers have
	// expired and we no longer accept it. It is intentionally absent here
	// so that unknown-method errors surface early at the CDoc1 reader.
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
    LOG_TRACE_KEY("Ksr {}", z);
    LOG_TRACE_KEY("AlgorithmID {}", AlgorithmID);
    LOG_TRACE_KEY("PartyUInfo {}", PartyUInfo);
    LOG_TRACE_KEY("PartyVInfo {}", PartyVInfo);

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
        SSL_FAILED(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding), "EVP_PKEY_CTX_set_rsa_padding"))
		return {};
	if(padding == RSA_PKCS1_OAEP_PADDING) {
        if (SSL_FAILED(EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()), "EVP_PKEY_CTX_set_rsa_oaep_md") ||
            SSL_FAILED(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()), "EVP_PKEY_CTX_set_rsa_mgf1_md"))
			return {};
	}
    if (SSL_FAILED(EVP_PKEY_encrypt(ctx.get(), nullptr, &size, data.data(), data.size()), "EVP_PKEY_encrypt"))
		return {};
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

    // N13: EVP_DecodeFinal must write at result.data() + size1, not
    // result.data(). For clean input OpenSSL consumes everything in
    // DecodeUpdate (size2 == 0), but embedded whitespace/line breaks
    // can leave work for DecodeFinal; writing at offset 0 would
    // silently overwrite the first size2 bytes.
    if(SSL_FAILED(EVP_DecodeFinal(ctx.get(), result.data() + size1, &size2), "EVP_DecodeFinal"))
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
	if(EVP_PKEY_derive(ctx.get(), sharedSecret.data(), &sharedSecretLen) <= 0) {
		sharedSecret.clear();
		return sharedSecret;
	}
	sharedSecret.resize(sharedSecretLen);
	return sharedSecret;
}

Crypto::Key Crypto::generateKey(const std::string &method)
{
	const EVP_CIPHER *c = cipher(method);
    if (!c) {
        LOG_ERROR("generateKey: unsupported cipher method {}", method);
        return {};
    }
    Key key(EVP_CIPHER_key_length(c), EVP_CIPHER_iv_length(c));
    if (RAND_status() != 1) {
        LOG_ERROR("generateKey: OpenSSL PRNG not seeded");
        return {};
    }
    if (SSL_FAILED(RAND_bytes(key.key.data(), int(key.key.size())), "RAND_bytes") ||
        SSL_FAILED(RAND_bytes(key.iv.data(), int(key.iv.size())), "RAND_bytes"))
        return {};
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
Crypto::fromPublicKeyDer(const std::vector<uint8_t> &der)
{
    if (auto key = d2i<d2i_PUBKEY,EVP_PKEY_free>(der, nullptr))
        return key;
    auto key = d2i<d2i_PublicKey,EVP_PKEY_free>(der, EVP_PKEY_RSA, nullptr);
    if(!key)
        LOG_SSL_ERROR("d2i_PublicKey");
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
Crypto::toPublicKeyDerLong(EVP_PKEY *key)
{
	if(!key) return {};
	std::vector<uint8_t> der(i2d_PUBKEY(key, nullptr), 0);
    if(auto *p = der.data(); i2d_PUBKEY(key, &p) != der.size())
    {
        LOG_SSL_ERROR("i2d_PUBKEY");
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

namespace {

// Per-key last-failure timestamp. Process-wide. The mutex protects a
// small map keyed by the recipient's public-key hash; lock contention is
// negligible because throttle invocations only happen on the failed-decrypt
// path which is already an attacker-budget-limited code path.
std::mutex g_throttle_mutex;
std::unordered_map<std::string, std::chrono::steady_clock::time_point> g_throttle_failures;

constexpr std::chrono::milliseconds kMinFailureInterval{1000};

} // anonymous namespace

void Crypto::rsaOracleThrottle(const std::string& key_id)
{
    const auto now = std::chrono::steady_clock::now();
    std::chrono::milliseconds delay{0};
    {
        std::lock_guard<std::mutex> lk(g_throttle_mutex);
        // Erase entries older than the minimum interval to bound map growth.
        for (auto it = g_throttle_failures.begin(); it != g_throttle_failures.end(); ) {
            if (now - it->second >= kMinFailureInterval) {
                it = g_throttle_failures.erase(it);
            } else {
                ++it;
            }
        }
        auto [entry, inserted] = g_throttle_failures.try_emplace(key_id, now);
        if (!inserted) {
            const auto elapsed = now - entry->second;
            if (elapsed < kMinFailureInterval) {
                delay = std::chrono::duration_cast<std::chrono::milliseconds>(kMinFailureInterval - elapsed);
            }
            entry->second = now;
        }
    }
    // Sleep outside the mutex to avoid holding the lock during the delay.
    if (delay.count() > 0) {
        LOG_WARN("RSA decrypt failure (key={}); throttling for {} ms",
                 key_id, delay.count());
        std::this_thread::sleep_for(delay);
    }
}

namespace {

// Derive a per-(privkey, ciphertext) deterministic byte string used as the
// "synthetic plaintext" when PKCS#1 v1.5 unpadding fails. We follow the
// recipe in RFC 8017 section 7.2.2 and OpenSSL 3.2's implicit-rejection
// implementation: HMAC-SHA-256(privkey_seed, ciphertext) seeded into HKDF
// expand. The output is deterministic-of-(key, ct) so repeating the same
// query yields the same synthetic output (this is what defeats the
// distinguisher); but unpredictable to an attacker who does not know the
// private key.
std::vector<uint8_t> syntheticPlaintext(EVP_PKEY *priv,
                                        const std::vector<uint8_t> &ct,
                                        size_t out_len)
{
    if (!priv || out_len == 0) return std::vector<uint8_t>(out_len, 0);

    // Use the private key's PKCS#8 DER as the HMAC key. It is private to the
    // decryption process and stable across calls.
    int der_len = i2d_PrivateKey(priv, nullptr);
    if (der_len <= 0)
        return std::vector<uint8_t>(out_len, 0);
    std::vector<uint8_t> mac_key(size_t(der_len), 0);
    {
        unsigned char *p = mac_key.data();
        if (i2d_PrivateKey(priv, &p) != der_len) {
            libcdoc::cleanse(mac_key);
            return std::vector<uint8_t>(out_len, 0);
        }
    }

    std::vector<uint8_t> prk = Crypto::sign_hmac(mac_key, ct);
    libcdoc::cleanse(mac_key);
    if (prk.empty())
        return std::vector<uint8_t>(out_len, 0);

    auto out = Crypto::expand(prk, "cdoc1-rsa-implicit-reject", int(out_len));
    libcdoc::cleanse(prk);
    if (out.size() != out_len) {
        libcdoc::cleanse(out);
        return std::vector<uint8_t>(out_len, 0);
    }
    return out;
}

// Constant-time PKCS#1 v1.5 unpadding. Walks the entire EM block in a
// data-independent fashion regardless of where (or whether) the 0x00
// separator is found, the value of the leading bytes, or the eventual
// message length. Produces a single byte mask `good` (0xFF on valid
// padding, 0x00 otherwise) and a copy of either the recovered message
// or the synthetic plaintext into `dst`. dst is always exactly
// expected_len bytes long.
void unpadPKCS1v15CT(const std::vector<uint8_t> &em,
                     const std::vector<uint8_t> &synth,
                     size_t expected_len,
                     std::vector<uint8_t> &dst)
{
    using namespace libcdoc::ct;

    dst.assign(expected_len, 0);

    // Need at least 0x00 || 0x02 || PS(>=8) || 0x00 || M
    // -> EM length must be >= 11 + expected_len.
    if (em.size() < 11u + expected_len) {
        // Caller-side guarantees this in normal use because the modulus is
        // always larger than expected_len. Still, fall back to synthetic
        // output rather than reading out-of-bounds.
        for (size_t i = 0; i < expected_len; ++i)
            dst[i] = synth[i];
        return;
    }

    // Initial header check.
    uint8_t good = 0xFF;
    good &= eq8(em[0], 0x00);
    good &= eq8(em[1], 0x02);

    // Find the index of the first 0x00 byte at index >= 2.
    // We must walk every byte of EM regardless of where the byte happens
    // to be, otherwise a timing channel leaks the position of the first
    // 0x00 (the classic "Manger / Bardou" oracle).
    size_t first_zero_idx = 0;
    uint8_t found_zero = 0x00;
    for (size_t i = 2; i < em.size(); ++i) {
        uint8_t is_zero = eq8(em[i], 0x00);
        // latch the first index at which is_zero is set
        uint8_t latch = uint8_t(is_zero & ~found_zero);
        // "if latch then first_zero_idx = i". We can't branch; do it
        // arithmetically. N25: the ternary form below may compile to a
        // secret-dependent branch; use pure arithmetic instead.
        // latch is 0x00 or 0xFF, so latch & 1 is 0 or 1, and
        // size_t(0) - 0 = 0 (all zeros), size_t(0) - 1 = ~0 (all ones).
        const size_t mask_size = size_t(0) - size_t(latch & 1);
        first_zero_idx = (i & mask_size) | (first_zero_idx & ~mask_size);
        found_zero = uint8_t(found_zero | is_zero);
    }
    good &= found_zero;

    // PS must be at least 8 bytes -> first 0x00 index >= 10.
    good &= ge_size(first_zero_idx, 10);

    // Message starts after the separator and runs to the end of EM.
    // (We don't need ge here because if found_zero is 0xFF then
    // first_zero_idx <= em.size()-1.)
    size_t msg_off = first_zero_idx + 1;
    size_t msg_len = (msg_off <= em.size()) ? (em.size() - msg_off) : 0;

    // Check that the message length matches what the caller expects.
    good &= eq32(uint32_t(msg_len), uint32_t(expected_len));

    // Constant-time copy: walk every possible message offset, and for
    // each output position i select em[msg_off + i] if it is in range,
    // otherwise 0. We then conditionally mux it against the synthetic
    // plaintext using `good`.
    //
    // Important: the inner read em[src_idx] must not depend on `good` in
    // a way that the compiler could turn into a conditional load. We
    // therefore always perform the read and clamp src_idx to a valid
    // range (em.size() - 1). When good==0 we discard the value.
    for (size_t i = 0; i < expected_len; ++i) {
        size_t src_idx = msg_off + i;
        // Clamp: if src_idx >= em.size() use em[em.size()-1] (always in
        // range since em.size() >= 11+expected_len > 0). The clamped value
        // is replaced by synth[i] below when good == 0, so the actual
        // bytes read here never reach the caller.
        // ge_size() returns a single-byte mask (0x00 or 0xFF). It must be
        // widened to a full-width size_t mask before splicing indices;
        // using the byte mask directly would mix the low byte of src_idx
        // with the high bits of (em.size() - 1) and index past the end of
        // em for modulus lengths that are not a multiple of 256 bytes
        // (e.g. 384-byte EM of a 3072-bit RSA key). The widening is
        // branch-free arithmetic: 0x00 -> 0, 0xFF -> ~size_t(0).
        size_t in_range = size_t(ge_size(em.size() - 1, src_idx));   // 0x00 or 0xFF
        size_t mask = size_t(0) - (in_range & size_t(0x01));         // 0 or ~size_t(0)
        size_t safe_idx = (src_idx & mask) | ((em.size() - 1) & ~mask);
        uint8_t real = em[safe_idx];
        uint8_t synthetic = synth[i];
        dst[i] = uint8_t((real & good) | (synthetic & uint8_t(~good)));
    }
}

} // anonymous namespace

std::vector<uint8_t> Crypto::syntheticPlaintextFromEM(const std::vector<uint8_t>& em,
                                                      const std::vector<uint8_t>& ct,
                                                      size_t out_len)
{
    if (em.empty() || ct.empty() || out_len == 0)
        return std::vector<uint8_t>(out_len, 0);

    std::vector<uint8_t> seed_key;
    {
        const std::string_view tag{"cdoc1-rsa-implicit-reject"};
        seed_key.reserve(tag.size() + em.size());
        seed_key.insert(seed_key.end(), tag.begin(), tag.end());
        seed_key.insert(seed_key.end(), em.begin(), em.end());
    }
    std::vector<uint8_t> prk = Crypto::sign_hmac(seed_key, ct);
    libcdoc::cleanse(seed_key);
    if (prk.empty())
        return std::vector<uint8_t>(out_len, 0);

    auto synth = Crypto::expand(prk, "cdoc1-rsa-implicit-reject", int(out_len));
    libcdoc::cleanse(prk);
    if (synth.size() != out_len) {
        libcdoc::cleanse(synth);
        return std::vector<uint8_t>(out_len, 0);
    }
    return synth;
}

int Crypto::rsaImplicitRejectFromEM(std::vector<uint8_t>& dst,
                                    const std::vector<uint8_t>& em,
                                    const std::vector<uint8_t>& /*ct*/,
                                    const std::vector<uint8_t>& synth_seed,
                                    size_t expected_len)
{
    // The caller passes a key-derived synthetic seed already sized to
    // `expected_len`. For token backends (PKCS#11, CNG) the seed is
    // produced by syntheticPlaintextFromEM(); for the software path by
    // syntheticPlaintext() to be consistent with OpenSSL implementation.
    // Both derive from private-key-dependent
    // material that the caller has access to.
    if (synth_seed.size() != expected_len)
        return CRYPTO_ERROR;

    unpadPKCS1v15CT(em, synth_seed, expected_len, dst);
    return OK;
}

int Crypto::decryptRSAv15_implicitReject(std::vector<uint8_t>& dst,
                                         EVP_PKEY *priv,
                                         const std::vector<uint8_t>& ct,
                                         size_t expected_len)
{
    if (!priv || expected_len == 0)
        return CRYPTO_ERROR;

    auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new(priv, nullptr));
    if (!ctx) {
        LOG_SSL_ERROR("EVP_PKEY_CTX_new");
        return CRYPTO_ERROR;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    // Native fast path: OpenSSL 3.2+ implements the implicit-rejection
    // countermeasure internally, with platform-specific constant-time
    // primitives, when this control is set AFTER EVP_PKEY_decrypt_init.
    //
    // Behaviour with implicit rejection enabled: a successful PKCS#1 v1.5
    // unpad returns the original plaintext (length = M length). A failed
    // unpad returns a deterministic synthetic message of length
    // (modulus_bytes - 11) - the maximum unpad length for the modulus.
    // Either way EVP_PKEY_decrypt returns 1.
    //
    // We allocate a buffer of (modulus_bytes - 11) so both cases fit, then
    // accept the result iff outlen == expected_len. A wrong-length
    // unpadding (real bug or wrong-key-with-coincidentally-good-padding)
    // is treated as a padding failure: fall through to the software path
    // which produces a synthetic plaintext of expected_len bytes.
    if (EVP_PKEY_decrypt_init(ctx.get()) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) == 1) {
        unsigned int impl_reject = 1;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION,
                                      &impl_reject),
            OSSL_PARAM_END
        };
        if (EVP_PKEY_CTX_set_params(ctx.get(), params) == 1) {
            const size_t mod_size = size_t(EVP_PKEY_get_size(priv));
            if (mod_size > 11 + expected_len && ct.size() == mod_size) {
                // Allocate enough room for the worst-case (synthetic)
                // output, then ask the API how many bytes it wrote.
                std::vector<uint8_t> tmp(mod_size, 0);
                size_t outlen = tmp.size();
                int rv = EVP_PKEY_decrypt(ctx.get(), tmp.data(), &outlen,
                                          ct.data(), ct.size());
                if (rv == 1 && outlen == expected_len) {
                    dst.assign(tmp.begin(), tmp.begin() + outlen);
                    libcdoc::cleanse(tmp);
                    return OK;
                }
                libcdoc::cleanse(tmp);
                // Length didn't match - fall through to software path so we
                // produce a synthetic plaintext of the correct length.
                //
                // N12 (accepted residual): the OpenSSL >= 3.2 fast path
                // returns after one RSA operation when padding is valid
                // AND the message length equals expected_len; all other
                // cases fall through to the software path below (second
                // RSA op + DER encode + HMAC/HKDF). An attacker with
                // precise timing can therefore distinguish
                // "PKCS#1-conformant with a 32-byte message" from
                // everything else - a narrow Bleichenbacher-style oracle
                // covering roughly 1/246 of conformant messages for
                // 2048-bit keys. We accept this residual: the N10
                // per-key minimum-interval throttle limits the attacker
                // to one query per second per RSA key, so extracting a
                // usable oracle signal requires days of wall-clock time
                // and is further constrained by the same countermeasures
                // that protect the software path (constant-time unpad,
                // synthetic plaintext, AES-GCM body authentication).
            }
        }
    }
    // Reset the context for the fall-through software path.
    ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new(priv, nullptr));
    if (!ctx) {
        LOG_SSL_ERROR("EVP_PKEY_CTX_new");
        return CRYPTO_ERROR;
    }
#endif

    // Software path: raw RSA decrypt + constant-time unpadding.
    if (EVP_PKEY_decrypt_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_NO_PADDING) != 1) {
        LOG_SSL_ERROR("EVP_PKEY_decrypt_init/RSA_NO_PADDING");
        return CRYPTO_ERROR;
    }

    const size_t mod_size = size_t(EVP_PKEY_get_size(priv));
    if (mod_size == 0 || ct.size() != mod_size) {
        // Genuine input error - return CRYPTO_ERROR rather than synthetic
        // bytes. The shape of this failure is independent of any padding
        // bits, so it does not feed an oracle.
        return CRYPTO_ERROR;
    }

    std::vector<uint8_t> em(mod_size, 0);
    size_t em_len = mod_size;
    int rv = EVP_PKEY_decrypt(ctx.get(), em.data(), &em_len,
                              ct.data(), ct.size());
    if (rv != 1 || em_len != mod_size) {
        // Raw RSA can fail if ct >= modulus. Produce a synthetic plaintext
        // anyway so the timing/return shape matches a "bad padding" path
        // and does not leak the cause.
        libcdoc::cleanse(em);
        dst = syntheticPlaintext(priv, ct, expected_len);
        return OK;
    }

    std::vector<uint8_t> synth = syntheticPlaintext(priv, ct, expected_len);
    unpadPKCS1v15CT(em, synth, expected_len, dst);
    libcdoc::cleanse(em);
    libcdoc::cleanse(synth);
    return OK;
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
        LOG_TRACE_KEY("tag: {}", tag);
        if (dst.write(tag.data(), tag.size()) != tag.size())
            return IO_ERROR;
    }
    else if(EVP_CIPHER_CTX_flags(ctx.get()) & EVP_CIPH_FLAG_AEAD_CIPHER)
    {
        if(SSL_FAILED(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, int(tag.size()), tag.data()), "EVP_CIPHER_CTX_ctrl"))
            return CRYPTO_ERROR;
        LOG_TRACE_KEY("tag: {}", tag);
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
        LOG_TRACE_KEY("tag: {}", tag);
        if (SSL_FAILED(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, int(tag.size()), tag.data()), "EVP_CIPHER_CTX_ctrl")) {
            return error = CRYPTO_ERROR;
        }
    }
    else if(EVP_CIPHER_CTX_flags(ctx.get()) & EVP_CIPH_FLAG_AEAD_CIPHER)
    {
        LOG_TRACE_KEY("tag: {}", tag);
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
