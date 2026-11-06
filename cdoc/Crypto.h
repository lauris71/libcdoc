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

#pragma once

#include "Io.h"

#include "utils/memory.h"

#include <array>

using EVP_CIPHER_CTX = struct evp_cipher_ctx_st;
using EVP_CIPHER = struct evp_cipher_st;
using EVP_PKEY = struct evp_pkey_st;
using X509 = struct x509_st;

namespace libcdoc {

#define SSL_FAILED(retval,func) Crypto::isError((retval), (func), __FILE__, __LINE__)
#define LOG_SSL_ERROR(func) Crypto::LogSslError((func), __FILE__, __LINE__)

class Crypto
{
public:
	using EVP_PKEY_ptr = unique_free_t<EVP_PKEY>;

	static constexpr std::string_view KWAES128_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
	static constexpr std::string_view KWAES192_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
	static constexpr std::string_view KWAES256_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes256";

	static const std::string SHA256_MTH, SHA384_MTH, SHA512_MTH;
    // AES-CBC was only used by CDoc 1.0; all CDoc 1.0 containers have
    // expired and we no longer accept it. The constants are removed so
    // that new code cannot accidentally re-introduce CBC support.
    static constexpr std::string_view AES128GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    static constexpr std::string_view AES192GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
    static constexpr std::string_view AES256GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
	static const std::string RSA_MTH, CONCATKDF_MTH, AGREEMENT_MTH;

    struct Key {
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;

        Key() {}
		~Key() {
			libcdoc::cleanse(key);
			libcdoc::cleanse(iv);
		}
        Key(std::vector<uint8_t> _key, std::vector<uint8_t> _iv) : key(std::move(_key)), iv(std::move(_iv)) {}
        Key(size_t keySize, size_t ivSize) : key(keySize), iv(ivSize) {}
    };

	static std::vector<uint8_t> AESWrap(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data, bool encrypt);
	static const EVP_CIPHER *cipher(const std::string &algo);
	static std::vector<uint8_t> concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uint8_t> &z, const std::vector<uint8_t> &otherInfo);
	static std::vector<uint8_t> concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uint8_t> &z,
		const std::vector<uint8_t> &AlgorithmID, const std::vector<uint8_t> &PartyUInfo, const std::vector<uint8_t> &PartyVInfo);
	static std::vector<uint8_t> encrypt(EVP_PKEY *pub, int padding, const std::vector<uint8_t> &data);
	static std::vector<uint8_t> decodeBase64(const uint8_t *data);
	static std::vector<uint8_t> deriveSharedSecret(EVP_PKEY *pkey, EVP_PKEY *peerPKey);
	static Key generateKey(const std::string &method);
	static uint32_t keySize(const std::string &algo);

    static std::vector<uint8_t> hkdf(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, std::string_view info, int len = 32, int mode = 0);
    static std::vector<uint8_t> expand(const std::vector<uint8_t> &key, std::string_view info, int len = 32);
	static std::vector<uint8_t> extract(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, int len = 32);
	static std::vector<uint8_t> sign_hmac(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data);

	static std::vector<uint8_t> pbkdf2_sha256(const std::vector<uint8_t>& pw, const std::vector<uint8_t>& salt, uint32_t iter);

    static EVP_PKEY_ptr fromRSAPublicKeyDer(const std::vector<uint8_t> &der);

    /* Create public key from short encoding (0x04...) */
    static EVP_PKEY_ptr fromECPublicKeyDer(const std::vector<uint8_t> &der, int curveName);
    /* Create public key from long encoding (0x30...) */
    static EVP_PKEY_ptr fromECPublicKeyDer(const std::vector<uint8_t> &der);
    static EVP_PKEY_ptr fromPublicKeyDer(const std::vector<uint8_t> &der);

    static EVP_PKEY_ptr genECKey(EVP_PKEY *params);
	static std::vector<uint8_t> toPublicKeyDer(EVP_PKEY *key);
	static std::vector<uint8_t> toPublicKeyDerLong(EVP_PKEY *key);

	static std::vector<uint8_t> random(uint32_t len = 32);
	static int xor_data(std::vector<uint8_t>& dst, const std::vector<uint8_t> &lhs, const std::vector<uint8_t> &rhs);

    /**
     * @brief Decrypt an RSA PKCS#1 v1.5 ciphertext with implicit rejection.
     *
     * Implements the decryption procedure of RFC 8017 section 7.2.2 with the
     * "implicit rejection" countermeasure described by Bleichenbacher /
     * RFC 8017 Appendix B / OpenSSL's @c EVP_PKEY_CTX_set_rsa_implicit_rejection.
     * On successful unpadding produces the recovered plaintext; on padding
     * failure produces a deterministic synthetic plaintext derived from the
     * private key and the ciphertext, of the requested @p expected_len bytes,
     * indistinguishable from a real decryption to an attacker who does not
     * already know the private key.
     *
     * The function ALWAYS returns @c OK and ALWAYS produces exactly
     * @p expected_len output bytes for any well-formed ciphertext (size equal
     * to the modulus length). The caller MUST treat the output as a candidate
     * key whose validity can only be confirmed by a downstream authenticated
     * step (AES-GCM tag, HMAC, ...). It MUST NOT branch on the output's
     * structure or surface a different error for "decryption failed" vs
     * "key was wrong" - doing so reintroduces the very oracle this function
     * exists to remove.
     *
     * On OpenSSL >= 3.2 this delegates to OpenSSL's native implementation; on
     * older OpenSSL versions it implements the same algorithm in software.
     *
     * @param dst        destination buffer (resized to @p expected_len)
     * @param priv       RSA private key
     * @param ct         ciphertext (must equal modulus length)
     * @param expected_len length of plaintext the caller expects to receive
     * @return OK on success, CRYPTO_ERROR only for unrecoverable, non-padding
     *         failures (e.g. ct size mismatch with modulus)
     */
    static int decryptRSAv15_implicitReject(std::vector<uint8_t>& dst,
                                            EVP_PKEY *priv,
                                            const std::vector<uint8_t>& ct,
                                            size_t expected_len);

    /**
     * @brief Enforce a minimum interval between RSA decrypt failures
     *        from the same recipient key.
     *
     * Bleichenbacher / cross-protocol attacks against RSA-PKCS#1 v1.5
     * require a large number of adaptive queries against the same victim
     * key. This helper enforces a 1-second minimum interval between
     * consecutive failures for a given key, dramatically increasing the
     * wall-clock cost of a remote oracle campaign without penalising
     * legitimate single-shot use.
     *
     * The throttle is keyed by a hash of the recipient's public key
     * (not the container ciphertext), so different RSA keys have
     * independent intervals and no cross-tenant DoS is possible.
     *
     * On each call, entries older than the minimum interval are erased,
     * keeping the map bounded.
     *
     * @param key_id a hex-encoded hash of the recipient's public key
     */
    static void rsaOracleThrottle(const std::string& key_id);

    /**
     * @brief Constant-time PKCS#1 v1.5 unpadding from a pre-decrypted EM block.
     *
     * Same semantics as @ref decryptRSAv15_implicitReject, but skips the raw
     * RSA decryption step. Intended for backends (PKCS#11, CNG) that obtain
     * the EM block via raw RSA (CKM_RSA_X_509 / BCRYPT_PAD_NONE) and need to
     * apply the constant-time unpadding in user space.
     *
     * @param dst          destination buffer (resized to @p expected_len)
     * @param em           EM block as returned by raw RSA decryption
     * @param ct           original ciphertext (used as input to the synthetic
     *                     plaintext derivation - MUST be the *same* bytes the
     *                     caller decrypted, so that retries on the same
     *                     ciphertext yield the same synthetic output)
     * @param synth_seed   private-key-derived seed used to make synthetic
     *                     output unpredictable to attackers
     * @param expected_len length of plaintext the caller expects to receive
     * @return OK on success
     */
    static std::vector<uint8_t> syntheticPlaintextFromEM(const std::vector<uint8_t>& em,
                                                         const std::vector<uint8_t>& ct,
                                                         size_t out_len);

    static int rsaImplicitRejectFromEM(std::vector<uint8_t>& dst,
                                       const std::vector<uint8_t>& em,
                                       const std::vector<uint8_t>& ct,
                                       const std::vector<uint8_t>& synth_seed,
                                       size_t expected_len);

    static bool isError(int retval, const char* funcName, const char* file, int line)
    {
        if (retval < 1) {
            LogSslError(funcName, file, line);
            return true;
        }
        return false;
    }

    static void LogSslError(const char* funcName, const char* file, int line);
};

struct EncryptionConsumer final : public DataConsumer {
    EncryptionConsumer(DataConsumer &dst, const std::string &method, const Crypto::Key &key);
    EncryptionConsumer(DataConsumer &dst, const EVP_CIPHER *cipher, const Crypto::Key &key);
    ~EncryptionConsumer() { libcdoc::cleanse(buf); }
    CDOC_DISABLE_MOVE_COPY(EncryptionConsumer)
    result_t write(const uint8_t *src, size_t size) noexcept final;
    result_t writeAAD(const std::vector<uint8_t> &data) noexcept;
    result_t close() noexcept final;
    bool isError() noexcept final { return error != OK || dst.isError(); }

private:
    unique_free_t<EVP_CIPHER_CTX> ctx;
    DataConsumer &dst;
    result_t error = OK;
    std::vector<uint8_t> buf;
};

struct DecryptionSource final : public DataSource {
    DecryptionSource(DataSource &src, const std::string &method, const std::vector<unsigned char> &key, size_t ivLen = 0);
    DecryptionSource(DataSource &src, const EVP_CIPHER *cipher, const std::vector<unsigned char> &key, size_t ivLen = 0);
    ~DecryptionSource() { libcdoc::cleanse(tag); }
    CDOC_DISABLE_MOVE_COPY(DecryptionSource)

    result_t read(unsigned char* dst, size_t size) noexcept final;
    result_t updateAAD(const std::vector<uint8_t>& data);
    result_t close();
    bool isError() noexcept final { return error != OK || src.isError(); }
    bool isEof() noexcept final { return src.isEof(); }

private:
    unique_free_t<EVP_CIPHER_CTX> ctx;
    DataSource &src;
    result_t error = OK;
    std::array<uint8_t, 16> tag {};
};

}; // namespace libcdoc
