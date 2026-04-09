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
    static constexpr std::string_view AES128CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
    static constexpr std::string_view AES192CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
    static constexpr std::string_view AES256CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    static constexpr std::string_view AES128GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    static constexpr std::string_view AES192GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
    static constexpr std::string_view AES256GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
	static const std::string RSA_MTH, CONCATKDF_MTH, AGREEMENT_MTH;

    struct Key {
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;

        Key() {}
		~Key() {
			std::fill(key.begin(), key.end(), 0);
			std::fill(iv.begin(), iv.end(), 0);
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

    static EVP_PKEY_ptr genECKey(EVP_PKEY *params);
	static std::vector<uint8_t> toPublicKeyDer(EVP_PKEY *key);

	static std::vector<uint8_t> random(uint32_t len = 32);
	static int xor_data(std::vector<uint8_t>& dst, const std::vector<uint8_t> &lhs, const std::vector<uint8_t> &rhs);

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
