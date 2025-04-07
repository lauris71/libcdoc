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

#include "utils/memory.h"

#include <string>
#include <vector>

typedef unsigned char uint8_t;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;

namespace libcdoc {

#define SSL_FAILED(retval,func) Crypto::isError((retval), (func), __FILE__, __LINE__)
#define LOG_SSL_ERROR(func) Crypto::LogSslError((func), __FILE__, __LINE__)

class Crypto
{
public:
	using EVP_PKEY_ptr = unique_free_t<EVP_PKEY>;

	struct Cipher {
		struct evp_cipher_ctx_st *ctx;
		Cipher(const EVP_CIPHER *cipher, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, bool encrypt = true);
		~Cipher();
		bool updateAAD(const std::vector<uint8_t> &data) const;
		bool update(uint8_t *data, int size) const;
		bool result() const;
		static constexpr int tagLen() { return 16; }
		std::vector<uint8_t> tag() const;
		bool setTag(const std::vector<uint8_t> &data) const;
		int blockSize() const;
		void clear();
	};

	static constexpr std::string_view KWAES128_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
	static constexpr std::string_view KWAES192_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
	static constexpr std::string_view KWAES256_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes256";

	static const std::string SHA256_MTH, SHA384_MTH, SHA512_MTH;
	static const char *AES128CBC_MTH, *AES192CBC_MTH, *AES256CBC_MTH, *AES128GCM_MTH, *AES192GCM_MTH, *AES256GCM_MTH;
	static const std::string RSA_MTH, CONCATKDF_MTH, AGREEMENT_MTH;

    struct Key {
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;

        Key() {}
        Key(size_t keySize, size_t ivSize) : key(keySize), iv(ivSize) {}
    };

	static std::vector<uint8_t> AESWrap(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data, bool encrypt);
	static const EVP_CIPHER *cipher(const std::string &algo);
	static std::vector<uint8_t> concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uint8_t> &z, const std::vector<uint8_t> &otherInfo);
	static std::vector<uint8_t> concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uint8_t> &z,
		const std::vector<uint8_t> &AlgorithmID, const std::vector<uint8_t> &PartyUInfo, const std::vector<uint8_t> &PartyVInfo);
    static std::vector<uint8_t> encrypt(const std::string &method, const Key &key, const std::vector<uint8_t> &data);
	static std::vector<uint8_t> decrypt(const std::string &method, const std::vector<uint8_t> &key, const std::vector<uint8_t> &data);
	static std::vector<uint8_t> encrypt(EVP_PKEY *pub, int padding, const std::vector<uint8_t> &data);
	static std::vector<uint8_t> decodeBase64(const uint8_t *data);
	static std::vector<uint8_t> deriveSharedSecret(EVP_PKEY *pkey, EVP_PKEY *peerPKey);
	static Key generateKey(const std::string &method);
	static uint32_t keySize(const std::string &algo);

	static std::vector<uint8_t> hkdf(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, const std::vector<uint8_t> &info, int len = 32, int mode = 0);
	static std::vector<uint8_t> expand(const std::vector<uint8_t> &key, const std::vector<uint8_t> &info, int len = 32);
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

	static unique_free_t<X509> toX509(const std::vector<uint8_t> &data);

    static bool isError(int retval, const char* funcName, const char* file, int line)
    {
        if (retval < 1) {
            LogSslError(funcName, file, line);
            return true;
        } else
            return false;
    }

    static void LogSslError(const char* funcName, const char* file, int line);
};

}; // namespace libcdoc
