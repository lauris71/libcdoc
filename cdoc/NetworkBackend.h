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

#ifndef __NETWORKBACKEND_H__
#define __NETWORKBACKEND_H__

#include <cdoc/CryptoBackend.h>

namespace libcdoc {

struct CDOC_EXPORT NetworkBackend {
	static constexpr int OK = 0;
	static constexpr int NOT_IMPLEMENTED = -300;
	static constexpr int INVALID_PARAMS = -301;
	static constexpr int NETWORK_ERROR = -302;

    struct CapsuleInfo {
        std::string transaction_id;
        uint64_t expiry_time;
    };

    struct ShareInfo {
        std::vector<uint8_t> share;
        std::string recipient;
    };

    NetworkBackend() = default;
	virtual ~NetworkBackend() noexcept = default;
    NetworkBackend(const NetworkBackend&) = delete;
    NetworkBackend& operator=(const NetworkBackend&) = delete;
    CDOC_DISABLE_MOVE(NetworkBackend);

	virtual std::string getLastErrorStr(result_t code) const;

	/**
	 * @brief send key material to keyserver
     *
     * The default implementation uses internal http client and peer TLS certificate list.
     * @param dst the transaction id and expiry date of the capsule on server
     * @param url server url
     * @param rcpt_key recipient's public key
     * @param key_material encrypted KEK or ECDH public Key used to derive shared secret
	 * @param type algorithm type, currently either "rsa" or "ecc_secp384r1"
	 * @return error code or OK
	 */
    virtual result_t sendKey (CapsuleInfo& dst, const std::string& url, const std::vector<uint8_t>& rcpt_key, const std::vector<uint8_t> &key_material, const std::string& type);
    /**
     * @brief send key share to server
     *
     * The recipient has to be in form "etsi/PNOEE-XXXXXXXXXXXX" and must match certificate subject serial number field (without "etsi/" prefix).
     * @param dst a container for share id
     * @param url server url
     * @param recipient the recipient id (ETSI319412-1)
     * @param share base64 encoded Key Share
     * @return error code or OK
     */
    virtual result_t sendShare(std::string& dst, const std::string& url, const std::string& recipient, const std::vector<uint8_t>& share);
	/**
	 * @brief fetch key material from keyserver
     *
     * The default implementation uses internal http client, peer TLS list and client TLS certificate
     * @param dst a destination container for key material
     * @param url server url
     * @param transaction_id transaction id of capsule
	 * @return error code or OK
	 */
    virtual result_t fetchKey (std::vector<uint8_t>& dst, const std::string& url, const std::string& transaction_id);
    /**
     * @brief fetch authentication nonce from share server
     * @param dst a destination container for nonce
     * @param share_id share id (transaction id)
     * @return error code or OK
     */
    virtual result_t fetchNonce(std::vector<uint8_t>& dst, const std::vector<uint8_t>& share_id);
    /**
     * @brief fetch key share from share server
     * @param share acontainer for result
     * @param url server url
     * @param share_id share id (transaction id)
     * @return error code or OK
     */
    virtual result_t fetchShare(ShareInfo& share, const std::string& url, const std::string& share_id);


    /**
     * @brief get client TLS certificate in der format
     * @param dst a destination container for certificate
     * @return error code or OK
     */
    virtual result_t getClientTLSCertificate(std::vector<uint8_t>& dst) {
        return NOT_IMPLEMENTED;
    }

    /**
     * @brief get a list of peer TLS certificates in der format
     * @param dst a destination container for certificate
     * @return error code or OK
     */
    virtual result_t getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst) {
        return NOT_IMPLEMENTED;
    }

    /**
     * @brief sign TLS digest with client's private key
     * @param dst a destination container for signature
     * @param algorithm signing algorithm
     * @param digest data to be signed
     * @return error code or OK
     */
    virtual result_t signTLS(std::vector<uint8_t>& dst, CryptoBackend::HashAlgorithm algorithm, const std::vector<uint8_t> &digest) {
        return NOT_IMPLEMENTED;
    }

#if LIBCDOC_TESTING
    virtual int64_t test(std::vector<std::vector<uint8_t>> &dst);
#endif
};

} // namespace libcdoc

#endif // NETWORKBACKEND_H
