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

#include <map>

namespace libcdoc {

struct CDOC_EXPORT NetworkBackend {
    /**
     * @brief Generic network error
     * 
     */
	static constexpr int NETWORK_ERROR = -300;
#ifdef HAS_KEYSHARES
    // SID v3.1+ session endResult codes
    // (https://sk-eid.github.io/smart-id-documentation/rp-api/api_specification.html)
    // User refused the session
    static constexpr int MIDSID_USER_REFUSED = -350;
    // There was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
    static constexpr int MIDSID_TIMEOUT = -351;
    // For some reason, this RP request cannot be completed. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason
    static constexpr int MIDSID_DOCUMENT_UNUSABLE = -352;
    // In case the multiple-choice verification code was requested, the user did not choose the correct verification code
    static constexpr int MIDSID_WRONG_VC = -353;
    // User app version does not support any of the allowedInteractionsOrder interactions
    static constexpr int MIDSID_REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP = -354;
    // User has multiple accounts and pressed Cancel on device choice screen on any device
    static constexpr int MIDSID_USER_REFUSED_CERT_CHOICE = -355;
    // User pressed Cancel on the interaction screen (result.details contains which interaction was cancelled).
    // Since SID v3.1 this replaces the removed granular codes
    // USER_REFUSED_DISPLAYTEXTANDPIN / USER_REFUSED_VC_CHOICE /
    // USER_REFUSED_CONFIRMATIONMESSAGE / USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE.
    static constexpr int MIDSID_USER_REFUSED_INTERACTION = -356;
    // There was a logical error in the signing protocol
    static constexpr int MIDSID_PROTOCOL_FAILURE = -357;
    // The app received a different transaction while waiting for the linked session
    static constexpr int MIDSID_EXPECTED_LINKED_SESSION = -358;
    // The process was terminated due to server-side technical error
    static constexpr int MIDSID_SERVER_ERROR = -359;
    // The account is currently unusable
    static constexpr int ACCOUNT_UNUSABLE = -360;

    // Numeric gap at -361..-364: the SID v3.0 granular USER_REFUSED_* codes
    // were removed from the API in v3.1 and their constants deleted here.
    // The remaining values are kept stable for API compatibility.

    // MID session end result codes
    // (https://github.com/SK-EID/MID/blob/master/README.md#338-session-end-result-codes)
    // Given user has no active certificates and is not MID client.
    static constexpr int MIDSID_NOT_MID_CLIENT = -365;
    // User cancelled the operation
    static constexpr int MIDSID_USER_CANCELLED = -366;
    // Mobile-ID configuration on user's SIM card differs from what is configured on service provider's side. User needs to contact his/her mobile operator.
    static constexpr int MIDSID_SIGNATURE_HASH_MISMATCH = -367;
    // Sim not available
    static constexpr int MIDSID_PHONE_ABSENT = -368;
    // SMS sending error
    static constexpr int MIDSID_DELIVERY_ERROR = -369;
    // Invalid response from card
    static constexpr int MIDSID_SIM_ERROR = -370;
#endif

    /**
     * @brief Capsule information returned by capsule server
     * 
     */
    struct CapsuleInfo {
        /**
         * @brief Transaction id needed to retrieve the key later
         *
         */
        std::string transaction_id;
        /**
         * @brief Capsule exipry time on server
         *
         */
        uint64_t expiry_time;
    };

    /**
     * @brief Proxy credentials used for network access
     * 
     */
    struct ProxyCredentials {
        /**
         * @brief Proxy host
         */
        std::string host;
        /**
         * @brief Proxy port
         */
        uint16_t port;
        /**
         * @brief Proxy username
         */
        std::string username;
        /**
         * @brief Proxy password
         * 
         * It is the implementer's responsibility to ensure that the buffer remains valid during CDocWriter getFMK and beginEncryption calls
         */
        std::string_view password;
    };

    NetworkBackend() = default;
	virtual ~NetworkBackend() noexcept = default;
    NetworkBackend(const NetworkBackend&) = delete;
    NetworkBackend& operator=(const NetworkBackend&) = delete;
    CDOC_DISABLE_MOVE(NetworkBackend);
    /**
     * @brief Get the textual description of the last error
     * 
     * The result is undefined if the error code does not match the most recent error
     * @param code The error code
     * @return std::string error description
     */
	virtual std::string getLastErrorStr(result_t code) const;

    virtual result_t get(const std::string& url, std::vector<uint8_t>& body, std::map<std::string, std::string>& headers, bool client_cert);
    virtual result_t post(const std::string& url, std::vector<uint8_t>& body, std::map<std::string, std::string>& headers, bool client_cert);

    /**
	 * @brief send key material to keyserver
     *
     * The default implementation uses internal http client and peer TLS certificate list.
     * @param dst the transaction id and expiry date of the capsule on server
     * @param url server url
     * @param rcpt_key recipient's public key
     * @param key_material encrypted KEK or ECDH public Key used to derive shared secret
	 * @param type algorithm type, currently either "rsa", "ecc_secp384r1", "ecc_secp256r1" or "ecc_secp521r1"
     * @param expiry_ts the requested capsule expiry timestamp, 0 - use server default
	 * @return error code or OK
	 */
    virtual result_t sendKey (CapsuleInfo& dst, const std::string& url, const std::vector<uint8_t>& rcpt_key, const std::vector<uint8_t> &key_material, const std::string& type, uint64_t expiry_ts);
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
     * @brief get a list of peer TLS certificates in der format
     * @param dst a destination container for certificate
     * @param url the base url ("https://servername:port/")
     * @return error code or OK
     */
    virtual result_t getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst, const std::string& url) {
        return getPeerTLSCertificates(dst);
    }

    /**
     * @brief Get proxy configuration currently set
     * @param credentials output for proxy credentials
     */
    virtual result_t getProxyCredentials(ProxyCredentials& credentials) const {
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

#ifdef HAS_KEYSHARES
    //
    // SID/MID (keyshare) support
    //

    /**
     * @brief Share information returned by share server
     *
     */
    struct ShareInfo {
        /**
         * @brief Share value
         *
         */
        std::vector<uint8_t> share;
        /**
         * @brief Recipoient id (etsi/PNOEE-01234567890)
         *
         */
        std::string recipient;
    };

    const std::string X_CDOC2_SID_RPV3_SIGNATURE_PARAMETERS = "x-cdoc2-sid-rpv3-signature-parameters";
    const std::string X_RP_SIGNED_HASH = "x-rp-signed-hash";
    const std::string X_RP_NAME = "x-rp-name";
    const std::string HDR_SIGNATURE_INPUT = "Signature-Input";
    const std::string HDR_SIGNATURE = "Signature";

    /**
     * @brief Session data
     *
     * The session token and certificate provided by AUTH server or the per-share server authentication token,
     * authentication certificate and protocol-specific parameters.
     *
     */
    struct SessionData {
        std::string token;
        std::string cert;
        std::map<std::string, std::string> params;
    };

    /**
     * @brief SID/MID verification feedback data
     * 
     * Currently only 4-digit verification code is supported, the url is for future device-link based authentication
     *
     */
    struct SIDMIDFeedback {
        int code;
        std::string url;
    };

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
    virtual result_t sendShare(std::vector<uint8_t>& dst, const std::string& url, const std::string& recipient, const std::vector<uint8_t>& share);

    /**
     * @brief Run a full SID/MID authentication round-trip.
     *
     * POSTs @p body to `{url}/auth/start`, extracts the Location
     * header and verification code, calls showFeedback, then polls
     * GET `{url}/auth/status/{id}` until the server reports COMPLETE.
     *
     * The default implementation uses a single httplib::SSLClient with
     * httpPost/httpGet, polling on the same connection with
     * set_keep_alive(false).
     *
     * @param url The auth server base URL
     * @param body Input: pre-constructed request body.
     *             Output: final response body (COMPLETE state).
     *             On error the value may or may not have changed.
     * @param headers Input: request headers (may be empty).
     *                Output: final response headers.
     *                On error the value may or may not have changed.
     * @return Error code or OK
     */
    virtual result_t getAuthResponse(const std::string& url, std::vector<uint8_t>& body,
        std::map<std::string, std::string>& headers);

    /**
     * @brief Run a full SID/MID signing round-trip.
     *
     * POSTs @p body to @p post_path, extracts the session ID from
     * the response body, then polls GET on @p poll_path_prefix/{sessionID}
     * until the server reports COMPLETE.
     *
     * Unlike getAuthResponse, this method does not call showFeedback; the
     * caller is expected to display the verification code before calling.
     *
     * The default implementation uses a single httplib::SSLClient with
     * httpPost/httpGet, polling on the same connection with
     * set_keep_alive(false).
     *
     * @param url The server base URL
     * @param post_path Path for the initial POST (e.g. "/sid/authenticate")
     * @param body Input: pre-constructed request body.
     *             Output: final response body (COMPLETE state).
     *             On error the value may or may not have changed.
     * @param headers Input: headers for the initial POST (session token etc.).
     *                Output: final response headers.
     *                On error the value may or may not have changed.
     * @param poll_path_prefix Path prefix for polling (e.g. "/sid/session/")
     * @return Error code or OK
     */
    virtual result_t getSignResponse(const std::string& url, const std::string& post_path,
        std::vector<uint8_t>& body, std::map<std::string, std::string>& headers,
        const std::string& poll_path_prefix);

    /**
     * @brief Get a session token and certificate for share authentication
     *
     * Implementation may cache the session token and certificate if appropriate
     *
     * @param url The server URL
     * @param rcpt_id The recipient id (etsi/PNOEE-...) the session is authenticated for.
     *        Must match the identity that will sign the share tickets and the lock's
     *        recipient id, so that session identity == signing identity == recipient.
     * @param session Output parameter for session data (token and certificate)
     * @return Error code or OK
     */
    virtual result_t authenticateForShares(const std::string& url, const std::string& rcpt_id, const std::string& phone, SessionData& session);

    /**
     * @brief fetch authentication nonce from share server
     * @param dst a destination container for nonce
     * @param url server url
     * @param share_id share id (transaction id)
     * @param session session data (token and certificate)
     * @return error code or OK
     */
    virtual result_t fetchNonce(std::vector<uint8_t>& dst, const std::string& url, const std::string& share_id, const SessionData& session);

    /**
     * @brief fetch key share from share server
     * @param share a container for result
     * @param url server url
     * @param share_id share id (transaction id)
     * @param session session data (token and certificate)
     * @param auth authentication data: token = the signed ticket for this
     *             share, cert = base64url-encoded certificate of the
     *             signing key, params = protocol-specific header parameters
     * @return error code or OK
     */
    virtual result_t fetchShare(ShareInfo& share, const std::string& url, const std::string& share_id,
        const SessionData& session, const SessionData& auth);

    /**
     * @brief show MID/SID verification code or QR code
     *
     * Show SID/MID verification code or QR code. The default implementation logs the content with level INFO.
     *
     * @param feedback SID/MID feedback data
     * @return error code or OK
     */
    virtual result_t showFeedback(SIDMIDFeedback& feedback);

    /**
     * @brief Sign digest with SmartID authentication key
     *
     * @param dst a container for signature
     * @param cert a container for certificate
     * @param params SID signature parameters
     * @param url SmartID gateway base URL
     * @param session session data (token and certificate)
     * @param rcpt_id recipient id (etsi/PNOEE-XYZXYZXYZXY)
     * @param text the text shown on the user's device (displayText200,
     *             max 200 characters)
     * @param digest digest to sign
     * @param algo algorithm type (SHA256, SHA385, SHA512)
     * @return error code or OK
     */
    result_t signSID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert, std::map<std::string, std::string>& params,
        const std::string& url, const SessionData& session,
        const std::string& rcpt_id, std::string& text, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo);

    /**
     * @brief Sign digest with Mobile ID authentication key
     *
     * @param dst a container for signature
     * @param cert a container for certificate
     * @param url Mobile ID gateway base URL
     * @param phone recipient's phone number
     * @param session session data (token and certificate)
     * @param rcpt_id recipient id (etsi/PNOEE-XYZXYZXYZXY)
     * @param text the text shown on the user's device (displayText,
     *             max 100 characters in GSM-7 or 50 in UCS-2 encoding)
     * @param digest digest to sign
     * @param algo algorithm type (SHA256, SHA385, SHA512)
     * @return error code or OK
     */
    result_t signMID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert, std::map<std::string, std::string>& params,
        const std::string& url, const std::string& phone, const SessionData& session,
        const std::string& rcpt_id, std::string& text, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo);
#endif
};

} // namespace libcdoc

#endif // NETWORKBACKEND_H
