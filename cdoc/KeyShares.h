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

#ifndef __KEYSHARES_H__
#define __KEYSHARES_H__

#include <cdoc/NetworkBackend.h>

namespace libcdoc {

/**
 * @brief Share information from CDoc capsule
 * 
 * Contains the full share information, including session nonce fetched from the server
 * 
 */
struct ShareData {
    std::string base_url;
    std::string share_id;
    std::string nonce;
    
    /**
     * @brief Construct a new Share Data object for authentication
     * 
     * @param _base_url share server base url (e.g. https://cdoc2.my.domain/v1/)
     * @param _share_id share id from capsule
     */
    ShareData(const std::string& _base_url, const std::string& _share_id) : base_url(_base_url), share_id(_share_id) {}


    /**
     * @brief Get share url
     * 
     * Construct the url to fetch share from the server: base_url/key-shares/share_id?nonce=nonce
     * 
     * @return share url
     */
    std::string getURL();
};

/**
 * @brief Authentication data for share tickets
 * 
 * The certificate and signature parameters from RP server
 */
struct AuthenticationData {
    std::vector<uint8_t> cert;
    std::map<std::string, std::string> params;
};

/**
 * @brief Abstract base class for MID/SID signing
 * 
 * Implementations use protocol-specific methods to sign JWT and create share tickets
 * 
 */
struct Signer {
    /**
     * @brief Generate tickets for shares
     * 
     * Generates a list of tickets for all shares by creating and signing SD-JWT and adding server-specific
     * disclosures to each ticket
     * 
     * @param dst the destination container
     * @param shares a list of shares, including nonces
     * @return result_t error code or OK
     */
    result_t generateTickets(std::vector<std::string>& dst, std::vector<libcdoc::ShareData>& shares);
    /**
     * @brief Protocol-specific signing method
     * 
     * @param dst the destination container
     * @param data plaintext data to be signed
     * @return result_t error code or ok
     */
    virtual result_t signDigest(std::vector<uint8_t>& dst, const std::vector<uint8_t>& digest) = 0;
    /**
     * @brief Full session token
     * 
     */
    const NetworkBackend::SessionData& session;
    /**
     * @brief Signing algorithm name (RS256/ES256)
     * 
     */
    const std::string algo_name;
    /**
     * @brief Recipient full id in etsi format (ets/PNOEE-XYZXYZXYZXY)
     * 
     */
    std::string rcpt_id;
    /**
     * @brief After successful signing holds the user certificate value
     * 
     */
    std::vector<uint8_t> cert;
    std::map<std::string, std::string> params;
    /**
     * @brief The text of last error
     * 
     */
    std::string error;
protected:
    NetworkBackend *network;
    /**
     * @brief Construct a new Signer object
     * 
     * @param _session Full session data (token and certificate)
     * @param _rcpt_id Recipient full id in etsi format (ets/PNOEE-XYZXYZXYZXY)
     * @param _algo_name Signing algorithm name (RS256/ES256)
     */
    Signer(const NetworkBackend::SessionData& _session, const std::string& _rcpt_id, const std::string& _algo_name, NetworkBackend *_network) : session(_session), rcpt_id(_rcpt_id), algo_name(_algo_name), network(_network) {}
};

/**
 * @brief SmartID protocol signer
 * 
 */
struct SIDSigner : public Signer {
    /**
     * @brief SmartID gateway url
     * 
     */
    const std::string url;

    /**
     * @brief Construct a new SIDSigner object
     * 
     * @param _url SmartID gateway url
     * @param _session Full session data (token and certificate)
     * @param _rcpt_id Recipient full id in etsi format (ets/PNOEE-XYZXYZXYZXY)
     */
    SIDSigner(const std::string& _url, const NetworkBackend::SessionData& _session, const std::string& _rcpt_id, NetworkBackend *network)
    : Signer(_session, _rcpt_id, "RSASSA-PSS+ACSP_V2", network), url(_url) {}

    result_t signDigest(std::vector<uint8_t>& dst, const std::vector<uint8_t>& digest) final;
};

/**
 * @brief Mobile ID protocol signer
 * 
 */
struct MIDSigner : public Signer {
    /**
     * @brief Mobile ID gateway url
     * 
     */
    const std::string url;
    /**
     * @brief Recipient phone number (with country code)
     * 
     */
    const std::string phone;
    /**
     * @brief Construct a new MIDSigner object
     * 
     * @param _url Mobile ID gateway url
     * @param _rcpt_id Recipient full id in etsi format (ets/PNOEE-XYZXYZXYZXY)
     */
    MIDSigner(const std::string& _url, const std::string& _phone, const NetworkBackend::SessionData& _session, const std::string& _rcpt_id, NetworkBackend *network)
    : Signer(_session, _rcpt_id, "ES256", network), url(_url), phone(_phone) {}

    result_t signDigest(std::vector<uint8_t>& dst, const std::vector<uint8_t>& digest) final;
};

struct SessionToken {
    std::string jwt;
    std::string aud;
    std::vector<std::string> disclosures;
    // fixme: Keep parsed data?

    SessionToken(std::string_view str);
    std::string discloseForUrl(std::string_view url);
    /**
     * @brief Check whether the session token authorizes a share server
     *
     * Returns true if any disclosure in the session token refers to the same
     * origin (scheme, host, port) as the given URL. The disclosures are issued
     * by the authentication server, so they enumerate the share servers that
     * are authorized for this session. Used to reject container-supplied share
     * servers that the authentication server has not authorized - the session
     * token and user credentials must never be sent to such servers.
     */
    bool hasDisclosureForUrl(std::string_view url);
};

std::string decodeTicket(const std::string& ticket);

/**
 * @brief Build the ACSP_V2 signed payload (Smart-ID RP v3)
 *
 * The payload is the |-joined string:
 * schemeName|ACSP_V2|serverRandom|rpChallenge|userChallenge|base64(rpName)||
 * interactionsDigest|interactionTypeUsed||flowType
 * (construction verified against the SK reference verifier).
 */
std::string buildAcspV2Payload(const std::string& scheme_name, const std::string& server_random,
                               const std::string& rp_challenge, const std::string& user_challenge,
                               const std::string& rp_name, const std::string& interactions_digest,
                               const std::string& interaction_type_used, const std::string& flow_type);

/**
 * @brief Validate the authentication session client-side (S8)
 *
 * Checks that the session signing certificate belongs to rcpt_id (via
 * CryptoBackend::validateCertificate), that the session token is not expired,
 * and extracts the schemeName/rpName claims needed for ticket validation for SmartId.
 *
 * @param crypto crypto backend
 * @param rcpt_id recipient id from the lock (etsi/PNOEE-...)
 * @param session_token the SD-JWT session token from the auth server
 * @param session_cert_b64 session signing certificate (base64url DER)
 * @param scheme_name output: session token schemeName claim
 * @param rp_name output: session token rpName claim
 * @param error output: error description on failure
 * @return error code or OK
 */
result_t validateSessionData(CryptoBackend *crypto, const std::string& rcpt_id, bool is_mid,
                             const std::string& session_token, const std::string& session_cert_b64,
                             std::string& scheme_name, std::string& rp_name, std::string& error);

/**
 * @brief Validate a signed SID/MID auth ticket client-side (S8)
 *
 * Checks that the signing certificate belongs to rcpt_id and that the
 * ACSP_V2 signature verifies. This binds the signer's identity, the consent
 * text shown to the user (interactionsDigest) and the freshness
 * (serverRandom) of the signature before it is presented to share servers.
 *
 * @param crypto crypto backend
 * @param rcpt_id recipient id from the lock (etsi/PNOEE-...)
 * @param ticket the auth ticket (jwt~disclosures...)
 * @param cert_der signing certificate in DER encoding
 * @param signature_params_json the x-cdoc2-sid-rpv3-signature-parameters JSON
 * @param scheme_name schemeName (from the session token claims)
 * @param rp_name rpName (from the session token claims)
 * @param error output: error description on failure
 * @return error code or OK
 */
result_t validateAuthTicket(CryptoBackend *crypto, const std::string& rcpt_id,
                            const std::string& ticket, const std::vector<uint8_t>& cert_der,
                            const std::string& signature_params_json,
                            const std::string& scheme_name, const std::string& rp_name,
                            std::string& error);

/**
 * @brief Validate the RP server's RFC9421 HTTP countersignature (Mobile-ID flow)
 *
 * Reconstructs the signature base from the rp-sig covered components
 * (x-rp-signed-hash, x-rp-name) and verifies the Signature header value with
 * the RP server public key selected by keyid from the server JWKS.
 *
 * @param params the MID signature parameters (HTTP headers from the RP server)
 * @param rp_jwks the RP server JWK Set JSON (from /.well-known/jwks.jws)
 * @param error output: error description on failure
 * @return error code or OK
 */
result_t validateRpHttpSignature(const std::map<std::string, std::string>& params,
                                 const std::string& rp_jwks, std::string& error);

/**
 * @brief Validate a signed Mobile-ID auth ticket client-side (S8)
 *
 * Checks that the signing certificate belongs to rcpt_id, that the phone's
 * ECDSA (ES256) signature verifies over the ticket signing input, that
 * x-rp-signed-hash matches the ticket signature, and that the RP server's
 * RFC9421 HTTP countersignature verifies.
 *
 * @param crypto crypto backend
 * @param rcpt_id recipient id from the lock (etsi/PNOEE-...)
 * @param ticket the auth ticket (jwt~disclosures...)
 * @param cert_der signing certificate in DER encoding
 * @param params the MID signature parameters (HTTP headers from the RP server)
 * @param rp_jwks the RP server JWK Set JSON (from /.well-known/jwks.jws)
 * @param error output: error description on failure
 * @return error code or OK
 */
result_t validateAuthTicketMID(CryptoBackend *crypto, const std::string& rcpt_id,
                               const std::string& ticket, const std::vector<uint8_t>& cert_der,
                               const std::map<std::string, std::string>& params,
                               const std::string& rp_jwks, std::string& error);

} // namespace libcdoc

#endif // KEYSHARES_H
