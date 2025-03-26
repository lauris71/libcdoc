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

#include <cdoc/CryptoBackend.h>
#include <cdoc/NetworkBackend.h>
#include <cdoc/CDoc.h>

#include <cstdint>
#include <string>
#include <system_error>

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
     * @param base_url share server base url (e.g. https://cdoc2.my.domain/v1/)
     * @param share_id share id from capsule
     * @param nonce session nonce from server
     */
    ShareData(const std::string& base_url, const std::string& share_id, const std::string& nonce);

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
protected:
    NetworkBackend *network;
    /**
     * @brief Construct a new Signer object
     * 
     * @param _rcpt_id Recipient full id in etsi format (ets/PNOEE-XYZXYZXYZXY)
     * @param _algo_name Signing algorithm name (RS256/ES256)
     */
    Signer(const std::string& _rcpt_id, const std::string _algo_name, NetworkBackend *_network) : rcpt_id(_rcpt_id), algo_name(_algo_name), network(_network) {}
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
     * @brief Relying party UUID
     * 
     */
    const std::string rp_uuid;
    /**
     * @brief Relying party name
     * 
     */
    const std::string rp_name;
    /**
     * @brief Construct a new SIDSigner object
     * 
     * @param _url SmartID gateway url
     * @param _rp_uuid Relying party UUID
     * @param _rp_name Relying party name
     * @param _rcpt_id Recipient full id in etsi format (ets/PNOEE-XYZXYZXYZXY)
     */
    SIDSigner(const std::string& _url, const std::string& _rp_uuid, const std::string& _rp_name, const std::string& _rcpt_id, NetworkBackend *network)
    : Signer(_rcpt_id, "RS256", network), url(_url), rp_uuid(_rp_uuid), rp_name(_rp_name) {}

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
     * @brief Relying party UUID
     * 
     */
    const std::string rp_uuid;
    /**
     * @brief Relying party name
     * 
     */
    const std::string rp_name;
    /**
     * @brief Recipient phone number (with country code)
     * 
     */
    const std::string phone;
    /**
     * @brief Construct a new MIDSigner object
     * 
     * @param _url Mobile ID gateway url
     * @param _rp_uuid Relying party UUID
     * @param _rp_name Relying party name
     * @param _rcpt_id Recipient full id in etsi format (ets/PNOEE-XYZXYZXYZXY)
     */
    MIDSigner(const std::string& _url, const std::string& _rp_uuid, const std::string& _rp_name, const std::string& _phone, const std::string& _rcpt_id, NetworkBackend *network)
    : Signer(_rcpt_id, "ES256", network), url(_url), rp_uuid(_rp_uuid), rp_name(_rp_name), phone(_phone) {}

    result_t signDigest(std::vector<uint8_t>& dst, const std::vector<uint8_t>& digest) final;
};

} // namespace libcdoc

#endif // LOCK_H
