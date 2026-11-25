// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef __LIBCDOC_WINBACKEND_H__
#define __LIBCDOC_WINBACKEND_H__

#include <cdoc/CryptoBackend.h>

#include <memory>

namespace libcdoc {

/**
 * @brief A convenience class for Windows NCrypt cryptographic operations
 *
 * It has default implementations of all CryptoBackend methods. Instead the user has to implement
 * connectToKey method. The latter should find the correct private or secret key for the lock and
 * then call useKey to load the key.
 */
struct CDOC_EXPORT WinBackend : public CryptoBackend {
    /**
     * @brief Load the actual private key
     * 
     * Loads the key internally for subsequent cryptographic operations.
     * @param name the name of key
     * @param pin key pin
     * @return result_t error code ot OK
     */
    result_t useKey(const std::string& name, const std::string& pin);

    /**
     * @brief loads key for encryption/decryption
     *
     * A method to load the correct private/secret key for given capsule or reciever. The subclass implementation should
     * use useKey with proper name.
     * @param idx lock or recipient index (0-based) in CDoc container
     * @param priv whether to connect to private or secret key
     * @return error code or OK
     */
    virtual result_t connectToKey(int idx, bool priv) = 0;

    virtual result_t decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx);
    virtual result_t deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string &digest,
								 const std::vector<uint8_t> &algorithm_id, const std::vector<uint8_t> &party_uinfo,
                                 const std::vector<uint8_t> &party_vinfo, unsigned int idx);
    virtual result_t deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &salt, unsigned int idx);

    virtual result_t sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, unsigned int idx);

    WinBackend(const std::string& provider);
    virtual ~WinBackend();
private:
	struct Private;
	std::unique_ptr<Private> d;
};

} // namespace libcdoc

#endif
