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

#ifndef SSLCERTIFICATE_H
#define SSLCERTIFICATE_H

#include "utils/memory.h"

#include <string>
#include <vector>

using X509 = struct x509_st;

namespace libcdoc {

class Certificate {
public:
	enum Algorithm : unsigned char {
		RSA,
		ECC
	};

    enum EIDType : unsigned char {
        Unknown,
        IDCard,
        DigiID,
        DigiID_EResident
    };

    explicit Certificate(const std::vector<uint8_t>& data);

    std::string getName(int NID) const;
    std::string getCommonName() const;
    std::string getGivenName() const;
    std::string getSurname() const;
    std::string getSerialNumber() const;

    EIDType getEIDType() const;

	std::vector<uint8_t> getPublicKey() const;
    Algorithm getAlgorithm() const;
    time_t getNotAfter() const;

    std::vector<uint8_t> getDigest() const;

    X509* handle() const noexcept { return cert.get(); }
    operator bool() const noexcept { return cert.operator bool(); };

private:
    unique_free_t<X509> cert;
};

} // Namespace

#endif // SSLCERTIFICATE_H
