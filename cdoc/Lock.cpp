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

#include "Lock.h"

#include "Certificate.h"
#include "Utils.h"
#include "ILogger.h"

namespace libcdoc {

std::string
Lock::getString(Params key) const
{
	const std::vector<uint8_t>& bytes = params.at(key);
	return std::string((const char *) bytes.data(), bytes.size());
}

int32_t
Lock::getInt(Params key) const
{
	const std::vector<uint8_t>& bytes = params.at(key);
	int32_t val = 0;
	for (int i = 0; (i < bytes.size()) && (i < 4); i++) {
		val = (val << 8) | bytes.at(i);
	}
	return val;
}

void
Lock::setInt(Params key, int32_t val)
{
	std::vector<uint8_t> bytes(4);
	for (int i = 0; i < 4; i++) {
		bytes[3 - i] = (val & 0xff);
		val = val >> 8;
	}
	params[key] = std::move(bytes);
}

bool
Lock::hasTheSameKey(const Lock& other) const
{
	if (!isPKI()) return false;
	if (!other.isPKI()) return false;
	if (!params.contains(Params::RCPT_KEY)) return false;
	if (!other.params.contains(Params::RCPT_KEY)) return false;
	std::vector<uint8_t> pki = getBytes(Params::RCPT_KEY);
	if (pki.empty()) return false;
	std::vector<uint8_t> other_pki = other.getBytes(Params::RCPT_KEY);
	if (other_pki.empty()) return false;
	return pki == other_pki;
}

bool
Lock::hasTheSameKey(const std::vector<uint8_t>& public_key) const
{
	if (!isPKI()) return false;
	if (!params.contains(Params::RCPT_KEY)) return false;
	if (public_key.empty()) return false;
	std::vector<uint8_t> pki = getBytes(Params::RCPT_KEY);
	LOG_DBG("Lock key: {}", toHex(pki));
	if (pki.empty()) return false;
	return pki == public_key;
}

void
Lock::setCertificate(const std::vector<uint8_t> &_cert)
{
	setBytes(Params::CERT, _cert);
	Certificate ssl(_cert);
	std::vector<uint8_t> pkey = ssl.getPublicKey();
	Certificate::Algorithm algo = ssl.getAlgorithm();

	setBytes(Params::RCPT_KEY, pkey);
	pk_type = (algo == libcdoc::Certificate::RSA) ? PKType::RSA : PKType::ECC;
}

} // namespace libcdoc

