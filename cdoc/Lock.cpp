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

} // namespace libcdoc

