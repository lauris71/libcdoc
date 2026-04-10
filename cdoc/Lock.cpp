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

#include "CDoc2.h"
#include "Utils.h"

#include "json/base.h"

#include <ranges>

namespace libcdoc {

std::string
Lock::getString(Params key) const
{
    if (params.contains(key)) {
        const std::vector<uint8_t>& bytes = params.at(key);
        return {(const char *) bytes.data(), bytes.size()};
    }
    return {};
}

int32_t
Lock::getInt(Params key) const
{
	int32_t val = 0;
    if (params.contains(key)) {
        const std::vector<uint8_t>& bytes = params.at(key);
        for (int i = 0; (i < bytes.size()) && (i < 4); i++) {
            val = (val << 8) | bytes.at(i);
        }
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

std::map<std::string, std::string>
Lock::parseLabel(const std::string& label)
{
    std::map<std::string, std::string> parsed_label;
    // Check if provided label starts with the machine generated label prefix.
    if (!label.starts_with(CDoc2::LABELPREFIX)) {
        return parsed_label;
    }

    auto label_wo_prefix = std::string_view(label).substr(CDoc2::LABELPREFIX.size());

    // Label to be processed
    std::string decodedBase64; // Strong ref
    std::string_view label_to_prcss;

    // We ignore mediatype part

    // Check, if the label is Base64 encoded
    if (auto base64IndPos = label_wo_prefix.find(CDoc2::LABELBASE64IND);
        base64IndPos != std::string::npos)
    {
        std::string base64_label(label_wo_prefix.substr(base64IndPos + CDoc2::LABELBASE64IND.size()));
        decodedBase64 = jwt::base::decode<jwt::alphabet::base64>(base64_label);
        label_to_prcss = decodedBase64;
    } else if (label_wo_prefix.starts_with(",")) {
        label_to_prcss = label_wo_prefix.substr(1);
    } else {
        label_to_prcss = label_wo_prefix;
    }

    auto range_to_sv = [](auto range) constexpr {
        return std::string_view(&*range.begin(), std::ranges::distance(range));
    };
    for (const auto &part : std::ranges::split_view(label_to_prcss, '&'))
    {
        auto label_data_parts = std::ranges::split_view(part, '=');
        if (label_data_parts.empty()) {
            LOG_ERROR("The label '{}' is invalid", label);
            continue;
        }
        auto it = label_data_parts.begin();
        std::string key = urlDecode(range_to_sv(*it));
        std::ranges::transform(key, key.begin(), [](unsigned char c){ return std::tolower(c); });
        ++it;
        std::string value = urlDecode(range_to_sv(*it));
        parsed_label[std::move(key)] = std::move(value);
    }

    return parsed_label;
}

} // namespace libcdoc

