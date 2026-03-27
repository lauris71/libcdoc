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

std::map<std::string, std::string>
Lock::parseLabel(const std::string& label)
{
    std::map<std::string, std::string> parsed_label;
    // Check if provided label starts with the machine generated label prefix.
    if (!label.starts_with(CDoc2::LABELPREFIX))
    {
        return parsed_label;
    }

    std::string label_wo_prefix(label.substr(CDoc2::LABELPREFIX.size()));

    // Label to be processed
    std::string label_to_prcss;

    // We ignore mediatype part

    // Check, if the label is Base64 encoded
    auto base64IndPos = label_wo_prefix.find(CDoc2::LABELBASE64IND);
    if (base64IndPos == std::string::npos)
    {
        if (label_wo_prefix.starts_with(",")) {
            label_to_prcss = label_wo_prefix.substr(1);
        } else {
            label_to_prcss = std::move(label_wo_prefix);
        }
    }
    else
    {
        std::string base64_label(label_wo_prefix.substr(base64IndPos + CDoc2::LABELBASE64IND.size()));
        label_to_prcss = jwt::base::decode<jwt::alphabet::base64>(base64_label);
    }

    auto label_parts(split(label_to_prcss, '&'));
    for (auto& part : label_parts)
    {
        auto label_data_parts(split(part, '='));
        if (label_data_parts.size() != 2)
        {
            // Invalid label data. We just ignore them.
            LOG_ERROR("The label '{}' is invalid", label);
        }
        else
        {
            std::string key = urlDecode(label_data_parts[0]);
            std::string value = urlDecode(label_data_parts[1]);
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
            parsed_label[key] = value;
        }
    }

    return parsed_label;
}

} // namespace libcdoc

