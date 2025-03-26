#define __CONFIGURATION_CPP__

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

#include "Configuration.h"

#include "ILogger.h"
#include "Utils.h"

#include "json/picojson/picojson.h"

#include <sstream>

namespace libcdoc {

bool
libcdoc::Configuration::getBoolean(std::string_view param, bool def_val) const
{
	std::string val = getValue(param);
    if (val.empty()) return def_val;
	return val == "true";
}

int
libcdoc::Configuration::getInt(std::string_view param, int def_val) const
{
    std::string val = getValue(param);
    if (val.empty()) return def_val;
    return std::stoi(val);
}

struct JSONConfiguration::Private {
    picojson::object root = {};
};

JSONConfiguration::JSONConfiguration()
: d(new Private())
{
}

JSONConfiguration::JSONConfiguration(std::istream& ifs)
: d(new Private())
{
    parse(ifs);
}

JSONConfiguration::JSONConfiguration(const std::string& file)
: d(new Private())
{
    parse(file);
}

JSONConfiguration::JSONConfiguration(const std::vector<uint8_t>& data)
: d(new Private())
{
    parse(data);
}

JSONConfiguration::~JSONConfiguration()
{
    delete d;
}

bool
JSONConfiguration::parse(std::istream& ifs)
{
    picojson::value val;
    ifs >> val;
    std::string err = picojson::get_last_error();
    if(!err.empty()) {
        LOG_ERROR("Error parsing configuration: {}", err);
        return false;
    }
    if(!val.is<picojson::object>()) {
        LOG_ERROR("Configuration file is not JSON object");
        return false;
    }
    d->root = val.get<picojson::object>();
    return true;
}

bool
JSONConfiguration::parse(const std::string& file)
{
    std::ifstream ifs(file, std::ios::binary);
    if (ifs.bad()) {
        LOG_ERROR("Cannot open {}", file);
        return false;
    }
    return parse(ifs);
}

bool
JSONConfiguration::parse(const std::vector<uint8_t>& data)
{
    std::stringstream ss(std::string((const char *)data.data(), data.size()));
    return parse(ss);
}

std::string
JSONConfiguration::getValue(std::string_view domain, std::string_view param) const
{
    LOG_DBG("getValue {} {}", domain, param);
    if (!domain.empty()) {
        if (d->root.contains(std::string(domain))) {
            picojson::value val = d->root.at(std::string(domain));
            if (!val.is<picojson::object>()) {
                LOG_ERROR("Configuration entry {} is not an object", domain);
                return {};
            }
            val = val.get(std::string(param));
            LOG_DBG("Value {}", val.serialize());
            if (val.is<std::string>()) return val.get<std::string>();
            return val.serialize();
        } else {
            return {};
        }
    }
    if (!d->root.contains(std::string(param))) return {};
    picojson::value val = d->root.at(std::string(param));
    LOG_DBG("Value {}", val.serialize());
    if (val.is<std::string>()) return val.get<std::string>();
    return val.serialize();
}

}
