// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#define __CONFIGURATION_CPP__

#include "Configuration.h"

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
    // N15: std::stoi throws on malformed config values. Use from_chars
    // and fall back to the default instead of crashing.
    int result = 0;
    auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), result);
    if (ec != std::errc{} || ptr != val.data() + val.size())
        return def_val;
    return result;
}

int64_t
libcdoc::Configuration::getInt64(std::string_view param, int64_t def_val) const
{
    std::string val = getValue(param);
    if (val.empty()) return def_val;
    int64_t result = 0;
    auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), result);
    if (ec != std::errc{} || ptr != val.data() + val.size())
        return def_val;
    return result;
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
    std::ifstream ifs(std::filesystem::path(encodeName(file)), std::ios::binary);
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
