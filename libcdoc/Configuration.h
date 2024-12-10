#ifndef __CONFIGURATION_H__
#define __CONFIGURATION_H__

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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <libcdoc/Exports.h>

#include <string>

namespace libcdoc {

/**
 * @brief A configuration provider.
 * Subclasses can implement different configuration systems (registry, .ini files etc.) by overriding getValue.
 */
struct CDOC_EXPORT Configuration {
	static constexpr std::string_view USE_KEYSERVER = "USE_KEYSERVER";
    static constexpr std::string_view KEYSERVER_ID = "KEYSERVER_ID";
    static constexpr std::string_view KEYSERVER_HOST = "KEYSERVER_HOST";
    static constexpr std::string_view KEYSERVER_SEND_PORT = "KEYSERVER_SEND_PORT";
    static constexpr std::string_view KEYSERVER_FETCH_PORT = "KEYSERVER_FETCH_PORT";

	Configuration() = default;
	virtual ~Configuration() = default;

    virtual std::string getValue(const std::string_view& param) = 0;

    bool getBoolean(const std::string_view& param, bool def_val = false);
    int getInt(const std::string_view& param, int def_val = 0);

	Configuration (const Configuration&) = delete;
	Configuration& operator= (const Configuration&) = delete;
};

} // namespace libcdoc

#endif // CONFIGURATION_H
