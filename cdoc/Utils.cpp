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

#include "Utils.h"

#include "ILogger.h"

#include "json/jwt.h"
#include "json/picojson/picojson.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/evp.h>
#include <openssl/http.h>

#include <charconv>
#include <chrono>

namespace libcdoc {

std::string
toBase64(const uint8_t *data, size_t len)
{
    std::string result(((len + 2) / 3) * 4, 0);
    int size = EVP_EncodeBlock((uint8_t *) result.data(), data, int(len));
    result.resize(size);
    return result;
}

std::vector<uint8_t>
fromBase64(const std::string& data)
{
    std::string str = jwt::base::details::decode(data, jwt::alphabet::base64::rdata(), "=");
    return std::vector<uint8_t>(str.cbegin(), str.cend());
}

double
getTime()
{
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

int
parseURL(const std::string& url, std::string& host, int& port, std::string& path)
{
    char *phost, *ppath;
    int pport;
    if (!OSSL_HTTP_parse_url(url.c_str(),
                             nullptr, // SSL
                             nullptr, // user
                             &phost,
                             nullptr, // port (str)
                             &pport,
                             &ppath,
                             nullptr, // query
                             nullptr // frag
        )) {
        return libcdoc::DATA_FORMAT_ERROR;
    }
    host = phost;
    port = pport;
    path = ppath;
    OPENSSL_free(phost);
    OPENSSL_free(ppath);
    return OK;
}

std::string
buildURL(const std::string& host, int port)
{
    return std::string("https://") + host + ":" + std::to_string(port) + "/";
}

std::string
urlEncode(std::string_view src)
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (auto c : src) {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }
        // Any other characters are percent-encoded
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char) c);
        escaped << std::nouppercase;
    }
    return escaped.str();
}

std::string
urlDecode(const std::string &src)
{
    std::string ret;
    ret.reserve(src.size());
    uint8_t value = 0;

    for (auto it = src.begin(), end = src.end(); it != end; ++it) {
        if (*it == '%' && std::distance(it, end) >= 3 &&
            std::isxdigit(*(it + 1)) && std::isxdigit(*(it + 2))) {
            auto result = std::from_chars(&*(it + 1), &*(it + 3), value, 16);
            if (result.ec == std::errc()) {
                ret += char(value);
                std::advance(it, 2);
                continue;
            }
        }
        ret += *it;
    }

    return ret;
}

std::vector<std::string>
JsonToStringArray(std::string_view json)
{
    std::vector<std::string> values;
    picojson::value val;
    std::string err;
    picojson::parse(val, json.data(), json.data() + json.size(), &err);
    if (!err.empty()) {
        LOG_WARN("String is not valid JSON: {}", std::string(json));
        return values;
    }
    if (!val.is<picojson::array>()) {
        LOG_WARN("String is not valid JSON array: {}", std::string(json));
        return values;
    }
    picojson::array arr = val.get<picojson::array>();
    for (auto s : arr) {
        if (!s.is<std::string>()) {
            LOG_WARN("Value is not valid JSON string: {}", s.serialize());
            return values;
        }
        values.push_back(s.get<std::string>());
    }
    return values;
}

} // Namespace libcdoc

