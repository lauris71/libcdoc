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

#include "json/base.h"
#include "json/picojson/picojson.h"

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

#if defined(_WIN32) || defined(_WIN64)
#define timegm _mkgmtime
#endif

double
timeFromISO(const std::string& iso)
{
    std::istringstream in{iso};
    std::tm t = {};
    in >> std::get_time(&t, "%Y-%m-%dT%TZ");
    return timegm(&t);
}

std::string
timeToISO(time_t time)
{
#ifdef __cpp_lib_format
    auto expiry_tp = std::chrono::system_clock::from_time_t(time);
    return std::format("{:%FT%TZ}", expiry_tp);
#else
    std::string buf = "0000-00-00T00:00:00Z";
    strftime(buf.data(), buf.size() + 1, "%FT%TZ", gmtime(&time));
    return buf;
#endif
}

bool
isValidUtf8 (std::string str)
{
    const uint8_t *s = (const uint8_t *) str.data();
    const uint8_t *e = s + str.size();
    while (s < e) {
        size_t s_len = e - s;
        if ((s[0] & 0x80) == 0x0) {
            s += 1;
        } else if (((s[0] & 0xe0) == 0xc0) && (s_len >= 2) && ((s[1] & 0xc0) == 0x80)) {
            s += 2;
        } else if (((*s & 0xf0) == 0xe0) && (s_len >= 3) && ((s[1] & 0xc0) == 0x80) && ((s[2] & 0xc0) == 0x80)) {
            s += 3;
        } else if (((*s & 0xf8) == 0xf0) && (s_len >= 4) && ((s[1] & 0xc0) == 0x80) && ((s[2] & 0xc0) == 0x80) && ((s[3] & 0xc0) == 0x80)) {
            s += 4;
        } else {
            return false;
        }
    }
	return true;
}

int
parseURL(const std::string& url, std::string& host, int& port, std::string& path, bool end_with_slash)
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
    if (end_with_slash) {
        if (!path.ends_with('/')) path = path + '/';
    } else {
        if (path.ends_with('/')) path.resize(path.size() - 1);
    }
    return OK;
}

std::string
buildURL(const std::string& host, int port)
{
    return std::string("https://") + host + ":" + std::to_string(port) + "/";
}

std::ostream&
operator<<(std::ostream& escaped, urlEncode src)
{
    escaped.fill('0');
    escaped << std::hex;

    for (auto c : src.src) {
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
    return escaped;
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

