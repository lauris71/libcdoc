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

#ifndef __LIBCDOC_UTILS_H__
#define __LIBCDOC_UTILS_H__

#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef __cpp_lib_format
#include <format>
namespace fmt = std;
#else
#define FMT_HEADER_ONLY
#include "fmt/format.h"
#endif

#include <CDoc.h>

#define FORMAT fmt::format

namespace libcdoc {

static auto encodeName(std::string_view path)
{
    return std::u8string_view(reinterpret_cast<const char8_t*>(path.data()), path.size());
}

std::string toBase64(const uint8_t *data, size_t len);

static std::string toBase64(const std::vector<uint8_t> &data) {
    return toBase64(data.data(), data.size());
}

std::vector<uint8_t> fromBase64(const std::string& data);

template <typename F>
static std::string toHex(const F &data)
{
    std::stringstream os;
    os << std::hex << std::uppercase << std::setfill('0');
    for(const auto &i: data)
        os << std::setw(2) << (static_cast<int>(i) & 0xFF);
    return os.str();
}

static constexpr bool fromHex(auto pos, auto end, auto& val)
{
    if(std::distance(pos, end) < 2)
        return false;
    auto p = std::to_address(pos);
    return std::from_chars(p, p + 2, val, 16).ec == std::errc{};
}

static std::vector<uint8_t>
fromHex(std::string_view hex) {
    std::vector<uint8_t> val;
    if((hex.size() % 2) != 0)
        return val;
    val.resize(hex.size() / 2);
    auto p = val.begin();
    for (auto i = hex.cbegin(), end = hex.cend(); p != val.end() && fromHex(i, end, *p); i += 2, ++p);
    return val;
}

static std::vector<std::string>
split(const std::string &s, char delim = ':') {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;
    while (getline (ss, item, delim)) {
        result.push_back (item);
    }
    return result;
}

static std::string
join(const std::vector<std::string> &parts, const std::string_view sep)
{
	std::string result;
    for (const auto& part : parts) {
		if (part != parts.front()) result += sep;
		result += part;
	}
    return result;
}

std::vector<std::string> JsonToStringArray(std::string_view json);

// Get time in seconds since the Epoch

double getTime();
double timeFromISO(const std::string& iso);
std::string timeToISO(time_t time);

bool isValidUtf8 (std::string str);

static std::vector<uint8_t>
readAllBytes(std::string_view filename)
{
    std::vector<uint8_t> dst;
    std::filesystem::path path(filename);
    if (std::error_code ec; !std::filesystem::exists(path, ec)) {
        std::cerr << "readAllBytes(): File '" << filename << "' does not exist" << std::endl;
        return dst;
    }
    std::ifstream ifs(path, std::ios_base::binary);
    if (!ifs) {
        std::cerr << "readAllBytes(): Opening '" << filename << "' failed." << std::endl;
        return dst;
    }
    std::array<uint8_t, 4096> b;
    while (!ifs.eof()) {
        ifs.read((char *) b.data(), b.size());
        if (ifs.bad()) return {};
        dst.insert(dst.end(), b.begin(), std::next(b.begin(), ifs.gcount()));
    }
    return dst;
}

int parseURL(const std::string& url, std::string& host, int& port, std::string& path, bool end_with_slash = false);
std::string buildURL(const std::string& host, int port);

struct urlEncode {
    std::string_view src;
    friend std::ostream& operator<<(std::ostream& escaped, urlEncode src);
};

std::vector<uint8_t> toUint8Vector(const auto* data)
{
    return {data->cbegin(), data->cend()};
}

std::vector<uint8_t> toUint8Vector(const auto& data)
{
    return {data.cbegin(), data.cend()};
}

static std::string
urlDecode(std::string_view src)
{
    std::string ret;
    ret.reserve(src.size());
    uint8_t value = 0;

    for (auto it = src.cbegin(), end = src.cend(); it != end; ++it) {
        switch (*it)
        {
        case '+':
            ret += ' ';
            break;
        case '%':
            if (fromHex(it + 1, end, value)) {
                ret += char(value);
                std::advance(it, 2);
                continue;
            }
            [[fallthrough]];
        default:
            ret += *it;
        }
    }

    return ret;
}

#ifndef SWIG
template<typename... Args>
static inline void LogFormat(LogLevel level, std::string_view file, int line, fmt::format_string<Args...> fmt, Args&&... args)
{
    auto msg = fmt::format(fmt, std::forward<Args>(args)...);
    libcdoc::log(level, file, line, msg);
}

static inline void LogFormat(LogLevel level, std::string_view file, int line, std::string_view msg)
{
    libcdoc::log(level, file, line, msg);
}
#endif

#define LOG(l,...) LogFormat((l), __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) LogFormat(libcdoc::LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...) LogFormat(libcdoc::LEVEL_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...) LogFormat(libcdoc::LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DBG(...) LogFormat(libcdoc::LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#ifdef NDEBUG
#define LOG_TRACE(...)
#define LOG_TRACE_KEY(MSG, KEY)
#else
#define LOG_TRACE(...) LogFormat(libcdoc::LEVEL_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_TRACE_KEY(MSG, KEY) LogFormat(libcdoc::LEVEL_TRACE, __FILE__, __LINE__, MSG, toHex(KEY))
#endif

} // namespace libcdoc

#endif // UTILS_H
