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

static std::string decodeName(const std::filesystem::path& path)
{
    auto name = path.u8string();
    return {reinterpret_cast<const char*>(name.data()), name.size()};
}

std::string toBase64(const uint8_t *data, size_t len);
static std::string toBase64(const std::vector<uint8_t> &data) {
    return toBase64(data.data(), data.size());
}

std::string toBase64URL(const std::string& data);
std::string toBase64URL(const uint8_t *data, size_t len);
static std::string toBase64URL(const std::vector<uint8_t> &data) {
    return toBase64URL(data.data(), data.size());
}

std::vector<uint8_t> fromBase64(std::string_view data);
std::vector<uint8_t> fromBase64URL(std::string_view data);

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

/**
 * @brief Parse a bounded non-negative decimal integer
 *
 * Reports failure explicitly: the whole string must be digits and the value
 * must fit in [0, max_value]. Used for security-relevant numeric fields
 * (e.g. the authentication verification code) where a malformed server
 * value must never silently render as 0 (S16).
 *
 * @param str string to parse
 * @param max_value maximum accepted value (inclusive)
 * @param out parsed value on success
 * @return true on success
 */
inline bool
parseBoundedUInt(std::string_view str, int max_value, int& out)
{
    int value = -1;
    auto res = std::from_chars(str.data(), str.data() + str.size(), value);
    if (res.ec != std::errc() || res.ptr != str.data() + str.size() || value < 0 || value > max_value)
        return false;
    out = value;
    return true;
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
split(std::string_view s, char delim = ':') {
    std::vector<std::string> result;
    auto start = s.cbegin();
    for (auto end = s.cbegin(); end != s.cend(); ++end) {
        if (*end == delim) {
            result.push_back(std::string(start, end));
            start = end + 1;
        }
    }
    if (start != s.cend()) {
        result.push_back(std::string(start, s.cend()));
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

/**
 * @brief Sanitise an attacker-controlled file name for safe extraction.
 *
 * @p name comes from a CDoc1/DDoc/CDoc2 archive header and is fully under the
 * control of whoever produced the container. The function strips every
 * filesystem-significant component that could let the path escape the
 * caller-supplied @p base directory or trick a Windows API into doing
 * something other than "create a normal file inside @p base":
 *
 *   - all leading directory components (slashes, backslashes, drive letters),
 *   - "." and ".." segments,
 *   - NUL bytes and other ASCII control characters,
 *   - leading/trailing whitespace and dots (Windows trims these silently),
  *   - reserved Windows device names (CON, PRN, AUX, NUL, COM1..COM9, LPT1..LPT9),
  *   - NTFS Alternate Data Stream separator ':',
  *   - malformed UTF-8,
  *   - excessively long names (capped at 255 bytes after sanitisation, the
  *     practical filename limit on every filesystem libcdoc supports;
  *     truncation respects UTF-8 character boundaries).
 *
 * The returned string is a relative file name (no slashes), or empty if no
 * safe name could be derived. A caller that gets an empty return value MUST
 * either skip the entry or replace it with a generated placeholder; it MUST
 * NOT fall back to the raw @p name. This function does not consult the
 * filesystem; the caller is still expected to verify, after composing
 * @p base / sanitisedName, that the resulting absolute path stays within
 * @p base (e.g. by comparing weakly_canonical(base / safe).parent_path()
 * against weakly_canonical(base)). The two checks are complementary:
 * sanitisation eliminates known-malicious shapes up-front, the post-compose
 * check protects against symlinks pointed at by previously-extracted files.
 *
 * @param name the unsafe input file name
 * @return a relative file name guaranteed not to contain path-traversal
 *         elements, or an empty string when no safe name can be produced.
 */
CDOC_EXPORT std::string sanitiseExtractedFilename(std::string_view name);

/**
 * @brief Parsed components of an ETSI Smart-ID / Mobile-ID recipient identifier.
 *
 * The on-the-wire format used by SK's Smart-ID and Mobile-ID services is
 * @c etsi/PNO<CC>-<NATIONAL-ID>, e.g. @c etsi/PNOEE-30303039914. The
 * @c <CC> field is the ISO-3166-1 alpha-2 country code; the
 * @c <NATIONAL-ID> field is the personal identifier issued by that
 * country (in Estonia: 11 ASCII digits).
 *
 * @ref parseEtsiRecipientId returns this struct after validating the
 * shape of the input; an empty @ref country / @ref national_id pair
 * indicates a parse failure.
 */
struct EtsiRecipientId {
    /// ISO-3166-1 alpha-2 country code (e.g. "EE"). Empty on parse failure.
    std::string country;
    /// National identifier portion (digits only). Empty on parse failure.
    std::string national_id;

    /// Convenience: true iff the input parsed cleanly.
    [[nodiscard]] bool valid() const noexcept {
        return !country.empty() && !national_id.empty();
    }
};

/**
 * @brief Parse an ETSI recipient identifier into its country and national-id parts.
 *
 * The accepted shape is @c etsi/PNO<CC>-<NATIONAL-ID>:
 *
 *   - exactly the literal prefix @c "etsi/PNO";
 *   - exactly two ASCII letters of country code (case-insensitive on input,
 *     normalised to upper case in the result);
 *   - a literal @c '-' separator;
 *   - a non-empty national identifier composed of ASCII digits and at
 *     most 32 characters total (a generous upper bound that comfortably
 *     covers all current SK formats while rejecting megabyte payloads).
 *
 * Returns an @ref EtsiRecipientId with empty fields if any of the above
 * is violated. The function never throws, never logs, and never reads
 * past the end of the input.
 *
 * @param rcpt_id the recipient identifier to parse
 * @return parsed components; check @ref EtsiRecipientId::valid() to test
 */
CDOC_EXPORT EtsiRecipientId parseEtsiRecipientId(std::string_view rcpt_id);

struct urlEncode {
    std::string_view src;
    friend std::ostream& operator<<(std::ostream& escaped, urlEncode src);
};

/**
 * @brief Percent-encode a string for use as a URL path segment or query value
 *
 * RFC 3986 unreserved characters (A-Z a-z 0-9 - _ . ~) are kept as-is,
 * everything else (including space) is percent-encoded. Used to safely
 * interpolate untrusted values (share ids, nonces, transaction ids) into
 * request URLs (S12).
 */
std::string urlEncodeComponent(std::string_view value);

/**
 * @brief Decode the next UTF-8 codepoint from sv at pos, advancing pos past it
 *
 * Returns false on malformed input (bad continuation bytes, truncated
 * sequence, invalid lead byte). Overlong encodings and surrogates are not
 * specially rejected - the input is a localised UI string from
 * configuration, not a security boundary.
 *
 * @param sv the UTF-8 string
 * @param pos current position (advanced past the decoded character)
 * @param cp output codepoint
 * @return true on success
 */
inline bool
decodeUtf8Char(std::string_view sv, size_t& pos, uint32_t& cp) noexcept
{
    uint8_t c = uint8_t(sv[pos]);
    if (c < 0x80) {
        cp = c;
        pos += 1;
        return true;
    }
    size_t extra;
    uint32_t val;
    if ((c & 0xE0) == 0xC0) { extra = 1; val = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { extra = 2; val = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { extra = 3; val = c & 0x07; }
    else return false;
    if (pos + extra >= sv.size()) return false;
    for (size_t i = 1; i <= extra; i++) {
        uint8_t cc = uint8_t(sv[pos + i]);
        if ((cc & 0xC0) != 0x80) return false;
        val = (val << 6) | (cc & 0x3F);
    }
    cp = val;
    pos += extra + 1;
    return true;
}

/**
 * @brief Classify a Unicode codepoint against the GSM 03.38 alphabet
 *
 * Used by the Mobile-ID displayText field:
 *   0 - not representable in GSM-7
 *   1 - GSM-7 basic charset (1 septet)
 *   2 - GSM-7 extension table (2 septets)
 *
 * @param cp Unicode codepoint
 * @return 0, 1 or 2 as above
 */
constexpr int
gsm7CharClass(uint32_t cp) noexcept
{
    switch (cp) {
    // Extension table: ^ { } \ [ ] ~ | € and FF (page break)
    case 0x005E: case 0x007B: case 0x007D: case 0x005C: case 0x005B:
    case 0x005D: case 0x007E: case 0x007C: case 0x20AC: case 0x000C:
        return 2;
    default:
        break;
    }
    if (cp == 0x60) return 0;                 // '`' has no GSM-7 mapping
    if (cp >= 0x20 && cp <= 0x7E) return 1;   // printable ASCII is in the basic set
    switch (cp) {
    case 0x000A: case 0x000D: case 0x001B:     // LF, CR, ESC
    case 0x00A1: case 0x00A3: case 0x00A4: case 0x00A5: case 0x00A7: case 0x00BF:
    case 0x00C4: case 0x00C5: case 0x00C6: case 0x00C7: case 0x00C9:
    case 0x00D1: case 0x00D6: case 0x00D8: case 0x00DC: case 0x00DF:
    case 0x00E0: case 0x00E4: case 0x00E5: case 0x00E6: case 0x00E8:
    case 0x00E9: case 0x00EC: case 0x00F1: case 0x00F2: case 0x00F6:
    case 0x00F8: case 0x00F9: case 0x00FC:
    case 0x0393: case 0x0394: case 0x0398: case 0x039B: case 0x039E:
    case 0x03A0: case 0x03A3: case 0x03A6: case 0x03A8: case 0x03A9:
        return 1;
    default:
        return 0;
    }
}

/**
 * @brief Validate and classify SID/MID display text
 *
 * On success returns OK and sets n_chars (Unicode codepoints), n_ext (chars
 * from the GSM-7 extension table), gsm7 (true if the whole text is GSM-7
 * representable) and bmp (true if all codepoints fit in the Basic
 * Multilingual Plane, i.e. are representable in UCS-2).
 *
 * Returns DATA_FORMAT_ERROR if the input is not valid UTF-8.
 *
 * @param utf8 the display text (UTF-8)
 * @param n_chars output: number of Unicode codepoints
 * @param n_ext output: number of GSM-7 extension-table characters
 * @param gsm7 output: true if fully GSM-7 representable
 * @param bmp output: true if all codepoints are in the BMP (UCS-2 safe)
 * @return OK or DATA_FORMAT_ERROR
 */
inline result_t
classifyDisplayText(std::string_view utf8, size_t& n_chars, size_t& n_ext, bool& gsm7, bool& bmp)
{
    n_chars = 0;
    n_ext = 0;
    gsm7 = true;
    bmp = true;
    for (size_t pos = 0; pos < utf8.size();) {
        uint32_t cp = 0;
        if (!decodeUtf8Char(utf8, pos, cp))
            return DATA_FORMAT_ERROR;
        n_chars++;
        if (cp > 0xFFFF) bmp = false;
        switch (gsm7CharClass(cp)) {
        case 2: n_ext++; break;
        case 0: gsm7 = false; break;
        default: break;
        }
    }
    return OK;
}

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

struct restoreFlags {
    std::ostream& os;
    std::ios_base::fmtflags f;
    restoreFlags(std::ostream &os) : os(os), f(os.flags()) {}
    CDOC_DISABLE_MOVE_COPY(restoreFlags)
    ~restoreFlags() { os.flags(f); }
};

/**
 * @brief Join a base URL with a path suffix, handling trailing slashes.
 *
 * The @p base may or may not end with '/'; the @p suffix must start with
 * '/'. The result always has exactly one '/' between base and suffix.
 *
 * @param base the base URL (e.g. "https://host" or "https://host/")
 * @param suffix the path suffix (e.g. "/key-capsules")
 * @return the joined URL
 */
[[nodiscard]] inline std::string joinUrl(std::string_view base, std::string_view suffix)
{
    std::string result(base);
    if (!result.empty() && result.back() == '/')
        result.pop_back();
    result.append(suffix);
    return result;
}

[[nodiscard]] constexpr auto range_to_sv(auto begin, auto end) noexcept {
    if (begin == end)
        return std::string_view();
    return std::string_view(&*begin, std::ranges::distance(begin, end));
};

[[nodiscard]] constexpr auto range_to_sv(auto range) noexcept {
    return range_to_sv(range.begin(), range.end());
};

#ifndef SWIG
template<typename... Args>
static inline void LogFormat(LogLevel level, std::string_view file, int line, fmt::format_string<Args...> fmt, Args&&... args) noexcept
{
    try {
        libcdoc::log(level, file, line, fmt::format(fmt, std::forward<Args>(args)...));
    } catch (const std::exception&) {
        auto sv = fmt.get();
        libcdoc::log(level, file, line, std::string_view(sv.data(), sv.size()));
    }
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

// LOG_TRACE and LOG_TRACE_KEY are compile-gated by LIBCDOC_CRYPTO_TRACE
// (default OFF). They are intended for debugging cryptographic material and
// other potentially sensitive data. Never use LOG_DBG for secrets — it is
// runtime-gated only and may be enabled in production deployments.
#ifdef LIBCDOC_CRYPTO_TRACE
#define LOG_TRACE(...) LogFormat(libcdoc::LEVEL_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_TRACE_KEY(MSG, KEY) LogFormat(libcdoc::LEVEL_TRACE, __FILE__, __LINE__, MSG, toHex(KEY))
#else
#define LOG_TRACE(...)
#define LOG_TRACE_KEY(MSG, KEY)
#endif

} // namespace libcdoc

#endif // UTILS_H
