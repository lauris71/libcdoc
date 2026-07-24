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
#include <locale>

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
fromBase64(std::string_view data)
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
    int pssl;
    if (!OSSL_HTTP_parse_url(url.c_str(),
                             &pssl,
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
    if (!pssl) {
        OPENSSL_free(phost);
        OPENSSL_free(ppath);
        LOG_ERROR("URL scheme must be https: {}", url);
        return libcdoc::CONFIGURATION_ERROR;
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
    static const std::locale locC("C");
    restoreFlags rf(escaped);
    escaped.fill('0');
    escaped << std::hex;

    for (auto c : src.src) {
        if (c == ' ') {
            escaped << '+';
            continue;
        }
        // Keep alphanumeric and other accepted characters intact
        if (std::isalnum(c, locC) || c == '-' || c == '_' || c == '.' || c == '~') {
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

EtsiRecipientId
parseEtsiRecipientId(std::string_view rcpt_id)
{
    constexpr std::string_view kPrefix{"etsi/PNO"};
    constexpr size_t kCountryCodeLen = 2;
    constexpr size_t kSeparatorLen = 1;
    constexpr size_t kMaxNationalIdLen = 32;

    // Need at least: prefix + 2 country chars + '-' + 1 id digit.
    if (rcpt_id.size() < kPrefix.size() + kCountryCodeLen + kSeparatorLen + 1) {
        return {};
    }
    if (rcpt_id.substr(0, kPrefix.size()) != kPrefix) {
        return {};
    }

    std::string_view cc = rcpt_id.substr(kPrefix.size(), kCountryCodeLen);
    for (char c : cc) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
            return {};
        }
    }

    if (rcpt_id[kPrefix.size() + kCountryCodeLen] != '-') {
        return {};
    }

    std::string_view nat_id = rcpt_id.substr(kPrefix.size() + kCountryCodeLen + kSeparatorLen);
    if (nat_id.empty() || nat_id.size() > kMaxNationalIdLen) {
        return {};
    }
    for (char c : nat_id) {
        if (c < '0' || c > '9') {
            return {};
        }
    }

    EtsiRecipientId out;
    out.country.reserve(kCountryCodeLen);
    for (char c : cc) {
        out.country.push_back(char((c >= 'a' && c <= 'z') ? (c - 'a' + 'A') : c));
    }
    out.national_id.assign(nat_id);
    return out;
}

std::string
sanitiseExtractedFilename(std::string_view name)
{
    // 1. Reject anything whose UTF-8 is malformed or contains NUL/control
    //    characters. NUL is particularly dangerous: many Windows APIs
    //    truncate at NUL while the filesystem treats the full name, which
    //    has historically been used to mask malicious extensions.
    if (name.empty()) return {};
    for (unsigned char c : name) {
        if (c == 0u) return {};
        if (c < 0x20u && c != '\t') return {};   // strip ASCII control bytes
    }

    // 2. Strip every directory component. We split on BOTH '/' and '\\'
    //    on every platform: an attacker who crafts a Windows-style path on
    //    Linux is still trying to escape, and vice versa. We always take
    //    the last non-empty component.
    size_t last_sep = name.find_last_of("\\/");
    std::string_view base = (last_sep == std::string_view::npos)
                                ? name
                                : name.substr(last_sep + 1);

    // 3. Reject Windows drive-letter prefixes that survived the slash split
    //    (e.g. "C:foo.txt" with no slash is drive-relative on Windows and
    //    refers to the current directory of drive C:, NOT the current
    //    working directory). We strip "X:" if the prefix looks like one.
    if (base.size() >= 2 && base[1] == ':' &&
        ((base[0] >= 'A' && base[0] <= 'Z') ||
         (base[0] >= 'a' && base[0] <= 'z'))) {
        base = base.substr(2);
    }

    // 4. Trim trailing dots and whitespace. Windows silently strips these
    //    when creating files, so "evil.exe.." resolves to "evil.exe" and
    //    can collide with or hide a legitimate file. Trim leading
    //    whitespace too, for symmetry.
    while (!base.empty() && (base.back() == '.' || base.back() == ' '))
        base.remove_suffix(1);
    while (!base.empty() && (base.front() == ' ' || base.front() == '\t'))
        base.remove_prefix(1);

    // 5. Reject "." and ".." outright. These appear standalone after
    //    stripping a leading directory component (e.g. name == "..").
    if (base.empty() || base == "." || base == "..") return {};

    // 6. Reject reserved Windows device names. The check is case-insensitive
    //    and applies to both the bare name and the name before any extension.
    {
        size_t dot = base.find('.');
        std::string_view stem = base.substr(0, dot);
        std::string upper(stem.size(), '\0');
        for (size_t i = 0; i < stem.size(); ++i) {
            unsigned char ch = uint8_t(stem[i]);
            upper[i] = char((ch >= 'a' && ch <= 'z') ? (ch - 'a' + 'A') : ch);
        }
        static constexpr std::string_view reserved[] = {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5",
            "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
            "LPT6", "LPT7", "LPT8", "LPT9",
        };
        for (const auto &r : reserved) {
            if (upper == r) return {};
        }
    }

    // 7. Cap to a sensible byte length. The practical filename limit on
    //    every filesystem libcdoc supports is 255 bytes (NTFS, ext4, APFS).
    //    A name longer than that would fail filesystem operations anyway;
    //    truncating up-front gives a uniform error mode. We truncate from
    //    the end while keeping the file extension if there is one.
    constexpr size_t MAX_BYTES = 255;
    if (base.size() > MAX_BYTES) {
        size_t dot = base.find_last_of('.');
        if (dot != std::string_view::npos &&
            dot > 0 &&
            base.size() - dot < 16) {
            // Preserve a short extension; truncate the stem.
            std::string_view ext = base.substr(dot);
            std::string_view stem = base.substr(0, dot);
            size_t keep_stem = MAX_BYTES - ext.size();
            std::string out;
            out.reserve(MAX_BYTES);
            out.assign(stem.data(), keep_stem);
            out.append(ext.data(), ext.size());
            return out;
        }
        return std::string(base.substr(0, MAX_BYTES));
    }

    return std::string(base);
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

