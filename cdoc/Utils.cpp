// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
    // jwt::base::details::decode throws std::runtime_error on malformed
    // input (characters outside the alphabet, bad padding, bad length).
    // The decoded data comes from remote servers and containers, i.e. it
    // is untrusted, so a decode failure must not crash the process. An
    // empty result signals a format error to the callers.
    try {
        std::string str = jwt::base::details::decode(data, jwt::alphabet::base64::rdata(), "=");
        return std::vector<uint8_t>(str.cbegin(), str.cend());
    } catch (const std::exception &e) {
        LOG_WARN("fromBase64: invalid base64 input: {}", e.what());
        return {};
    }
}

double
getTime()
{
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

#if defined(_WIN32) || defined(_WIN64)
#define timegm _mkgmtime
#endif

// N17: return -1 on parse failure so callers can distinguish garbage
// from a valid timestamp. Previously a malformed ISO string produced
// an undefined time_t via std::get_time without checking in.fail().
double
timeFromISO(const std::string& iso)
{
    std::istringstream in{iso};
    std::tm t = {};
    in >> std::get_time(&t, "%Y-%m-%dT%T");
    if (in.fail()) return -1;
    // The key server adds fractions of a second, e.g. 2027-04-17T08:52:36.450774506Z
    auto isDigit = [&in] { return in.peek() >= '0' && in.peek() <= '9'; };
    if (in.peek() == '.') {
        in.get();
        if (!isDigit()) return -1;
        while (isDigit()) in.get();
    }
    if (in.get() != 'Z') return -1;
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

libcdoc::Utf8Char
decodeUtf8Char(const uint8_t *data, size_t size)
{
    // Well-formed UTF-8 byte sequences per RFC 3629 / Unicode Standard 3.9
    // (Table 3-7). In particular this rejects overlong encodings (e.g.
    // 0xC0 0xAF for '/'), UTF-16 surrogate halves (U+D800..U+DFFF) and code
    // points above U+10FFFF - all of which are ill-formed and can be used
    // to bypass filters that decode differently.
    Utf8Char ch;
    if (size == 0) return ch;
    const uint8_t *s = data;
    if ((s[0] & 0x80) == 0x0) {
        // 1-byte: U+0000..U+007F
        ch.length = 1;
        ch.codepoint = s[0];
    } else if ((s[0] & 0xe0) == 0xc0) {
        // 2-byte: U+0080..U+07FF; lead 0xC0/0xC1 would be overlong
        if (s[0] < 0xc2 || size < 2 || (s[1] & 0xc0) != 0x80) return ch;
        ch.length = 2;
        ch.codepoint = (char32_t(s[0] & 0x1f) << 6) | char32_t(s[1] & 0x3f);
    } else if ((s[0] & 0xf0) == 0xe0) {
        // 3-byte: U+0800..U+FFFF
        // E0 requires second byte A0..BF (overlong otherwise)
        // ED requires second byte 80..9F (surrogates otherwise)
        if (size < 3) return ch;
        if (s[0] == 0xe0 && s[1] < 0xa0) return ch;
        if (s[0] == 0xed && s[1] > 0x9f) return ch;
        if ((s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80) return ch;
        ch.length = 3;
        ch.codepoint = (char32_t(s[0] & 0x0f) << 12) | (char32_t(s[1] & 0x3f) << 6) | char32_t(s[2] & 0x3f);
    } else if ((s[0] & 0xf8) == 0xf0) {
        // 4-byte: U+10000..U+10FFFF
        // F0 requires second byte 90..BF (overlong otherwise)
        // F4 requires second byte 80..8F (above U+10FFFF otherwise)
        // F5..F7 are always invalid
        if (size < 4) return ch;
        if (s[0] == 0xf0 && s[1] < 0x90) return ch;
        if (s[0] > 0xf4) return ch;
        if (s[0] == 0xf4 && s[1] > 0x8f) return ch;
        if ((s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80 || (s[3] & 0xc0) != 0x80) return ch;
        ch.length = 4;
        ch.codepoint = (char32_t(s[0] & 0x07) << 18) | (char32_t(s[1] & 0x3f) << 12)
                     | (char32_t(s[2] & 0x3f) << 6) | char32_t(s[3] & 0x3f);
    }
    // else: 0x80..0xBF as lead (lone continuation byte), 0xF8..0xFF:
    // not a lead byte of any sequence; return invalid.
    return ch;
}

bool
isValidUtf8 (std::string_view str)
{
    const uint8_t *s = (const uint8_t *) str.data();
    size_t pos = 0;
    while (pos < str.size()) {
        Utf8Char ch = decodeUtf8Char(s + pos, str.size() - pos);
        if (!ch.valid()) return false;
        pos += ch.length;
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
urlEncodeComponent(std::string_view value)
{
    static constexpr char UNRESERVED[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    static constexpr char HEX[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        if (memchr(UNRESERVED, c, sizeof(UNRESERVED) - 1)) {
            out += c;
        } else {
            out += '%';
            out += HEX[(static_cast<unsigned char>(c) >> 4) & 0x0F];
            out += HEX[static_cast<unsigned char>(c) & 0x0F];
        }
    }
    return out;
}

std::string_view
baseNameOf(std::string_view path)
{
    // Split on BOTH '/' and '\\' on every platform: an attacker who crafts
    // a Windows-style path on Linux is still trying to escape, and vice
    // versa. Always take the last non-empty component.
    size_t last_sep = path.find_last_of("\\/");
    return (last_sep == std::string_view::npos) ? path : path.substr(last_sep + 1);
}

std::string_view
trimFilenameEdges(std::string_view component)
{
    while (!component.empty() && (component.back() == '.' || component.back() == ' '))
        component.remove_suffix(1);
    while (!component.empty() && (component.front() == ' ' || component.front() == '\t'))
        component.remove_prefix(1);
    return component;
}

bool
isReservedDeviceName(std::string_view component)
{
    // The check is case-insensitive and applies to the name before the
    // first extension ("nul.tar.gz" is still the NUL device on Windows).
    size_t dot = component.find('.');
    std::string_view stem = component.substr(0, dot);
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
        if (upper == r) return true;
    }
    return false;
}

std::string_view
truncateUtf8(std::string_view s, size_t max_bytes)
{
    if (s.size() <= max_bytes) return s;
    // Find the last UTF-8 codepoint boundary at or before max_bytes.
    // A continuation byte has the pattern 10xxxxxx (0x80-0xBF).
    size_t pos = max_bytes;
    while (pos > 0 && (uint8_t(s[pos]) & 0xC0) == 0x80)
        --pos;
    return s.substr(0, pos);
}

bool
hasControlBytes(std::string_view s)
{
    for (unsigned char c : s) {
        if (c == 0u) return true;               // NUL
        if (c < 0x20u && c != '\t') return true; // ASCII control bytes
    }
    return false;
}

// Code points forbidden in CDoc2 entry names (Unicode control characters,
// RTL override, noncharacters). Tab and DEL count as control characters.
static bool
isForbiddenCodepoint(char32_t cp)
{
    return cp < 0x20u || (cp >= 0x7Fu && cp <= 0x9Fu)
        || cp == 0x202Eu || cp == 0xFFFEu || cp == 0xFFFFu;
}

// Split on the standard separator only. Backslash is never a separator in
// names - it is a suspicious symbol (removed by repairFilename).
static std::vector<std::string_view>
splitPathComponents(std::string_view name)
{
    std::vector<std::string_view> out;
    size_t start = 0;
    while (start <= name.size()) {
        size_t end = name.find('/', start);
        if (end == std::string_view::npos) {
            out.push_back(name.substr(start));
            break;
        }
        out.push_back(name.substr(start, end - start));
        start = end + 1;
    }
    return out;
}

// Cap one name component to max_bytes, keeping a short file extension
// (so "aaa...dat" stays recognisable after truncation).
static std::string
capFilenameComponent(std::string_view base, size_t max_bytes)
{
    if (base.size() <= max_bytes) return std::string(base);
    size_t dot = base.find_last_of('.');
    if (dot != std::string_view::npos &&
        dot > 0 &&
        base.size() - dot < 16) {
        std::string_view ext = base.substr(dot);
        std::string_view stem = base.substr(0, dot);
        std::string_view kept = truncateUtf8(stem, max_bytes - ext.size());
        std::string out;
        out.reserve(kept.size() + ext.size());
        out.append(kept.data(), kept.size());
        out.append(ext.data(), ext.size());
        return out;
    }
    return std::string(truncateUtf8(base, max_bytes));
}

bool
isConformantName(std::string_view name)
{
    // §5.3.1 + house rules (Filename-handling-proposal.md §3).
    if (name.empty() || name.size() > 1000) return false;
    if (name.front() == '/') return false;                          // absolute
    if (name.size() >= 2 && name[1] == ':' &&
        ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')))
        return false;                                               // drive letter
    const uint8_t *p = (const uint8_t *) name.data();
    size_t pos = 0;
    while (pos < name.size()) {
        Utf8Char ch = decodeUtf8Char(p + pos, name.size() - pos);
        if (!ch.valid() || isForbiddenCodepoint(ch.codepoint)) return false;
        pos += ch.length;
    }
    for (std::string_view comp : splitPathComponents(name)) {
        if (comp.empty() || comp == "." || comp == "..") return false;
    }
    return true;
}

bool
hasSuspiciousTraits(std::string_view name)
{
    // Suspicious symbols: `<>:\|?*` and backslash (NTFS ADS, shell
    // globs, CLI options).
    for (unsigned char c : name) {
        if (c < 0x80u && memchr("<>:\\|?*", c, 7) != nullptr) return true;
    }
    for (std::string_view comp : splitPathComponents(name)) {
        if (comp.empty()) continue;
        if (isReservedDeviceName(comp)) return true;
        if (comp.size() > 255) return true;
        // Leading dots make the file hidden on Unix: extraction must
        // never produce dotfiles like ".bashrc".
        if (comp.front() == '.' || comp.front() == ' ' || comp.front() == '-') return true;
        if (comp.back() == '.' || comp.back() == ' ') return true;
    }
    return false;
}

std::string
repairFilename(std::string_view name)
{
    // Pass 1: codepoint level. Ill-formed bytes and forbidden code points
    // become '_', suspicious symbols are removed; '/' survives as the
    // path separator.
    std::string cleaned;
    cleaned.reserve(name.size());
    const uint8_t *p = (const uint8_t *) name.data();
    size_t pos = 0;
    while (pos < name.size()) {
        Utf8Char ch = decodeUtf8Char(p + pos, name.size() - pos);
        if (!ch.valid()) {
            cleaned += '_';
            pos += 1;
        } else if (isForbiddenCodepoint(ch.codepoint)) {
            cleaned += '_';
            pos += ch.length;
        } else {
            char32_t cp = ch.codepoint;
            bool suspicious_symbol = cp == '<' || cp == '>' || cp == ':' || cp == '\\'
                                  || cp == '|' || cp == '?' || cp == '*';
            if (!suspicious_symbol)
                cleaned.append(name.data() + pos, ch.length);
            pos += ch.length;
        }
    }

    // Pass 2: shape confinement plus per-component repair. Empty and "."
    // components are dropped; ".." resolves against the previous component
    // (and is dropped at the root), so the result can never escape.
    std::vector<std::string> parts;
    for (std::string_view comp : splitPathComponents(cleaned)) {
        if (comp.empty() || comp == ".") continue;
        if (comp == "..") {
            if (!parts.empty()) parts.pop_back();
            continue;
        }
        comp = trimFilenameEdges(comp);
        while (!comp.empty() && comp.front() == '-') comp.remove_prefix(1);
        if (comp.empty()) continue;
        // Modifications below need owned storage (comp is a view into
        // cleaned); keep it alive for the rest of the iteration.
        std::string scratch;
        // Hidden names: each leading dot becomes '_' so extraction never
        // produces dotfiles (Unix hidden names like ".bashrc").
        if (comp.front() == '.') {
            scratch.assign(comp);
            for (char& c : scratch) {
                if (c != '.') break;
                c = '_';
            }
            comp = scratch;
        }
        // Prefix reserved devices before capping so the prefix can never
        // be truncated away again. (Constructing from comp first keeps the
        // read valid even when comp already aliases scratch.)
        if (isReservedDeviceName(comp)) {
            scratch = std::string("_") + std::string(comp);
            comp = scratch;
        }
        std::string fixed(capFilenameComponent(comp, 255));
        // Capping can land on a trimmed edge again ("...aaa." style).
        std::string_view retrim = trimFilenameEdges(fixed);
        if (retrim.empty()) continue;
        parts.emplace_back(retrim);
    }

    std::string result;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) result += '/';
        result += parts[i];
    }

    // Whole-name cap (spec: entry names at most 1000 bytes).
    if (result.size() > 1000) {
        result = truncateUtf8(result, 1000);
        while (!result.empty() && (result.back() == '/' || result.back() == '.' || result.back() == ' '))
            result.pop_back();
        // Truncation may expose a reserved device name as the (partial)
        // tail component; drop that component entirely.
        size_t slash = result.find_last_of('/');
        std::string_view last = (slash == std::string::npos) ? std::string_view(result)
                                                             : std::string_view(result).substr(slash + 1);
        if (isReservedDeviceName(last))
            result = (slash == std::string::npos) ? std::string() : result.substr(0, slash);
    }

    return result.empty() ? std::string("unnamed") : result;
}

FilenamePolicy
filenamePolicyFromString(std::string_view value)
{
    if (value == "safe") return FilenamePolicy::Safe;
    if (value == "lenient") return FilenamePolicy::Lenient;
    return FilenamePolicy::Strict;
}

FilenameDecision
applyFilenamePolicy(FilenamePolicy policy, FilenameState& state, std::string_view raw_name)
{
    FilenameDecision d;
    switch (policy) {
    case FilenamePolicy::Lenient:
        // Verbatim pass-through: no validation, no bookkeeping.
        d.name = raw_name;
        return d;
    case FilenamePolicy::Safe:
        d.name = repairFilename(raw_name);
        d.name = deduplicateFilename(state.returned, d.name);
        d.repaired = (d.name != raw_name);
        return d;
    case FilenamePolicy::Strict:
        break;
    }

    // Strict: non-conformant names fail the read and are not returned at
    // all; suspicious-but-conformant names succeed with the returned name
    // repaired. Duplicate raw names are a container violation (fail); a
    // repair that collides with an earlier *returned* name only renames
    // with a " (N)" suffix, because the container itself is conformant.
    if (!isConformantName(raw_name)) {
        d.ok = false;
        d.name.clear();
        return d;
    }
    std::string raw_key = filenameDedupKey(raw_name);
    if (state.raw.contains(raw_key)) {
        d.ok = false;
        d.name.clear();
        return d;
    }
    state.raw.insert(std::move(raw_key));
    d.name = raw_name;
    if (hasSuspiciousTraits(raw_name)) {
        d.name = repairFilename(raw_name);
        d.repaired = true;
    }
    std::string before = d.name;
    d.name = deduplicateFilename(state.returned, d.name);
    d.repaired = d.repaired || (d.name != before);
    return d;
}

std::string
sanitiseExtractedFilename(std::string_view name)
{
    // Sink-side wrapper composing the rule helpers; order matters (trim
    // must run before the "." / ".." and reserved-device checks).
    if (name.empty()) return {};
    if (!isValidUtf8(name)) return {};
    if (hasControlBytes(name)) return {};

    std::string_view base = baseNameOf(name);

    // Reject ':' rather than stripping a possible drive-letter prefix.
    // The Java reference implementation rejects colons too; on Windows
    // they can select a drive or an NTFS alternate data stream.
    if (base.find(':') != std::string_view::npos) return {};

    base = trimFilenameEdges(base);

    // Reject "." and ".." outright. These appear standalone after
    // stripping a leading directory component (e.g. name == "..").
    if (base.empty() || base == "." || base == "..") return {};

    if (isReservedDeviceName(base)) return {};

    // Cap to a sensible byte length. The practical filename limit on
    // every filesystem libcdoc supports is 255 bytes (NTFS, ext4, APFS).
    // A name longer than that would fail filesystem operations anyway;
    // truncating up-front gives a uniform error mode.
    return capFilenameComponent(base, 255);
}

std::string
filenameDedupKey(std::string_view name)
{
    std::string key(name);
    for (auto& c : key) {
        if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    }
    return key;
}

std::string
deduplicateFilename(std::map<std::string, size_t>& seen, const std::string& name)
{
    // Extension: last '.' not at position 0, at most 15 chars, no '/' after
    // it (the name should be pre-sanitized, but be defensive).
    std::string_view stem = name;
    std::string_view ext;
    if (size_t dot = name.find_last_of('.');
        dot != std::string::npos && dot > 0 && name.size() - dot <= 16) {
        stem = std::string_view(name).substr(0, dot);
        ext = std::string_view(name).substr(dot);
    }

    std::string key = filenameDedupKey(name);
    auto [it, inserted] = seen.emplace(key, 1);
    if (inserted) return name;

    // Clash: append " (N)" before the extension, truncating the stem if
    // needed so the result fits in 255 bytes without splitting a UTF-8
    // codepoint.
    for (;;) {
        size_t n = it->second++;
        std::string suffix = " (" + std::to_string(n) + ")";
        size_t max_stem = 255 - suffix.size() - ext.size();
        std::string_view keep = truncateUtf8(stem, max_stem);
        std::string candidate;
        candidate.reserve(keep.size() + suffix.size() + ext.size());
        candidate.append(keep.data(), keep.size());
        candidate.append(suffix);
        candidate.append(ext.data(), ext.size());
        std::string ckey = filenameDedupKey(candidate);
        auto [cit, cinserted] = seen.emplace(ckey, 1);
        if (cinserted) return candidate;
        // The candidate itself exists (e.g. attacker pre-planted "a (1).txt").
        // Try the next number.
    }
}

std::string
uniqueExtractedFilename(std::map<std::string, size_t>& seen, const std::string& name,
                        const std::filesystem::path& base_dir, bool allow_overwrite,
                        const std::vector<std::filesystem::path>& created)
{
    std::string candidate = deduplicateFilename(seen, name);
    for (;;) {
        std::error_code ec;
        std::filesystem::path probe = base_dir / std::filesystem::path(encodeName(candidate));
        if (!std::filesystem::exists(probe, ec) || ec) return candidate;
        // The name collides on this filesystem even after the in-memory
        // dedup - byte-different names fold together (NFC/NFD on APFS,
        // case on NTFS). Files created during this run are never
        // overwritten; pre-existing files only when explicitly allowed.
        bool created_here = false;
        for (const auto& c : created) {
            std::error_code ec2;
            if (std::filesystem::equivalent(probe, c, ec2) && !ec2) {
                created_here = true;
                break;
            }
        }
        if (!created_here && allow_overwrite) return candidate;
        candidate = deduplicateFilename(seen, candidate);
    }
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

