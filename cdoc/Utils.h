// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef __LIBCDOC_UTILS_H__
#define __LIBCDOC_UTILS_H__

#include "Exports.h"

#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
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

std::vector<uint8_t> fromBase64(std::string_view data);

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
    if((hex.size() % 2) != 0 || hex.find_first_not_of("0123456789abcdefABCDEF") != std::string_view::npos)
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

/**
 * @brief Result of decoding a single UTF-8 sequence.
 *
 * Returned by decodeUtf8Char(). The zero-length default state means "the
 * bytes at the cursor are not a well-formed UTF-8 character".
 */
struct Utf8Char {
    /// Bytes consumed: 1..4 for a well-formed sequence, 0 when invalid.
    size_t length = 0;
    /// Decoded code point (U+0000..U+10FFFF); meaningful only if valid().
    char32_t codepoint = 0;

    bool valid() const { return length > 0; }
};

/**
 * @brief Decode the single UTF-8 character at the start of [data, data+size).
 *
 * Enforces the well-formed byte sequences from RFC 3629 / Unicode Standard
 * 3.9 (Table 3-7): rejects overlong encodings (e.g. 0xC0 0xAF for '/'),
 * UTF-16 surrogate halves (U+D800..U+DFFF) and code points above U+10FFFF.
 * All of these are ill-formed and can bypass filters that decode them
 * differently, so repair/validity code must classify them as invalid.
 *
 * This is the per-character primitive behind isValidUtf8(); string-repair
 * code walks a buffer with it to replace ill-formed runs byte-by-byte and
 * to filter decoded code points (control characters etc.). On invalid
 * input nothing is consumed (length == 0), so the caller decides how many
 * bytes to replace/skip before retrying.
 *
 * @param data start of the input span (may be null only when size == 0)
 * @param size number of available bytes
 * @return the decoded character, or length 0 if invalid
 */
Utf8Char decodeUtf8Char(const uint8_t *data, size_t size);

/**
 * @brief Check that the whole string is well-formed UTF-8 (RFC 3629).
 *
 * Implemented as repeated decodeUtf8Char() calls; use the primitive
 * directly when repairing or classifying individual characters.
 */
bool isValidUtf8 (std::string_view str);

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
/**
 * @brief Last path component of @p path, ignoring directory parts.
 *
 * Splits on BOTH '/' and '\\' on every platform: an attacker who crafts a
 * Windows-style path on Linux is still trying to escape, and vice versa.
 * Returns the last non-empty component (empty if the path ends in a
 * separator).
 */
std::string_view baseNameOf(std::string_view path);

/**
 * @brief Trim leading whitespace and trailing dots/whitespace.
 *
 * Windows silently strips trailing dots and spaces when creating files, so
 * "evil.exe.." resolves to "evil.exe" and can collide with or hide a
 * legitimate file. Leading whitespace is trimmed for symmetry.
 */
std::string_view trimFilenameEdges(std::string_view component);

/**
 * @brief True for Windows reserved device names (CON, PRN, AUX, NUL,
 * COM1-9, LPT1-9), matched case-insensitively against the part before the
 * first dot (so "CON.txt" is reserved too).
 *
 * On Windows these are device handles regardless of working directory:
 * base/CON would not create a file but open the console device, and any
 * subsequent write goes there.
 */
bool isReservedDeviceName(std::string_view component);

/**
 * @brief Truncate to at most @p max_bytes without splitting a character.
 *
 * A multi-byte codepoint crossing the limit is dropped whole rather than
 * cut in half, which would produce ill-formed UTF-8.
 */
std::string_view truncateUtf8(std::string_view s, size_t max_bytes);

/**
 * @brief True if the string contains NUL or an ASCII control byte other
 * than tab.
 *
 * NUL is particularly dangerous: many Windows APIs truncate at NUL while
 * the filesystem treats the full name, which has historically been used to
 * mask malicious extensions. Tab is allowed as ordinary whitespace.
 */
bool hasControlBytes(std::string_view s);

/**
 * @brief True if @p name is a conformant CDoc2 entry name.
 *
 * Conformance is the §5.3.1 rule set (Filename-handling-proposal.md §3,
 * "non-conformant" class): valid UTF-8 (RFC 3629), non-empty, at most
 * 1000 bytes, no Unicode control characters / U+202E / U+FFFE / U+FFFF,
 * relative (no leading '/' or drive letter), and no empty / "." / ".."
 * path components. Uniqueness is a cross-entry property the caller checks
 * (see deduplicateFilename). A name may be conformant yet suspicious
 * (hasSuspiciousTraits) - the two classes are independent on purpose.
 */
CDOC_EXPORT bool isConformantName(std::string_view name);

/**
 * @brief True if @p name carries suspicious-but-spec-valid traits.
 *
 * The §3 "suspicious" class: symbols `<>:\|?*` and backslash, leading
 * dots (hidden files on Unix), leading space/hyphen, trailing dot/space,
 * reserved device components, or components longer than 255 bytes. These
 * names are legal to store but hazardous to write to disk or pass to other
 * tools: the writer rejects them, readers return them only after
 * repairFilename(). The scan is byte-level and meaningful together with
 * isConformantName().
 */
CDOC_EXPORT bool hasSuspiciousTraits(std::string_view name);

/**
 * @brief Repair @p name into a conformant name free of suspicious traits.
 *
 * Implements the §3 repair rules: ill-formed bytes and forbidden code
 * points become '_', suspicious symbols are removed, component edges are
 * trimmed (leading space/hyphen, trailing dot/space), leading dots become
 * '_' (no hidden files), reserved device components get a '_' prefix,
 * components are capped at 255 bytes and the whole name at 1000. Path
 * shape is preserved but confined: the leading
 * root of absolute names is dropped and "." / ".." components are
 * resolved, so the result is always a clean relative name that can never
 * escape an extraction root. An empty result becomes "unnamed"; callers
 * pipe through deduplicateFilename() for " (N)" indexing. Idempotent.
 */
CDOC_EXPORT std::string repairFilename(std::string_view name);

/**
 * @brief Entry-name handling policy for readers (FILENAME_MODE).
 */
enum class FilenamePolicy {
    /// Validate: non-conformant names fail the read (and are not
    /// returned), suspicious-but-conformant names come back repaired.
    /// Default.
    Strict,
    /// Repair everything: non-conformant names are repaired instead of
    /// failing, duplicates get " (N)" suffixes.
    Safe,
    /// Verbatim pass-through (forensics/inspection): raw names leave the
    /// library untouched, duplicates included.
    Lenient
};

/**
 * @brief Parse a FILENAME_MODE configuration value.
 *
 * Unknown or empty values mean Strict (the default).
 */
CDOC_EXPORT FilenamePolicy filenamePolicyFromString(std::string_view value);

/**
 * @brief Per-reader name bookkeeping for applyFilenamePolicy().
 */
struct FilenameState {
    /// Dedup keys of returned names (deduplicateFilename bookkeeping).
    std::map<std::string, size_t> returned;
    /// Dedup keys of raw stored names. Strict mode treats duplicate raw
    /// names as a container conformance violation, which is distinct from
    /// a repair-induced collision between different raw names.
    std::set<std::string> raw;
};

/**
 * @brief Outcome of applying a FilenamePolicy to one stored entry name.
 */
struct FilenameDecision {
    /// False when strict mode rejects the name; name is then empty (the
    /// raw name is never returned, see Filename-handling-proposal.md §5).
    bool ok = true;
    /// The name to return to the caller.
    std::string name;
    /// True when name differs from the stored raw name (repaired/renamed);
    /// callers log a warning in that case.
    bool repaired = false;
};

/**
 * @brief Apply the reader name policy to one stored entry name.
 *
 * Implements the mode matrix from Filename-handling-proposal.md §5 on top
 * of isConformantName()/hasSuspiciousTraits()/repairFilename() and updates
 * @p state for duplicate handling. This is the single place where reader
 * name policy lives; CDoc1/CDoc2Reader::nextFile() call it and only wire
 * the result to their error/integrity handling.
 */
CDOC_EXPORT FilenameDecision applyFilenamePolicy(FilenamePolicy policy, FilenameState& state, std::string_view raw_name);

/**
 * @brief Sink-side name safety: flatten to a safe basename for writing to
 * disk, or empty if no safe name exists.
 *
 * Composes the helpers above (UTF-8 validity, control bytes, baseNameOf,
 * ':' rejection, trimFilenameEdges, reserved devices, truncateUtf8); the
 * same rule blocks back the read-side repair/conformance functions (see
 * Filename-handling-proposal.md). Never returns a name with directory
 * components; returns "" for names that cannot be made safe.
 */
std::string sanitiseExtractedFilename(std::string_view name);

/**
 * @brief Insert @p name into the seen-set, renaming on clash.
 *
 * Used to guarantee that a sequence of file names (container entries,
 * extraction targets) contains no duplicates. If the (case-folded) name is
 * already present, a " (N)" suffix is inserted before the extension:
 * "a.txt" -> "a (1).txt". The stem is truncated so the result never exceeds
 * 255 bytes, and truncation never splits a UTF-8 codepoint.
 *
 * The dedup key folds ASCII case so that "A.txt" and "a.txt" are considered
 * equal: they collide on case-insensitive filesystems (Windows, default
 * APFS/HFS+). Full Unicode case folding / normalization is deliberately out
 * of scope; use cdoc-tool --no-overwrite to also avoid clobbering existing
 * on-disk files that only differ after normalization.
 *
 * Complexity is amortized O(log n) per call: the map stores the next free
 * suffix for each key, so a container containing a.txt, a (1).txt, ...
 * does not cause quadratic rescans.
 *
 * @param seen map of case-folded dedup key -> next free numeric suffix
 *             (0 = none assigned yet). Updated in place.
 * @param name the candidate name (must be non-empty and pre-sanitized)
 * @return the name actually inserted into the seen-set (the original name,
 *         or a renamed variant)
 */
std::string deduplicateFilename(std::map<std::string, size_t>& seen, const std::string& name);

/**
 * @brief ASCII case-folded dedup key for file names.
 *
 * Lowercases ASCII A-Z only; used as the map key by deduplicateFilename().
 * Exposed for direct duplicate testing (writers/readers that must reject
 * rather than rename).
 */
std::string filenameDedupKey(std::string_view name);

/**
 * @brief Choose a unique file name for extraction into @p base_dir.
 *
 * The extraction sinks' general rename loop: runs deduplicateFilename()
 * and additionally probes the filesystem, which is the per-OS collision
 * authority - byte-different names can collide after the filesystem's own
 * case/normalization folding (NFC/NFD on APFS, case folding on NTFS).
 * Names that collide with files created during this run (@p created) are
 * always renamed: extraction must never clobber its own output, even when
 * overwriting is allowed. Names colliding with pre-existing files are
 * renamed unless @p allow_overwrite is set.
 */
CDOC_EXPORT std::string uniqueExtractedFilename(std::map<std::string, size_t>& seen,
                                                const std::string& name,
                                                const std::filesystem::path& base_dir,
                                                bool allow_overwrite,
                                                const std::vector<std::filesystem::path>& created);

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
EtsiRecipientId parseEtsiRecipientId(std::string_view rcpt_id);

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
