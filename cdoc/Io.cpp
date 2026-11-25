// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "Io.h"

#include "Utils.h"

#include <array>

namespace fs = std::filesystem;

namespace libcdoc {

static constexpr size_t BLOCK_SIZE = 65536;

std::string
DataConsumer::getLastErrorStr(result_t code) const
{
	switch (code) {
    case OK:
		return "";
	case OUTPUT_ERROR:
		return "DataConsumer: Output error";
	case OUTPUT_STREAM_ERROR:
		return "DataConsumer: Output stream error";
	default:
		break;
	}
	return "DataConsumer: Internal error";
}

std::string
DataSource::getLastErrorStr(result_t code) const
{
	switch (code) {
    case OK:
		return "";
	case INPUT_ERROR:
		return "DataConsumer: Input error";
	case INPUT_STREAM_ERROR:
		return "DataConsumer: Intput stream error";
	default:
		break;
	}
	return "DataConsumer: Internal error";
}

int64_t
DataConsumer::writeAll(DataSource& src) noexcept
{
    std::array<uint8_t,64 * 1024> buf{};
	size_t total_read = 0;
	while (!src.isEof()) {
        int64_t n_read = src.read(buf.data(), buf.size());
		if (n_read < 0) return n_read;
		if (n_read > 0) {
            int64_t n_written = write(buf.data(), n_read);
			if (n_written < 0) return n_written;
			total_read += n_written;
		}
	}
	return total_read;
}

int64_t
DataSource::skip(size_t size) {
	uint8_t b[BLOCK_SIZE];
	size_t total_read = 0;
	while (total_read < size) {
		size_t to_read = std::min<size_t>(size - total_read, BLOCK_SIZE);
		int64_t n_read = read(b, to_read);
		if (n_read < 0) return n_read;
		total_read += n_read;
        if (n_read < to_read) break;
	}
	return total_read;
}

IStreamSource::IStreamSource(const std::string& path)
    : IStreamSource(new std::ifstream(fs::path(encodeName(path)), std::ios_base::binary), true)
{
}

OStreamConsumer::OStreamConsumer(const std::string& path)
    : OStreamConsumer(new std::ofstream(fs::path(encodeName(path)), std::ios_base::binary), true)
{
}

result_t FileListConsumer::open(const std::string &name, int64_t size) {
    if (ofs.is_open()) {
        ofs.close();
    }

    // The file name comes from inside the (encrypted) container and is
    // therefore fully attacker-controlled. Flatten to a repaired basename:
    // directory components are dropped and every hazard (symbols, device
    // names, lengths) is repaired rather than trusted (see
    // Filename-handling-proposal.md §6).
    std::string safeName = repairFilename(baseNameOf(name));

    // Unique output name: rename on in-run clashes and on collisions with
    // files already on disk (the filesystem folds case/NFC-NFD, so its
    // existence check is the per-OS authority). FileListConsumer never
    // overwrites existing files.
    std::string uniqueName = uniqueExtractedFilename(_names, safeName, base, false, _created);
    if (uniqueName != safeName)
        LOG_WARN("FileListConsumer::open: renamed clashing entry '{}' -> '{}'",
                 safeName, uniqueName);

    fs::path target = base / fs::path(encodeName(uniqueName));

    // Defence in depth: even after sanitising the leaf name, an attacker
    // who can plant a symlink at `base` (e.g. by extracting an earlier
    // entry that the host application created earlier) could redirect
    // writes outside `base`. weakly_canonical resolves any symlinks that
    // already exist in the path; we then verify the parent directory of
    // the target equals the canonical base.
    std::error_code ec;
    fs::path canonicalBase = fs::weakly_canonical(base, ec);
    if (ec) {
        LOG_ERROR("FileListConsumer::open: cannot canonicalise base {}: {}",
                  base.string(), ec.message());
        return OUTPUT_STREAM_ERROR;
    }
    fs::path canonicalTarget = fs::weakly_canonical(target, ec);
    if (ec) {
        LOG_ERROR("FileListConsumer::open: cannot canonicalise target {}: {}",
                  target.string(), ec.message());
        return OUTPUT_STREAM_ERROR;
    }
    if (canonicalTarget.parent_path() != canonicalBase) {
        LOG_ERROR("FileListConsumer::open: refusing entry '{}' - target {} "
                  "escapes base {}",
                  name, canonicalTarget.string(), canonicalBase.string());
        return DATA_FORMAT_ERROR;
    }

    ofs.open(target, std::ios_base::binary);
    // N23: ofs.bad() misses failbit set by a failed open() (e.g. permission
    // denied, read-only filesystem). Check fail() instead so extraction
    // reports the error instead of "succeeding" with nothing written.
    if (ofs.fail()) return OUTPUT_STREAM_ERROR;
    _created.push_back(std::move(target));
    return OK;
}

void FileListConsumer::removeCreated()
{
    ofs.close();
    // Delete-on-abort (CDOC2 spec §5.3.2), newest first.
    for (auto it = _created.rbegin(); it != _created.rend(); ++it) {
        std::error_code ec;
        fs::remove(*it, ec);
    }
    _created.clear();
}

FileListSource::FileListSource(const std::string& base, const std::vector<std::string>& files, bool allow_pathnames)
    : _base(encodeName(base)), _files(files), _allow_pathnames(allow_pathnames)
{
}

int64_t
FileListSource::read(uint8_t *dst, size_t size) noexcept try
{
	if ((_current < 0) || (_current >= _files.size())) return WORKFLOW_ERROR;
	_ifs.read((char *) dst, size);
	return (_ifs.bad()) ? INPUT_STREAM_ERROR : _ifs.gcount();
} catch(...) {
    return INPUT_STREAM_ERROR;
}

bool
FileListSource::isError() noexcept
{
    if ((_current < 0) || (_current >= _files.size())) return OK;
	return _ifs.bad();
}

bool
FileListSource::isEof() noexcept
{
	if (_current < 0) return false;
	if (_current >= _files.size()) return true;
	return _ifs.eof();
}

libcdoc::result_t
FileListSource::getNumComponents()
{
	return _files.size();
}

libcdoc::result_t
FileListSource::next(std::string& name, int64_t& size)
{
	_ifs.close();
	_current += 1;
	if (_current >= _files.size()) return END_OF_STREAM;
    fs::path path(_base);
    path.append(encodeName(_files[_current]));
    if (std::error_code ec; !fs::is_regular_file(path, ec)) return IO_ERROR;
    _ifs.open(path, std::ios_base::binary);
	if (_ifs.fail()) return IO_ERROR;
    if (_allow_pathnames) {
        // Preserve clean relative paths in the container, but never absolute
        // paths or traversal components.
        fs::path rel = path.lexically_relative(_base);
        // When _base is empty, lexically_relative returns the path itself.
        fs::path entry = rel.empty() ? path.lexically_normal() : rel.lexically_normal();
        if (entry.is_absolute()) {
            LOG_ERROR("Refusing absolute path in container: {}", decodeName(path));
            return DATA_FORMAT_ERROR;
        }
        // Reject any ".." component (would escape the base on extraction).
        for (const auto& part : entry) {
            if (part == "..") {
                LOG_ERROR("Refusing '..' component in container path: {}", decodeName(path));
                return DATA_FORMAT_ERROR;
            }
        }
        // Store with forward slashes (tar convention).
        auto gen = entry.generic_u8string();
        name = std::string(reinterpret_cast<const char*>(gen.data()), gen.size());
        if (name.empty() || name == ".") {
            LOG_ERROR("Unsupported file name: {}", decodeName(path));
            return DATA_FORMAT_ERROR;
        }
        // Repair remaining hazards (symbols, device names, lengths) while
        // keeping the path shape; the writer accepts only clean names.
        std::string repaired = repairFilename(name);
        if (repaired != name) {
            LOG_WARN("Entry name repaired: '{}' -> '{}'", name, repaired);
            name = std::move(repaired);
        }
    } else {
        // Strip to the basename and repair it to a clean name.
        std::string base(baseNameOf(decodeName(path.filename())));
        name = repairFilename(base);
        if (name != base) {
            LOG_WARN("Entry name repaired: '{}' -> '{}'", base, name);
        }
    }
    // Rename on clash (case-insensitively) so every entry name is unique.
    name = deduplicateFilename(_names, name);
    std::error_code ec;
    size = fs::file_size(path, ec);
    if (ec) return IO_ERROR;
    return OK;
}

} // namespace libcdoc
