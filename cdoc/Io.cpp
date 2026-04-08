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
    std::string_view fileName = name;
    if (ofs.is_open()) {
        ofs.close();
    }
    size_t lastSlashPos = fileName.find_last_of("\\/");
    if (lastSlashPos != std::string::npos) {
        fileName = fileName.substr(lastSlashPos + 1);
    }
    fs::path path(base);
    path /= encodeName(fileName);
    ofs.open(path, std::ios_base::binary);
    return ofs.bad() ? OUTPUT_STREAM_ERROR : OK;
}

FileListSource::FileListSource(const std::string& base, const std::vector<std::string>& files)
    : _base(encodeName(base)), _files(files)
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
    if (std::error_code ec; !fs::exists(path, ec)) return IO_ERROR;
    _ifs.open(path, std::ios_base::binary);
	if (_ifs.bad()) return IO_ERROR;
	name = _files[_current];
    std::error_code ec;
    size = fs::file_size(path, ec);
    if (!ec) return IO_ERROR;
    return OK;
}

} // namespace libcdoc
