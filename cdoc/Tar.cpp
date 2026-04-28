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

#include "Tar.h"
#include "Utils.h"

#include <array>
#include <cstring>

using namespace libcdoc;

constexpr unsigned int BLOCKSIZE = 512;

template<std::size_t SIZE>
static int64_t fromOctal(const std::array<char,SIZE> &data)
{
	int64_t i = 0;
	for(const char c: data)
	{
		if(c < '0' || c > '7')
			continue;
		i <<= 3;
		i += c - '0';
	}
	return i;
}

template<std::size_t SIZE>
static void toOctal(std::array<char,SIZE> &data, int64_t value)
{
	data.fill(' ');
	for(auto it = data.rbegin() + 1; it != data.rend(); ++it)
	{
		*it = char(value & 7) + '0';
		value >>= 3;
	}
}

struct libcdoc::Header {
	std::array<char,100> name;
	std::array<char,  8> mode;
	std::array<char,  8> uid;
	std::array<char,  8> gid;
	std::array<char, 12> size;
	std::array<char, 12> mtime;
	std::array<char,  8> chksum;
	char typeflag;
	std::array<char,100> linkname;
	std::array<char,  6> magic;
	std::array<char,  2> version;
	std::array<char, 32> uname;
	std::array<char, 32> gname;
	std::array<char,  8> devmajor;
	std::array<char,  8> devminor;
	std::array<char,155> prefix;
	std::array<char, 12> padding;

	std::pair<int64_t,int64_t> checksum() const
	{
		int64_t unsignedSum = 0;
		int64_t signedSum = 0;
		for (size_t i = 0, size = BLOCKSIZE; i < size; i++) {
			unsignedSum += ((unsigned char*) this)[i];
			signedSum += ((signed char*) this)[i];
		}
		return {unsignedSum, signedSum};
	}

    bool isNull() const {
        static const Header empty{};
        return *this == empty;
	}

	bool verify() {
		auto copy = chksum;
		chksum.fill(' ');
		auto checkSum = checksum();
		chksum.swap(copy);
		int64_t referenceChecksum = fromOctal(chksum);
		return referenceChecksum == checkSum.first ||
			   referenceChecksum == checkSum.second;
	}

	std::string getName() const {
		return std::string(name.data(), std::min<size_t>(name.size(), strlen(name.data())));
	}

	int64_t getSize() const {
		return fromOctal(size);
	}

	bool operator==(const Header&) const = default;
};

static_assert (sizeof(Header) == BLOCKSIZE, "Header struct size is incorrect");

static int padding(int64_t size)
{
	return BLOCKSIZE * ((size + BLOCKSIZE - 1) / BLOCKSIZE) - size;
}

std::string toPaxRecord (const std::string &keyword, const std::string &value) {
	std::string record = ' ' + keyword + '=' + value + '\n';
	std::string result;
	for(auto len = record.size() + 1; result.size() != len; ++len)
		result = std::to_string(len + 1) + record;
	return result;
};

libcdoc::TarConsumer::TarConsumer(DataConsumer *dst, bool take_ownership)
	: _dst(dst), _owned(take_ownership)
{

}

libcdoc::TarConsumer::~TarConsumer()
{
	if (_owned) {
		delete _dst;
	}
}

libcdoc::result_t
libcdoc::TarConsumer::write(const uint8_t *src, size_t size) noexcept
{
	if ((_current_size >= 0) && ((_current_written + size) > _current_size)) {
		return WORKFLOW_ERROR;
	}
	_current_written += size;
	return _dst->write(src, size);
}

libcdoc::result_t
libcdoc::TarConsumer::writeHeader(const Header &h) noexcept {
    if(auto rv = _dst->write((const uint8_t *)&h, BLOCKSIZE); rv != BLOCKSIZE)
        return rv < OK ? rv : OUTPUT_ERROR;
    return OK;
}

libcdoc::result_t
libcdoc::TarConsumer::writeHeader(const std::string& name, int64_t size, char typeflag) noexcept {
	Header h {};
	h.typeflag = typeflag;
    h.chksum.fill(' ');
    size_t len = std::min(name.size(), h.name.size());
    std::copy_n(name.cbegin(), len, h.name.begin());
    toOctal(h.size, size);
    toOctal(h.chksum, h.checksum().first);
    return writeHeader(h);
}

libcdoc::result_t
libcdoc::TarConsumer::writePadding(int64_t size) noexcept {
    static const std::array<uint8_t,BLOCKSIZE> pad {};
    auto padSize = padding(size);
    if(auto rv = _dst->write(pad.data(), padSize); rv != padSize)
        return rv < OK ? rv : OUTPUT_ERROR;
    return OK;
}

libcdoc::result_t
libcdoc::TarConsumer::close() noexcept
{
	result_t result = OK;
	if ((_current_size >= 0) && (_current_written < _current_size)) {
		result = DATA_FORMAT_ERROR;
	} else {
		if (_current_written > 0) {
			if(auto rv = writePadding(_current_written); rv != OK)
				return rv;
		}
		Header empty = {};
		if(auto rv = writeHeader(empty); rv != OK)
			return rv;
		if(auto rv = writeHeader(empty); rv != OK)
			return rv;
	}
	if (_owned) {
		if (auto rv = _dst->close(); rv != OK)
			return rv;
	}
    return result;
}

bool
libcdoc::TarConsumer::isError() noexcept
{
	return _dst->isError();
}

libcdoc::result_t
libcdoc::TarConsumer::open(const std::string& name, int64_t size)
{
	if ((_current_size >= 0) && (_current_written < _current_size)) {
		return WORKFLOW_ERROR;
	}
    if (_current_written > 0) {
        if(auto rv = writePadding(_current_written); rv != OK)
            return rv;
    }

    _current_size = size;
	_current_written = 0;

	bool need_pax_name = (name.size() >= 100);
	for (auto c : name) {
		if ((c & 0x80) || (c < ' ')) {
			need_pax_name = true;
			break;
		}
	}
    if(need_pax_name || size > 07777777) {
		LOG_DBG("Writing Pax header: name {} size {}", name, size);
		std::string paxData;
        if(need_pax_name)
            paxData += toPaxRecord("path", name);
		if(size > 07777777)
			paxData += toPaxRecord("size", std::to_string(size));
        std::filesystem::path path(encodeName(name));
		if (path.has_parent_path()) {
			path = path.parent_path() / "PaxHeaders.X" / path.filename();
		} else {
			path = std::filesystem::path("./PaxHeaders.X") / path.filename();
		}
		LOG_DBG("Pax path: {}", path.string());
        if (auto rv = writeHeader(path.string(), paxData.size(), 'x'); rv != OK)
            return rv;
        if (auto rv = _dst->write((const uint8_t *) paxData.data(), paxData.size()); rv != paxData.size())
            return rv < OK ? rv : OUTPUT_ERROR;
        if (auto rv = writePadding(paxData.size()); rv != OK)
            return rv;
    }
    return writeHeader(name, size, '0');
}

libcdoc::TarSource::TarSource(DataSource *src, bool take_ownership)
    : _src(src), _owned(take_ownership), _eof(false), _error(OK), _block_size(0), _data_size(0), _pos(0)
{

}

libcdoc::TarSource::~TarSource()
{
	if (_owned) {
		delete _src;
	}
}

libcdoc::result_t
libcdoc::TarSource::read(uint8_t *dst, size_t size) noexcept
{
    if (_error != OK) return _error;
	if (_pos >= _data_size) {
		_eof = true;
		return 0;
	}
	size_t rem = _data_size - _pos;
	int64_t n_read = _src->read(dst, std::min(rem, size));
	if (n_read < 0) return n_read;
	if (n_read == 0) {
		_eof = true;
		return 0;
	}
	_pos += n_read;
	return n_read;
}

bool
libcdoc::TarSource::isError() noexcept
{
    return _error != OK;
}

bool
libcdoc::TarSource::isEof() noexcept
{
	return _eof;
}

libcdoc::result_t
libcdoc::TarSource::readPaxHeader(const Header& hdr, std::string& name, int64_t& size)
{
	int64_t h_size = hdr.getSize();
	std::string paxData(h_size, 0);
	result_t result = _src->read((uint8_t *) paxData.data(), paxData.size());
	if (result != h_size) {
		_error = INPUT_STREAM_ERROR;
		return _error;
	}
	_src->skip(padding(h_size));
	// Parse Pax data
	for(const std::string &data: split(paxData, '\n')) {
		if(data.empty()) break;
		size_t eq_pos = data.find_first_of('=');
		if (eq_pos == std::string::npos) {
			_error = DATA_FORMAT_ERROR;
			return _error;
		}
		std::string headerValue = data.substr(eq_pos + 1, data.size() - eq_pos - 1);
		size_t sp_pos = data.find_first_of(' ');
		if ((sp_pos == std::string::npos) || (sp_pos >= eq_pos)) {
			_error = DATA_FORMAT_ERROR;
			return _error;
		}
		std::string lenStr = data.substr(0, sp_pos);
		std::string keyWord = data.substr(sp_pos + 1, eq_pos - sp_pos - 1);
		if(data.size() + 1 != stoi(lenStr)) {
			_error = DATA_FORMAT_ERROR;
			return _error;
		}
		LOG_DBG("PAX {} : {}", keyWord, headerValue);
		if(keyWord == "path")
			name = std::move(headerValue);
		if(keyWord == "size")
			size = stoll(headerValue);
	}
	return OK;
}

libcdoc::result_t
libcdoc::TarSource::next(std::string& name, int64_t& size)
{
	Header h;

	// Skip if not at the start of a block
	if (_pos < _block_size) {
		int64_t result = _src->skip(_block_size - _pos);
		_pos = 0;
		_block_size = 0;
		_data_size = 0;
		if (result < 0) {
			_error = INPUT_STREAM_ERROR;
			return _error;
		}
	}

	while (!_src->isEof()) {
		// Read header
		int64_t result = _src->read((uint8_t *)&h, BLOCKSIZE);
		if (result != BLOCKSIZE) {
			_error = INPUT_STREAM_ERROR;
			return _error;
		}
		if (h.isNull()) {
			// Two null headers mark end of archive
			LOG_DBG("NULL header");
			result = _src->read((uint8_t *)&h, BLOCKSIZE);
			if (result != BLOCKSIZE) {
				_error = INPUT_STREAM_ERROR;
				return _error;
			}
			LOG_DBG("EOF");
			_eof = true;
			return END_OF_STREAM;
		}
		if (!h.verify()) {
			_error = DATA_FORMAT_ERROR;
			return _error;
		}
		LOG_DBG("Header typeflag {} name {} size {}", h.typeflag, h.getName(), h.getSize());

		std::string h_name;
		int64_t h_size = -1;
		if(h.typeflag == 'x') {
			_error = readPaxHeader(h, h_name, h_size);
			if (_error != OK)
				return _error;
			// Read ustar header
			result = _src->read((uint8_t *)&h, BLOCKSIZE);
			if (result != BLOCKSIZE) {
				_error = INPUT_STREAM_ERROR;
				return _error;
			}
			if(h.isNull() || !h.verify()) {
				_error = DATA_FORMAT_ERROR;
				return _error;
			}
			if(h.typeflag != '0' && h.typeflag != 0) {
				_error = DATA_FORMAT_ERROR;
				return _error;
			}
		}
		if (h.typeflag == '0' || h.typeflag == 0) {
			name = (h_name.empty()) ? h.getName() : std::move(h_name);
			size = (h_size < 0) ? h.getSize() : h_size;
			_pos = 0;
			_data_size = size;
			_block_size = size + padding(size);
			_eof = false;
            return OK;
		} else {
			// Skip other header types ('g')
			h_size = h.getSize();
			_src->skip(h_size + padding(h_size));
		}
	}
	return END_OF_STREAM;
}
