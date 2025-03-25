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

#include <array>
#include <sstream>

std::vector<std::string>
split (const std::string &s, char delim) {
	std::vector<std::string> result;
	std::stringstream ss (s);
	std::string item;

	while (getline (ss, item, delim)) {
		result.push_back (item);
	}

	return result;
}

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

struct Header {
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
		for (size_t i = 0, size = sizeof(Header); i < size; i++) {
			unsignedSum += ((unsigned char*) this)[i];
			signedSum += ((signed char*) this)[i];
		}
		return {unsignedSum, signedSum};
	}

	bool isNull() {
		Header empty = {};
		return std::memcmp(this, &empty, sizeof(Header)) == 0;
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

	static const Header Empty;
	static const int Size;
};

static int padding(int64_t size)
{
	return sizeof(Header) - size % sizeof(Header);
}

bool
libcdoc::TAR::files(libcdoc::DataSource *src, bool &warning, libcdoc::MultiDataConsumer *dst)
{
	TarSource tar(src, false);
	std::string name;
	int64_t size;
    while (tar.next(name, size) == OK) {
		dst->open(name, size);
		dst->writeAll(tar);
	}
	warning = !src->isEof();
	return true;
}

int64_t writePadding(libcdoc::DataConsumer *dst, uint64_t size) {
	std::vector<char> pad(padding(size), 0);
	return dst->write((const uint8_t *) pad.data(), pad.size()) == pad.size();
};

int64_t writeHeader (libcdoc::DataConsumer *dst, Header &h, uint64_t size) {
	h.chksum.fill(' ');
	toOctal(h.size, size);
	toOctal(h.chksum, h.checksum().first);
	return dst->write((const uint8_t *)&h, sizeof(Header)) == sizeof(Header);
};

std::string toPaxRecord (const std::string &keyword, const std::string &value) {
	std::string record = ' ' + keyword + '=' + value + '\n';
	std::string result;
	for(auto len = record.size() + 1; result.size() != len; ++len)
		result = std::to_string(len + 1) + record;
	return result;
};

bool
libcdoc::TAR::save(libcdoc::DataConsumer& dst, libcdoc::MultiDataSource& src)
{
	std::string name;
	int64_t size;
	while (src.next(name, size)) {
		Header h {};
		std::string filename(name);
		std::string filenameTruncated(filename.begin(), filename.begin() + h.name.size());
		std::copy(filenameTruncated.cbegin(), filenameTruncated.cend(), h.name.begin());

        // TODO:
        // write pax record if name contains special symbols
		if(filename.size() > 100 || size > 07777777) {
			h.typeflag = 'x';
			std::string paxData;
			if(filename.size() > 100)
				paxData += toPaxRecord("path", filename);
			if(size > 07777777)
				paxData += toPaxRecord("size", std::to_string(size));
			if(!writeHeader(&dst, h, paxData.size()) ||
				dst.write((const uint8_t *) paxData.data(), paxData.size()) != paxData.size() ||
				!writePadding(&dst, paxData.size()))
				return false;
		}

		h.typeflag = '0';
		if(!writeHeader(&dst, h, size))
			return false;
		size_t total_written = 0;
		while (!src.isEof()) {
			uint8_t buf[256];
			auto n_read = src.read(buf, 256);
			if (n_read < 0) return false;
			dst.write(buf, n_read);
			total_written += n_read;
		}
		writePadding(&dst, total_written);

	}
	Header empty = {};
	return dst.write((const uint8_t *)&empty, sizeof(Header)) == sizeof(Header) &&
		dst.write((const uint8_t *)&empty, sizeof(Header)) == sizeof(Header);
}

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
libcdoc::TarConsumer::write(const uint8_t *src, size_t size)
{
	return _dst->write(src, size);
}

libcdoc::result_t
libcdoc::TarConsumer::close()
{
	if (_current_size) {
		writePadding(_dst, _current_size);
	}
	Header empty = {};
	_dst->write((const uint8_t *)&empty, sizeof(Header));
	_dst->write((const uint8_t *)&empty, sizeof(Header));
	if (_owned) {
		_dst->close();
	}
    return OK;
}

bool
libcdoc::TarConsumer::isError()
{
	return _dst->isError();
}

libcdoc::result_t
libcdoc::TarConsumer::open(const std::string& name, int64_t size)
{
	if (_current_size) {
		writePadding(_dst, _current_size);
	}
	_current_size = size;
	Header h {};
	std::string filename(name);
	size_t len = name.size();
	if (len > h.name.size()) len = h.name.size();
	std::copy(name.cbegin(), name.cbegin() + len, h.name.begin());

    // TODO: Create pax record if name contains special symbols
	if(filename.size() > 100 || size > 07777777) {
		h.typeflag = 'x';
		std::string paxData;
		if(filename.size() > 100)
			paxData += toPaxRecord("path", filename);
		if(size > 07777777)
			paxData += toPaxRecord("size", std::to_string(size));
        return writeHeader(_dst, h, paxData.size()) &&
            _dst->write((const uint8_t *) paxData.data(), paxData.size()) == paxData.size() &&
            writePadding(_dst, paxData.size()) ? OK : OUTPUT_ERROR;
	}

	h.typeflag = '0';
	if(writeHeader(_dst, h, size) < 0) return OUTPUT_ERROR;
    return OK;
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
libcdoc::TarSource::read(uint8_t *dst, size_t size)
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
libcdoc::TarSource::isError()
{
    return _error != OK;
}

bool
libcdoc::TarSource::isEof()
{
	return _eof;
}

libcdoc::result_t
libcdoc::TarSource::next(std::string& name, int64_t& size)
{
	Header h;

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
		int64_t result = _src->read((uint8_t *)&h, sizeof(Header));
		if (result != sizeof(Header)) {
			_error = INPUT_STREAM_ERROR;
			return _error;
		}
		if (h.isNull()) {
			result = _src->read((uint8_t *)&h, sizeof(Header));
			if (result != sizeof(Header)) {
				_error = INPUT_STREAM_ERROR;
				return _error;
			}
			_eof = true;
			return END_OF_STREAM;
		}
		if (!h.verify()) {
			_error = DATA_FORMAT_ERROR;
			return _error;
		}

		std::string h_name = std::string(h.name.data(), std::min<size_t>(h.name.size(), strlen(h.name.data())));
		size_t h_size = fromOctal(h.size);
		if(h.typeflag == 'x') {
			std::vector<char> pax_in(h_size);
			result = _src->read((uint8_t *) pax_in.data(), pax_in.size());
			if (result != h_size) {
				_error = INPUT_STREAM_ERROR;
				return _error;
			}
			std::string paxData(pax_in.data(), pax_in.size());
			_src->skip(padding(h_size));
			result = _src->read((uint8_t *)&h, sizeof(Header));
			if (result != sizeof(Header)) {
				_error = INPUT_STREAM_ERROR;
				return _error;
			}
			if(h.isNull() || !h.verify()) {
				_error = DATA_FORMAT_ERROR;
				return _error;
			}
			h_size = fromOctal(h.size);
			std::stringstream ss(paxData);
			for(const std::string &data: split(paxData, '\n')) {
				if(data.empty()) break;
				const auto &headerValue = split(data, '=');
				const auto &lenKeyword = split(headerValue[0], ' ');
				if(data.size() + 1 != stoi(lenKeyword[0])) {
					_error = DATA_FORMAT_ERROR;
					return _error;
				}
				if(lenKeyword[1] == "path") h_name = headerValue[1];
				if(lenKeyword[1] == "size") h_size = stoi(headerValue[1]);
			}
		}
		if(h.typeflag == '0' || h.typeflag == 0) {
			name = std::move(h_name);
			size = h_size;
			_pos = 0;
			_data_size = h_size;
			_block_size = h_size + padding(h_size);
			_eof = false;
            return OK;
		} else {
			_src->skip(h_size + padding(h_size));
		}
	}
	return END_OF_STREAM;
}
