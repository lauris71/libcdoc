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

#include "Io.h"

#include <algorithm>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace libcdoc {

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

static std::vector<uint8_t>
fromHex(std::string_view hex) {
    std::vector<uint8_t> val(hex.size() / 2);
    char c[3] = {0};
    for (size_t i = 0; i < (hex.size() & 0xfffffffe); i += 2) {
        std::copy(hex.cbegin() + i, hex.cbegin() + i + 2, c);
        val[i / 2] = (uint8_t) strtol(c, NULL, 16);
    }
    return std::move(val);
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
join(const std::vector<std::string> parts, const std::string_view sep)
{
	std::string result;
	for (auto& part : parts) {
		if (part != parts.front()) result += sep;
		result += part;
	}
	return std::move(result);
}

std::vector<std::string> JsonToStringArray(std::string_view json);

// Get time in seconds since the Epoch

double getTime();

static std::vector<uint8_t>
readAllBytes(std::istream& ifs)
{
	std::vector<uint8_t> dst;
	uint8_t b[4096];
	while (!ifs.eof()) {
		ifs.read((char *) b, 4096);
		if (ifs.bad()) return {};
		dst.insert(dst.end(), b, b + ifs.gcount());
	}
    return dst;
}

static std::vector<uint8_t>
readAllBytes(std::string_view filename)
{
    std::filesystem::path keyFilePath(filename);
    if (!std::filesystem::exists(keyFilePath)) {
        std::cerr << "readAllBytes(): File '" << filename << "' does not exist" << std::endl;
        return {};
    }
    std::ifstream keyStream(keyFilePath, std::ios_base::in | std::ios_base::binary);
    if (!keyStream) {
        std::cerr << "readAllBytes(): Opening '" << filename << "' failed." << std::endl;
        return {};
    }
    return readAllBytes(keyStream);
}

int parseURL(const std::string& url, std::string& host, int& port, std::string& path);
std::string buildURL(const std::string& host, int port);

std::string urlEncode(std::string_view src);
std::string urlDecode(const std::string &src);

#ifdef _WIN32

static std::wstring toWide(UINT codePage, const std::string &in)
{
	std::wstring result;
	if(in.empty())
		return result;
	int len = MultiByteToWideChar(codePage, 0, in.data(), int(in.size()), nullptr, 0);
	result.resize(size_t(len), 0);
	len = MultiByteToWideChar(codePage, 0, in.data(), int(in.size()), &result[0], len);
	return result;
}

static std::wstring
toWide(const std::string& in)
{
	return toWide(CP_UTF8, in);
}

static std::string toMultiByte(UINT codePage, const std::wstring &in)
{
	std::string result;
	if(in.empty())
		return result;
	int len = WideCharToMultiByte(codePage, 0, in.data(), int(in.size()), nullptr, 0, nullptr, nullptr);
	result.resize(size_t(len), 0);
	len = WideCharToMultiByte(codePage, 0, in.data(), int(in.size()), &result[0], len, nullptr, nullptr);
	return result;
}

static std::string
toUTF8(const std::wstring& in)
{
	return toMultiByte(CP_UTF8, in);
}


#endif

static std::string toUTF8(const std::string &in)
{
#ifdef _WIN32
	return toMultiByte(CP_UTF8, toWide(CP_ACP, in));
#else
	return in;
#endif
}

static std::vector<unsigned char> readFile(const std::string &path)
{
	std::vector<unsigned char> data;
#ifdef _WIN32
	std::ifstream f(toWide(CP_UTF8, path).c_str(), std::ifstream::binary);
#else
	std::ifstream f(path, std::ifstream::binary);
#endif
	if (!f)
		return data;
	f.seekg(0, std::ifstream::end);
	data.resize(size_t(f.tellg()));
	f.clear();
	f.seekg(0);
	f.read((char*)data.data(), std::streamsize(data.size()));
	return data;
}

static void writeFile(const std::string &path, const std::vector<unsigned char> &data)
{
#ifdef _WIN32
	std::ofstream f(toWide(CP_UTF8, path).c_str(), std::ofstream::binary);
#else
	std::ofstream f(path.c_str(), std::ofstream::binary);
#endif
	f.write((const char*)data.data(), std::streamsize(data.size()));
}

} // vectorwrapbuf

// A source implementation that always keeps last 16 bytes in tag

struct TaggedSource : public libcdoc::DataSource {
	std::vector<uint8_t> tag;
	libcdoc::DataSource *_src;
	bool _owned;

	TaggedSource(libcdoc::DataSource *src, bool take_ownership, size_t tag_size) : tag(tag_size), _src(src), _owned(take_ownership) {
		tag.resize(tag.size());
		_src->read(tag.data(), tag.size());
	}
	~TaggedSource() {
		if (_owned) delete(_src);
	}

    libcdoc::result_t seek(size_t pos) override final {
        if (!_src->seek(pos)) return libcdoc::INPUT_STREAM_ERROR;
        if (_src->read(tag.data(), tag.size()) != tag.size()) return libcdoc::INPUT_STREAM_ERROR;
        return libcdoc::OK;
	}

    libcdoc::result_t read(uint8_t *dst, size_t size) override final {
		std::vector<uint8_t> t(tag.size());
		uint8_t *tmp = t.data();
		size_t nread = _src->read(dst, size);
		if (nread >= tag.size()) {
			std::copy(dst + nread - tag.size(), dst + nread, tmp);
			std::copy_backward(dst, dst + nread - tag.size(), dst + nread);
			std::copy(tag.cbegin(), tag.cend(), dst);
			std::copy(tmp, tmp + tag.size(), tag.begin());
		} else {
			std::copy(dst, dst + nread, tmp);
			std::copy(tag.cbegin(), tag.cbegin() + nread, dst);
			std::copy(tag.cbegin() + nread, tag.cend(), tag.begin());
			std::copy(tmp, tmp + nread, tag.end() - nread);
		}
		return nread;
	}

	virtual bool isError() override final {
		return _src->isError();
	}
	virtual bool isEof() override final {
		return _src->isEof();
	}
};

#endif // UTILS_H
