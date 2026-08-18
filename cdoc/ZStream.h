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

#ifndef __ZSTREAM_H__
#define __ZSTREAM_H__

#include "Io.h"

#include <zlib.h>

#include <array>
#include <limits>

namespace libcdoc {

struct ZConsumer : public DataConsumer {
	static constexpr uint64_t CHUNK = 16LL * 1024LL;
    DataConsumer *_dst;
    bool _owned;
	z_stream _s {};
    bool _fail = false;
	int flush = Z_NO_FLUSH;
    ZConsumer(DataConsumer *dst, bool take_ownership = false)
        : _dst(dst), _owned(take_ownership) {
		if (deflateInit(&_s, Z_DEFAULT_COMPRESSION) != Z_OK) _fail = true;
	}
	~ZConsumer() {
		if (!_fail) deflateEnd(&_s);
        if (_owned) delete _dst;
	}

    libcdoc::result_t write(const uint8_t *src, size_t size) noexcept final {
		if (_fail) return OUTPUT_ERROR;
		size_t total_written = 0;
		std::array<uint8_t,CHUNK> out{};
		do {
			size_t chunk = std::min<size_t>(size - total_written, std::numeric_limits<uInt>::max());
			_s.next_in = (z_const Bytef *) (src ? src + total_written : nullptr);
			_s.avail_in = uInt(chunk);
			while(true) {
				_s.next_out = (Bytef *)out.data();
				_s.avail_out = out.size();
				int res = deflate(&_s, flush);
				if(res == Z_STREAM_ERROR)
					return OUTPUT_ERROR;
				auto o_size = out.size() - _s.avail_out;
				if(o_size > 0) {
					int64_t result = _dst->write(out.data(), o_size);
					if (result != o_size) return result;
				}
				if(res == Z_STREAM_END) break;
				if(flush == Z_FINISH) continue;
				if(_s.avail_in == 0) break;
			}
			total_written += chunk;
		} while (total_written < size);
		return size;
	}

    virtual bool isError() noexcept final {
        return _fail || _dst->isError();
	};

    libcdoc::result_t close() noexcept final {
		flush = Z_FINISH;
		libcdoc::result_t rv = write(nullptr, 0);
		if (rv < 0) return rv;
        return _owned ? _dst->close() : OK;
	}
};

struct ZSource : public DataSource {
	static constexpr uint64_t CHUNK = 16LL * 1024LL;
    DataSource *_src;
    bool _owned;
	z_stream _s {};
    int64_t _error = OK;
	std::vector<uint8_t> buf;
	int flush = Z_NO_FLUSH;
    /// Maximum total bytes this source will produce. 0 means unlimited.
    /// Prevents decompression bombs (N7).
    int64_t max_decompressed_size = 0;
    int64_t total_inflated = 0;
    ZSource(DataSource *src, bool take_ownership = false, int64_t max_size = 0)
        : _src(src), _owned(take_ownership), max_decompressed_size(max_size) {
		if (inflateInit2(&_s, MAX_WBITS) != Z_OK) {
			_error = ZLIB_ERROR;
		}
	}
	~ZSource() {
		if (!_error) inflateEnd(&_s);
        if (_owned) delete _src;
	}

    libcdoc::result_t read(uint8_t *dst, size_t size) noexcept final try {
		if (_error) return _error;
		size_t total_produced = 0;
        std::array<uint8_t,CHUNK> in{};
		while (total_produced < size) {
			size_t chunk = std::min<size_t>(size - total_produced, std::numeric_limits<uInt>::max());
			_s.next_out = (Bytef *) (dst + total_produced);
			_s.avail_out = uInt(chunk);
			int res = Z_OK;
			while((_s.avail_out > 0) && (res == Z_OK)) {
				int64_t n_read = _src->read(in.data(), in.size());
				if (n_read > 0) {
					buf.insert(buf.end(), in.begin(), in.begin() + n_read);
				} else if (n_read != 0) {
					inflateEnd(&_s);
					_error = n_read;
					return _error;
				}
				size_t buf_chunk = std::min<size_t>(buf.size(), std::numeric_limits<uInt>::max());
				_s.next_in = (z_const Bytef *) buf.data();
				_s.avail_in = uInt(buf_chunk);
				res = inflate(&_s, flush);
				switch(res) {
				case Z_OK:
					buf.erase(buf.begin(), buf.begin() + (buf_chunk - _s.avail_in));
					break;
				case Z_STREAM_END:
					buf.clear();
					break;
				default:
					inflateEnd(&_s);
					_error = ZLIB_ERROR;
					return _error;
				}
			}
			size_t produced = chunk - _s.avail_out;
			total_produced += produced;
			total_inflated += produced;
			if (max_decompressed_size > 0 && total_inflated > max_decompressed_size) {
				inflateEnd(&_s);
				_error = IO_ERROR;
				return _error;
			}
			if (produced == 0) break; // no progress (EOF or stream end)
		}
		return total_produced;
    } catch(...) {
        return INPUT_STREAM_ERROR;
    }

    virtual bool isError() noexcept final {
        return (_error != OK) || _src->isError();
	};

    virtual bool isEof() noexcept final {
        return (_s.avail_in == 0) && _src->isEof();
	};
};

} // namespace libcdoc

#endif // ZSTREAM_H
