// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

 #include <cdoc/Io.h>

 struct PipeSource : public libcdoc::DataSource {
	PipeSource(std::vector<uint8_t>& data, bool& eof) : _data(data), _eof(eof) {}

    libcdoc::result_t read(uint8_t *dst, size_t size) noexcept override {
		size = std::min<size_t>(size, _data.size());
		std::copy(_data.cbegin(), _data.cbegin() + size, dst);
        if (_buf.size() < 1024) {
            size_t newbufsize = _buf.size() + size;
            if (newbufsize > 1024) newbufsize = 1024;
            size_t tocopy = newbufsize - _buf.size();
            _buf.insert(_buf.end(), _data.begin(), _data.begin() + tocopy);
        }
        _data.erase(_data.cbegin(), _data.cbegin() + size);
		return size;
	}

    libcdoc::result_t seek(size_t pos) override {
        if (pos <= _buf.size()) {
            _data.insert(_data.begin(), _buf.begin() + pos, _buf.end());
            _buf.erase(_buf.begin() + pos, _buf.end());
            return libcdoc::OK;
        }
        return libcdoc::NOT_IMPLEMENTED;
    }
    bool isError() noexcept override { return false; }
    bool isEof() noexcept override { return _eof; }
protected:
	std::vector<uint8_t>& _data;
    bool& _eof;
    std::vector<uint8_t> _buf;
};

struct PipeConsumer : public libcdoc::DataConsumer {
	PipeConsumer(std::vector<uint8_t>& data, bool& eof) : _data(data), _eof(eof) { _eof = false; }
    libcdoc::result_t write(const uint8_t *src, size_t size) noexcept final {
		_data.insert(_data.end(), src, src + size);
		return size;
	}
    libcdoc::result_t close() noexcept final { _eof = true; return libcdoc::OK; }
    virtual bool isError() noexcept final { return false; }
protected:
    std::vector<uint8_t>& _data;
    bool& _eof;
};

struct PipeCrypto : public libcdoc::CryptoBackend {
    PipeCrypto(std::string pwd) : _secret(pwd.cbegin(), pwd.cend()) {}

    libcdoc::result_t getSecret(std::vector<uint8_t>& dst, unsigned int idx) {
        dst = _secret;
        return libcdoc::OK;
    };

    std::vector<uint8_t> _secret;
};

struct PipeWriter {
    static constexpr size_t BUFSIZE = 1024 * 16;

    PipeWriter(libcdoc::CDocWriter *writer, const std::vector<libcdoc::FileInfo>& files) : _writer(writer), _files(files), current(-1), cpos(0) {}

    uint8_t getChar(int filenum, size_t pos) {
        uint64_t x = pos + ((uint64_t) filenum << 40);
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        x = x ^ (x >> 31);
        return (uint8_t) (x & 0xff);
    }

    libcdoc::result_t writeMore() {
        if (current >= (int) _files.size()) return libcdoc::WORKFLOW_ERROR;

        if ((current < 0) || (cpos >= _files[current].size)) {
            // Start new file
            current += 1;
            cpos = 0;
            if (current >= (int) _files.size()) {
                return _writer->finishEncryption();
            }
            return _writer->addFile(_files[current].name, _files[current].size);
        }
        size_t towrite = _files[current].size - cpos;
        if (towrite > BUFSIZE) towrite = BUFSIZE;
        uint8_t buf[BUFSIZE];
        for (int i = 0; i < towrite; i++) buf[i] = getChar(current, cpos + i);
        cpos += towrite;
        return _writer->writeData(buf, towrite);
    }

    bool isEof() {
        return current >= (int) _files.size();
    }

    int current = 0;
    size_t cpos = 0;

    libcdoc::CDocWriter *_writer;
    const std::vector<libcdoc::FileInfo>& _files;
};
