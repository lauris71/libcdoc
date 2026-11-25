// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef TAR_H
#define TAR_H

#include <cdoc/Io.h>

namespace libcdoc {

struct Header;

struct TarConsumer final : public MultiDataConsumer
{
public:
	TarConsumer(DataConsumer *dst, bool take_ownership);
    ~TarConsumer() final;

    libcdoc::result_t write(const uint8_t *src, size_t size) noexcept final;
    libcdoc::result_t close() noexcept final;
    bool isError() noexcept final;
    libcdoc::result_t open(const std::string& name, int64_t size) final;
private:
    result_t writeHeader(const Header &h) noexcept;
    result_t writeHeader(const std::string& name, int64_t size, char typeflag = '0') noexcept;
    result_t writePadding(int64_t size) noexcept;

	DataConsumer *_dst;
	bool _owned;
	int64_t _current_size = 0;
	int64_t _current_written = 0;
};

struct TarSource final : public MultiDataSource
{
public:
	TarSource(DataSource *src, bool take_ownership);
    ~TarSource() final;
    libcdoc::result_t read(uint8_t *dst, size_t size) noexcept final;
    bool isError() noexcept final;
    bool isEof() noexcept final;
    libcdoc::result_t getNumComponents() final { return NOT_IMPLEMENTED; };
    libcdoc::result_t next(std::string& name, int64_t& size) final;
private:
	DataSource *_src;
	bool _owned;
    bool _eof = false;
    int _error = OK;
    size_t _block_size = 0;
    size_t _data_size = 0;
    size_t _pos = 0;

	libcdoc::result_t readPaxHeader(const Header& hdr, std::string& name, int64_t& size);
};

} // namespace libcdoc

#endif // TAR_H
