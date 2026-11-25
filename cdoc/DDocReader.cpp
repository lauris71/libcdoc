// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "DDocReader.h"
#include "CDoc.h"
#include "Io.h"

using namespace libcdoc;

int64_t
DDOCReader::parse(MultiDataConsumer *dst)
{
    while(read()) {
        if(isEndElement())
            continue;
        // EncryptedData
        if(!isElement("DataFile"))
            continue;
        std::string name = attribute("Filename");
        std::vector<uint8_t> content = readBase64();
        if (auto rv = dst->open(name, content.size()); rv != libcdoc::OK)
            return rv;
        if (auto rv = dst->write(content.data(), content.size()); rv < 0)
            return rv;
        if (auto rv = dst->close(); rv != libcdoc::OK)
            return rv;
    }
    if (hasError())
        return libcdoc::DATA_FORMAT_ERROR;
    return (dst->isError()) ? libcdoc::IO_ERROR : libcdoc::OK;
}

struct DDocFileListConsumer : public libcdoc::MultiDataConsumer {
    std::vector<DDOCReader::File> &files;

    DDocFileListConsumer(std::vector<DDOCReader::File> &_files): files(_files) {}
    int64_t write(const uint8_t *src, size_t size) noexcept final try {
        DDOCReader::File& file = files.back();
        file.data.insert(file.data.end(), src, src + size);
        return size;
    } catch(...) {
        return OUTPUT_STREAM_ERROR;
    }

    libcdoc::result_t close() noexcept final { return libcdoc::OK; }
    bool isError() noexcept final { return false; }
    libcdoc::result_t open(const std::string& name, int64_t /*size*/) final {
        files.push_back({name, "application/octet-stream", {}});
        return libcdoc::OK;
    }
};

int64_t
DDOCReader::files(std::vector<DDOCReader::File> &files)
{
    DDocFileListConsumer list{files};
    return parse(&list);
}
