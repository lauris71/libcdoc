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
