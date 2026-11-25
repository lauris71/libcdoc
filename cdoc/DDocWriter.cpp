// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "DDocWriter.h"

#include "Io.h"

using namespace libcdoc;

/**
 * @class DDOCWriter
 * @brief DDOCWriter is used for storing multiple files.
 */

constexpr XMLWriter::NS DDOC{ nullptr, "http://www.sk.ee/DigiDoc/v1.3.0#" };

DDOCWriter::DDOCWriter(DataConsumer &dst)
    : XMLWriter(dst)
    , state(writeStartElement(DDOC, "SignedDoc", {{"format", "DIGIDOC-XML"}, {"version", "1.3"}}))
{
}

DDOCWriter::~DDOCWriter() noexcept
{
    writeEndElement(DDOC); // SignedDoc
}

/**
 * Add File to container
 * @param file Filename
 * @param mime File mime type
 * @param size File size
 * @param data File content
 */
int64_t DDOCWriter::addFile(const std::string &file, const std::string &mime, size_t size, libcdoc::DataSource& src)
{
    if (state != OK)
        return state;
    return writeBase64Element(DDOC, "DataFile", [&src](DataConsumer &dst){ return src.readAll(dst); }, {
        {"ContentType", "EMBEDDED_BASE64"},
        {"Filename", file},
        {"Id", "D" + std::to_string(fileCount++)},
        {"MimeType", mime},
        {"Size", std::to_string(size)}
    });
}

/**
 * Add File to container
 * @param file Filename
 * @param mime File mime type
 * @param data File content
 */
int64_t DDOCWriter::addFile(const std::string &file, const std::string &mime, const std::vector<unsigned char> &data)
{
    if (state != OK)
        return state;
    return writeBase64Element(DDOC, "DataFile", data, {
        {"ContentType", "EMBEDDED_BASE64"},
        {"Filename", file},
        {"Id", "D" + std::to_string(fileCount++)},
        {"MimeType", mime},
        {"Size", std::to_string(data.size())}
    });
}
