// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "XmlWriter.h"

#include "Io.h"

#include <libxml/xmlwriter.h>

#include <array>

using namespace libcdoc;

using pcxmlChar = xmlChar *;

XMLWriter::XMLWriter(libcdoc::DataConsumer &dst)
    : w(make_unique_ptr(xmlNewTextWriter(xmlOutputBufferCreateIO([](void *context, const char *buffer, int len) -> int {
        auto *dst = reinterpret_cast<libcdoc::DataConsumer *>(context);
        auto result = dst->write((uint8_t *) buffer, len);
        return result >= OK ? result : -1;
    }, nullptr, &dst, nullptr)), xmlFreeTextWriter))
{
    if(w)
        xmlTextWriterStartDocument(w.get(), nullptr, "UTF-8", nullptr);
}

XMLWriter::~XMLWriter() noexcept
{
    if(w)
        xmlTextWriterEndDocument(w.get());
}

int64_t XMLWriter::writeStartElement(NS ns, const char *name, const std::map<const char *, std::string> &attr)
{
    if(!w)
        return WRONG_ARGUMENTS;
    auto &count = nsmap[ns.prefix ? ns.prefix : std::string_view{}];
    count++;
    if(xmlTextWriterStartElementNS(w.get(), pcxmlChar(ns.prefix), pcxmlChar(name), count > 1 ? nullptr : pcxmlChar(ns.ns)) == -1)
        return IO_ERROR;
    for(const auto &[name, content]: attr)
    {
        if(xmlTextWriterWriteAttribute(w.get(), pcxmlChar(name), pcxmlChar(content.c_str())) == -1)
            return IO_ERROR;
    }
    return OK;
}

int64_t XMLWriter::writeEndElement(NS ns)
{
    if(!w)
        return WRONG_ARGUMENTS;
    if(xmlTextWriterEndElement(w.get()) == -1)
        return IO_ERROR;
    if(auto pos = nsmap.find(ns.prefix ? ns.prefix : ""); pos != nsmap.cend())
        pos->second--;
    return OK;
}

int64_t XMLWriter::writeElement(NS ns, const char *name, const std::function<int64_t()> &f)
{
    if(auto rv = writeStartElement(ns, name, {}); rv != OK)
        return rv;
    if(int64_t rv = OK; f && (rv = f()) != OK)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeElement(NS ns, const char *name, const std::map<const char *, std::string> &attr, const std::function<int64_t()> &f)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(int64_t rv = OK; f && (rv = f()) != OK)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeBase64Element(NS ns, const char *name, const std::function<int64_t(DataConsumer&)> &f, const std::map<const char *, std::string> &attr)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;

    struct Base64Consumer : public DataConsumer {
        xmlTextWriterPtr w;
        std::array<uint8_t, 3> buf {}; // buffer up to 2 leftover bytes
        size_t bufSize = 0;
        Base64Consumer(xmlTextWriterPtr _w) : w(_w) {}
        result_t write(const uint8_t *src, size_t size) noexcept final {
            if(!src || size == 0)
                return OK;

            size_t pos = 0;
            if(bufSize > 0) {
                pos = std::min(buf.size() - bufSize, size);
                std::copy(src, src + pos, buf.begin() + bufSize);
                bufSize += pos;
                if (bufSize < 3) {
                    return result_t(size);
                }
                if (xmlTextWriterWriteBase64(w, reinterpret_cast<const char*>(buf.data()), 0, buf.size()) == -1)
                    return IO_ERROR;
                bufSize = 0;
            }

            // Write largest contiguous chunk with length multiple of 3
            size_t remaining = size - pos;
            if(size_t fullTriples = remaining - (remaining % 3); fullTriples > 0) {
                if (xmlTextWriterWriteBase64(w, reinterpret_cast<const char*>(src), pos, fullTriples) == -1)
                    return IO_ERROR;
                pos += fullTriples;
            }

            // Buffer leftover (0..2) bytes for next write/close
            if(bufSize = size - pos; bufSize > 0) {
                std::copy(src + pos, src + size, buf.begin());
            }

            return result_t(size);
        }
        result_t close() noexcept final {
            if (bufSize > 0) {
                // write remaining 1..2 bytes so base64 padding is applied only at the end
                if(xmlTextWriterWriteBase64(w, reinterpret_cast<const char*>(buf.data()), 0, bufSize) == -1)
                    return IO_ERROR;
            }
            bufSize = 0;
            return OK;
        }
        bool isError() noexcept final { return false; }
    } base64Consumer {w.get()};
    if(auto rv = f(base64Consumer); rv < 0)
        return rv;
    if(auto rv = base64Consumer.close(); rv < 0)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeBase64Element(NS ns, const char *name, const std::vector<xmlChar> &data, const std::map<const char *, std::string> &attr)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(xmlTextWriterWriteBase64(w.get(), reinterpret_cast<const char*>(data.data()), 0, data.size()) == -1)
        return IO_ERROR;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeTextElement(NS ns, const char *name, const std::map<const char *, std::string> &attr, const std::string &data)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(xmlTextWriterWriteString(w.get(), pcxmlChar(data.c_str())) == -1)
        return IO_ERROR;
    return writeEndElement(ns);
}
