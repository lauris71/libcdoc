// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "XmlWriter.h"

#include "Io.h"
#include "Utils.h"

#include <algorithm>
#include <array>

namespace {

static constexpr void encodeBase64Group(const uint8_t *src, size_t count, char *out)
{
    constexpr char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t v = uint32_t(src[0]) << 16;
    if(count > 1)
        v |= uint32_t(src[1]) << 8;
    if(count > 2)
        v |= src[2];
    out[0] = B64[v >> 18 & 63];
    out[1] = B64[v >> 12 & 63];
    out[2] = count > 1 ? B64[v >> 6 & 63] : '=';
    out[3] = count > 2 ? B64[v & 63] : '=';
}

constexpr bool isValidXmlText(std::string_view str)
{
    for (size_t pos = 0; pos < str.size();) {
        auto byte = [&](size_t i) { return static_cast<uint8_t>(str[pos + i]); };
        char32_t c;
        size_t len;
        if (byte(0) < 0x80) { c = byte(0); len = 1; }
        else if ((byte(0) & 0xe0) == 0xc0) { c = byte(0) & 0x1f; len = 2; }
        else if ((byte(0) & 0xf0) == 0xe0) { c = byte(0) & 0x0f; len = 3; }
        else if ((byte(0) & 0xf8) == 0xf0) { c = byte(0) & 0x07; len = 4; }
        else return false;
        if (str.size() - pos < len) return false;
        for (size_t i = 1; i < len; ++i) {
            if ((byte(i) & 0xc0) != 0x80) return false;
            c = c << 6 | (byte(i) & 0x3f);
        }
        constexpr char32_t minValue[] {0, 0, 0x80, 0x800, 0x10000};
        if (c < minValue[len]) return false; // overlong encoding
        // XML 1.0 Char: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
        if (!(c == 0x9 || c == 0xA || c == 0xD ||
              (c >= 0x20 && c <= 0xD7FF) ||
              (c >= 0xE000 && c <= 0xFFFD) ||
              (c >= 0x10000 && c <= 0x10FFFF)))
            return false;
        pos += len;
    }
    return true;
}

static_assert([] {
    constexpr uint8_t in[] {'M', 'a', 'n'};
    char out[12] {};
    encodeBase64Group(in, 3, out);
    encodeBase64Group(in, 2, out + 4);
    encodeBase64Group(in, 1, out + 8);
    return std::string_view(out, 12) == "TWFuTWE=TQ==";
}());

static_assert(isValidXmlText("a\tb\nc\rd \xC3\xB5 \xF0\x9F\x98\x80"));
static_assert(!isValidXmlText("a\x01" "b"));
static_assert(!isValidXmlText("\xED\xA0\x80"));

}

using namespace libcdoc;

XMLWriter::XMLWriter(DataConsumer &dst)
    : dst(dst)
{}

void XMLWriter::escape(std::string_view in, bool attribute)
{
    for(char c: in)
    {
        switch(c)
        {
        case '&': buf += "&amp;"; break;
        case '<': buf += "&lt;"; break;
        case '>': buf += "&gt;"; break;
        case '\r': buf += "&#13;"; break;
        case '\t': buf += attribute ? "&#9;" : "\t"; break;
        case '\n': buf += attribute ? "&#10;" : "\n"; break;
        case '"': buf += attribute ? "&quot;" : "\""; break;
        default: buf += c;
        }
    }
}

int64_t XMLWriter::write(std::string_view str) noexcept
{
    if(str.empty())
        return OK;
    if(auto rv = dst.write(reinterpret_cast<const uint8_t*>(str.data()), str.size()); rv < 0)
        return rv;
    return OK;
}

int64_t XMLWriter::writeStartElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr)
{
    // Validate before touching nsmap/stack so a rejected element leaves no state behind.
    for(const auto &[aname, avalue]: attr)
        if(!isValidXmlText(avalue))
            return DATA_FORMAT_ERROR;
    std::string qname;
    if(!ns.prefix.empty())
        (qname += ns.prefix) += ':';
    qname += name;

    if(!isStarted)
    {
        if(auto rv = write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"); rv != OK)
            return rv;
        isStarted = true;
    }
    buf.clear();
    buf += '<';
    buf += qname;
    // Declare the namespace only on its first (outermost) open element; nested
    // elements with the same prefix inherit it.
    if(auto &count = nsmap[ns.prefix]; ++count == 1 && !ns.ns.empty())
    {
        buf += !ns.prefix.empty() ? " xmlns:" : " xmlns";
        if(!ns.prefix.empty())
            buf += ns.prefix;
        buf += "=\"";
        buf += ns.ns; // namespace URIs are compile-time constants, no escaping needed
        buf += '"';
    }
    for(const auto &[aname, avalue]: attr)
    {
        (buf += ' ') += aname;
        buf += "=\"";
        escape(avalue, true);
        buf += '"';
    }
    buf += '>';
    stack.push_back(std::move(qname));
    return write(buf);
}

int64_t XMLWriter::writeEndElement(NS ns)
{
    if(stack.empty())
        return WRONG_ARGUMENTS;
    buf.clear();
    buf += "</";
    buf += stack.back();
    buf += '>';
    stack.pop_back();
    if(auto pos = nsmap.find(ns.prefix); pos != nsmap.cend())
        pos->second--;
    return write(buf);
}

int64_t XMLWriter::writeElement(NS ns, std::string_view name, const std::function<int64_t()> &f)
{
    return writeElement(ns, name, {}, f);
}

int64_t XMLWriter::writeElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr, const std::function<int64_t()> &f)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(int64_t rv = OK; f && (rv = f()) != OK)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeBase64(const uint8_t *src, size_t len) noexcept
{
    if(!src || len == 0)
        return OK;
    std::array<char, 4092> buf; // multiple of 4; flushed once full
    size_t n = 0, i = 0;
    for(; i + 3 <= len; i += 3)
    {
        encodeBase64Group(src + i, 3, buf.data() + n);
        if(n += 4; n == buf.size())
        {
            if(auto rv = write({buf.data(), n}); rv < 0)
                return rv;
            n = 0;
        }
    }
    if(size_t rem = len - i; rem > 0)
    {
        encodeBase64Group(src + i, rem, buf.data() + n);
        n += 4;
    }
    return write({buf.data(), n});
}

int64_t XMLWriter::writeBase64Element(NS ns, std::string_view name, const std::function<int64_t(DataConsumer&)> &f, const std::map<std::string_view, std::string> &attr)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;

    struct Base64Consumer: public DataConsumer {
        XMLWriter &w;
        std::array<uint8_t, 3> buf {}; // up to 2 leftover bytes between writes
        size_t bufSize = 0;
        result_t error = OK;
        Base64Consumer(XMLWriter &w): w(w) {}
        result_t write(const uint8_t *src, size_t size) noexcept final {
            if(error != OK)
                return error;
            if(!src || size == 0)
                return OK;
            size_t pos = 0;
            if(bufSize > 0) {
                pos = std::min(buf.size() - bufSize, size);
                std::copy(src, src + pos, buf.begin() + bufSize);
                bufSize += pos;
                if(bufSize < 3)
                    return result_t(size);
                if(auto rv = w.writeBase64(buf.data(), buf.size()); rv != OK)
                    return error = rv;
                bufSize = 0;
            }
            // Emit the largest chunk whose length is a multiple of 3 (no padding).
            size_t remaining = size - pos;
            if(size_t fullTriples = remaining - remaining % 3; fullTriples > 0) {
                if(auto rv = w.writeBase64(src + pos, fullTriples); rv != OK)
                    return error = rv;
                pos += fullTriples;
            }
            // Buffer the trailing 0..2 bytes for the next write / close().
            if(bufSize = size - pos; bufSize > 0)
                std::copy(src + pos, src + size, buf.begin());
            return result_t(size);
        }
        result_t close() noexcept final {
            if(error != OK)
                return error;
            if(auto rv = w.writeBase64(buf.data(), bufSize); rv != OK)
                return error = rv;
            bufSize = 0;
            return OK;
        }
        bool isError() noexcept final { return error != OK; }
    } base64Consumer {*this};
    if(auto rv = f(base64Consumer); rv < 0)
        return rv;
    if(auto rv = base64Consumer.close(); rv < 0)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeBase64Element(NS ns, std::string_view name, const std::vector<unsigned char> &data, const std::map<std::string_view, std::string> &attr)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(auto rv = writeBase64(data.data(), data.size()); rv != OK)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeTextElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr, std::string_view data)
{
    if(!isValidXmlText(data))
        return DATA_FORMAT_ERROR;
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    // writeStartElement already flushed buf, so it is free to reuse for the text.
    buf.clear();
    escape(data, false);
    if(auto rv = write(buf); rv != OK)
        return rv;
    return writeEndElement(ns);
}
