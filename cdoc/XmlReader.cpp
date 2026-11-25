// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "XmlReader.h"

#include "Crypto.h"
#include "Io.h"
#include "Utils.h"

#include <libxml/xmlreader.h>

using namespace libcdoc;

using pcxmlChar = const xmlChar *;

#if LIBXML_VERSION >= 21300
constexpr int XML_READ_FLAGS = XML_PARSE_NONET|XML_PARSE_HUGE|XML_PARSE_NODICT|XML_PARSE_NO_XXE;
#else
constexpr int XML_READ_FLAGS = XML_PARSE_NONET|XML_PARSE_HUGE|XML_PARSE_NODICT;
#endif

static std::string tostring(pcxmlChar tmp)
{
    std::string result;
    if(!tmp)
        return result;
    result = (const char*)tmp;
    return result;
}

XMLReader::XMLReader(libcdoc::DataSource &src)
    : d(xmlReaderForIO([](void *context, char *buffer, int len) -> int {
        auto *src = reinterpret_cast<DataSource *>(context);
        auto result = src->read((uint8_t *) buffer, len);
        return result >= OK ? result : -1;
    }, nullptr, &src, nullptr, nullptr, XML_READ_FLAGS))
    , error(!d)
{}

XMLReader::~XMLReader() noexcept
{
    xmlFreeTextReader(d);
}

std::string XMLReader::attribute(const char *attr) const
{
    if (!d) return {};
    xmlChar *tmp = xmlTextReaderGetAttribute(d, pcxmlChar(attr));
    std::string result = tostring(tmp);
    xmlFree(tmp);
    return result;
}

bool XMLReader::isEndElement() const
{
    if (!d) return false;
    return xmlTextReaderNodeType(d) == XML_READER_TYPE_END_ELEMENT;
}

bool XMLReader::isElement(const char *elem) const
{
    if (!d) return false;
    return xmlStrEqual(xmlTextReaderConstLocalName(d), pcxmlChar(elem)) == 1;
}

bool XMLReader::read()
{
    if (!d) return false;
    if (int result = xmlTextReaderRead(d); result != 1)
    {
        error = result < 0;
        if (error)
            LOG_ERROR("XMLReader: failed to parse document");
        return false;
    }
    switch(xmlTextReaderNodeType(d))
    {
    case XML_READER_TYPE_DOCUMENT_TYPE:
    case XML_READER_TYPE_ENTITY_REFERENCE:
        error = true;
        LOG_ERROR("XMLReader: document type declaration or entity reference is not allowed");
        return false;
    default:
        return true;
    }
}

std::vector<uint8_t> XMLReader::readBase64()
{
    if (!d) return {};
    xmlTextReaderRead(d);
    if (xmlTextReaderNodeType(d) == XML_READER_TYPE_ENTITY_REFERENCE)
        return {};
    return libcdoc::Crypto::decodeBase64(xmlTextReaderConstValue(d));
}

std::string XMLReader::readText()
{
    if (!d) return {};
    xmlTextReaderRead(d);
    if (xmlTextReaderNodeType(d) == XML_READER_TYPE_ENTITY_REFERENCE)
        return {};
    return tostring(xmlTextReaderConstValue(d));
}
