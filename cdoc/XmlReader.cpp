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

#include "XmlReader.h"

#include "Crypto.h"
#include "Io.h"

#include <libxml/xmlreader.h>

using namespace libcdoc;

typedef const xmlChar *pcxmlChar;

struct XMLReader::Private
{
	xmlTextReaderPtr reader = nullptr;

	libcdoc::DataSource *_src = nullptr;
	bool _delete_src = false;

	xmlParserInputBufferPtr ibuf = nullptr;

	std::string tostring(const xmlChar *tmp)
	{
		std::string result;
		if(!tmp)
			return result;
		result = (const char*)tmp;
		return result;
	}

	static int xmlInputReadCallback (void *context, char *buffer, int len);
	static int xmlInputCloseCallback (void *context);
};

int
XMLReader::Private::xmlInputReadCallback (void *context, char *buffer, int len)
{
	XMLReader *reader = reinterpret_cast<XMLReader *>(context);
    int64_t n_read = reader->d->_src->read((uint8_t *) buffer, len);
    //std::string str(buffer, len);
    //std::cerr << "XML read (" << n_read << "):" << str << std::endl;
    return n_read;
}

int
XMLReader::Private::xmlInputCloseCallback (void *context)
{
	XMLReader *reader = reinterpret_cast<XMLReader *>(context);
	int result = ((reader->d->_src && !reader->d->_src->isError())) ? 0 : -1;
	if (reader->d->_src && reader->d->_delete_src) {
		delete reader->d->_src;
		reader->d->_src = nullptr;
	}
	return result;
}

XMLReader::XMLReader(libcdoc::DataSource *src, bool delete_on_close)
	: d(new Private)
{
	d->_src = src;
	d->_delete_src = delete_on_close;
	d->ibuf = xmlParserInputBufferCreateIO(Private::xmlInputReadCallback, Private::xmlInputCloseCallback, this, XML_CHAR_ENCODING_UTF8);
	d->reader = xmlNewTextReader(d->ibuf, "");
}

XMLReader::XMLReader(std::istream *ifs, bool delete_on_close)
	: XMLReader(new libcdoc::IStreamSource(ifs, delete_on_close), true)
{
}

XMLReader::XMLReader(const std::string &file)
	: d(new Private)
{
	d->reader = xmlReaderForFile(file.c_str(), nullptr, XML_PARSE_HUGE);
}

XMLReader::XMLReader(const std::vector<uint8_t> &data)
	: d(new Private)
{
	d->reader = xmlReaderForMemory((const char*)data.data(), int(data.size()), nullptr, nullptr, XML_PARSE_HUGE);
}

XMLReader::~XMLReader()
{
	xmlFreeTextReader(d->reader);
	xmlFreeParserInputBuffer(d->ibuf);
	if(d->_src && d->_delete_src) delete d->_src;
	delete d;
}

std::string XMLReader::attribute(const char *attr) const
{
	xmlChar *tmp = xmlTextReaderGetAttribute(d->reader, pcxmlChar(attr));
	std::string result = d->tostring(tmp);
	xmlFree(tmp);
	return result;
}

bool XMLReader::isEndElement() const
{
	return xmlTextReaderNodeType(d->reader) == XML_READER_TYPE_END_ELEMENT;
}

bool XMLReader::isElement(const char *elem) const
{
	return xmlStrEqual(xmlTextReaderConstLocalName(d->reader), pcxmlChar(elem)) == 1;
}

bool XMLReader::read()
{
	return xmlTextReaderRead(d->reader) == 1;
}

std::vector<uint8_t> XMLReader::readBase64()
{
	xmlTextReaderRead(d->reader);
	return libcdoc::Crypto::decodeBase64(xmlTextReaderConstValue(d->reader));
}

std::string XMLReader::readText()
{
	xmlTextReaderRead(d->reader);
	return d->tostring(xmlTextReaderConstValue(d->reader));
}
