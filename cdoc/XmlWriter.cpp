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

#include "XmlWriter.h"

#include "Utils.h"

#include <openssl/evp.h>
#include <libxml/xmlwriter.h>

using namespace libcdoc;

typedef const xmlChar *pcxmlChar;

struct XMLWriter::Private
{
	xmlTextWriterPtr w = nullptr;
	std::map<std::string, int> nsmap;

	libcdoc::DataConsumer* dst = nullptr;
	bool dst_owned = false;

	xmlOutputBufferPtr obuf = nullptr;

	static int xmlOutputWriteCallback (void *context, const char *buffer, int len);
	static int xmlOutputCloseCallback (void *context);
};

int
XMLWriter::Private::xmlOutputWriteCallback (void *context, const char *buffer, int len)
{
	XMLWriter *writer = reinterpret_cast<XMLWriter *>(context);
	return writer->d->dst->write((uint8_t *) buffer, len);
}

int
XMLWriter::Private::xmlOutputCloseCallback (void *context)
{
	XMLWriter *writer = reinterpret_cast<XMLWriter *>(context);
	return writer->d->dst->close();
}

XMLWriter::XMLWriter(libcdoc::DataConsumer* dst)
	: d(new Private)
{
	d->dst = dst;
	d->obuf = xmlOutputBufferCreateIO(Private::xmlOutputWriteCallback,  Private::xmlOutputCloseCallback, this, nullptr);
	d->w = xmlNewTextWriter(d->obuf);
	xmlTextWriterStartDocument(d->w, nullptr, "UTF-8", nullptr);
}


XMLWriter::XMLWriter(std::ostream *ofs)
	: d(new Private)
{
	d->dst = new libcdoc::OStreamConsumer(ofs);
	d->dst_owned = true;
	d->obuf = xmlOutputBufferCreateIO(Private::xmlOutputWriteCallback,  Private::xmlOutputCloseCallback, this, nullptr);
	d->w = xmlNewTextWriter(d->obuf);
	xmlTextWriterStartDocument(d->w, nullptr, "UTF-8", nullptr);
}

XMLWriter::XMLWriter(const std::string& path)
	: d(new Private)
{
	d->dst = new libcdoc::OStreamConsumer(path);
	d->dst_owned = true;
	d->obuf = xmlOutputBufferCreateIO(Private::xmlOutputWriteCallback,  Private::xmlOutputCloseCallback, this, nullptr);
	d->w = xmlNewTextWriter(d->obuf);
	xmlTextWriterStartDocument(d->w, nullptr, "UTF-8", nullptr);
}

XMLWriter::XMLWriter(std::vector<uint8_t>& vec)
	: d(new Private)
{
	d->dst = new libcdoc::VectorConsumer(vec);
	d->dst_owned = true;
	d->obuf = xmlOutputBufferCreateIO(Private::xmlOutputWriteCallback,  Private::xmlOutputCloseCallback, this, nullptr);
	d->w = xmlNewTextWriter(d->obuf);
	xmlTextWriterStartDocument(d->w, nullptr, "UTF-8", nullptr);
}

XMLWriter::~XMLWriter()
{
	xmlTextWriterEndDocument(d->w);
	xmlFreeTextWriter(d->w);
	xmlOutputBufferClose(d->obuf);
	if(d->dst && d->dst_owned) delete d->dst;
	delete d;
}

void XMLWriter::writeStartElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr)
{
	std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
	if (pos != d->nsmap.cend())
		pos->second++;
	else
		pos = d->nsmap.insert({ns.prefix, 1}).first;
	if(!d->w)
		return;
	if(xmlTextWriterStartElementNS(d->w, ns.prefix.empty() ? nullptr : pcxmlChar(ns.prefix.c_str()),
		pcxmlChar(name.c_str()), pos->second > 1 ? nullptr : pcxmlChar(ns.ns.c_str())) < 0)
		return;
	for(auto i = attr.cbegin(), end = attr.cend(); i != end; ++i)
	{
		if(xmlTextWriterWriteAttribute(d->w, pcxmlChar(i->first.c_str()), pcxmlChar(i->second.c_str())) < 0)
			break;
	}
}

void XMLWriter::writeEndElement(const NS &ns)
{
	if(d->w)
		xmlTextWriterEndElement(d->w);
	std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
	if (pos != d->nsmap.cend())
		pos->second--;
}

void XMLWriter::writeElement(const NS &ns, const std::string &name, const std::function<void()> &f)
{
	writeStartElement(ns, name, {});
	if(f)
		f();
	writeEndElement(ns);
}

void XMLWriter::writeElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<void()> &f)
{
	writeStartElement(ns, name, attr);
	if(f)
		f();
	writeEndElement(ns);
}

void XMLWriter::writeBase64Element(const NS &ns, const std::string &name, const std::vector<xmlChar> &data, const std::map<std::string, std::string> &attr)
{
	if (!d->w)
		return;
	static const size_t bufLen = 48 * 10240;
	std::vector<xmlChar> result(((bufLen + 2) / 3) * 4, 0);
	writeStartElement(ns, name, attr);
	for (size_t i = 0; i < data.size(); i += bufLen)
	{
		int size = EVP_EncodeBlock(result.data(), &data[i], std::min(data.size() - i, bufLen));
		if(size == 0)
			break;
		if(xmlTextWriterWriteRawLen(d->w, result.data(), size) < 0)
			break;
	}
	writeEndElement(ns);
}

void XMLWriter::writeTextElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::string &data)
{
	writeStartElement(ns, name, attr);
	if(d->w)
		(void)xmlTextWriterWriteString(d->w, pcxmlChar(data.c_str()));
	writeEndElement(ns);
}
