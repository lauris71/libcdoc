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

#include "DDocWriter.h"

using namespace libcdoc;

/**
 * @class DDOCWriter
 * @brief DDOCWriter is used for storing multiple files.
 */

struct DDOCWriter::Private
{
	static const NS DDOC;
	int fileCount = 0;
};

const XMLWriter::NS DDOCWriter::Private::DDOC{ "", "http://www.sk.ee/DigiDoc/v1.3.0#" };

/**
 * DDOCWriter constructor.
 * @param file File to be created
 */
DDOCWriter::DDOCWriter(const std::string &file)
	: XMLWriter(file)
	, d(new Private)
{
	writeStartElement(Private::DDOC, "SignedDoc", {{"format", "DIGIDOC-XML"}, {"version", "1.3"}});
}

DDOCWriter::DDOCWriter(std::vector<uint8_t>& vec)
	: XMLWriter(vec),
	  d(new Private)
{
	writeStartElement(Private::DDOC, "SignedDoc", {{"format", "DIGIDOC-XML"}, {"version", "1.3"}});
}

DDOCWriter::~DDOCWriter()
{
	writeEndElement(Private::DDOC); // SignedDoc
	delete d;
}

/**
 * Add File to container
 * @param file Filename
 * @param mime File mime type
 * @param data File content
 */
void DDOCWriter::addFile(const std::string &file, const std::string &mime, const std::vector<unsigned char> &data)
{
	writeBase64Element(Private::DDOC, "DataFile", data, {
		{"ContentType", "EMBEDDED_BASE64"},
		{"Filename", file},
		{"Id", "D" + std::to_string(d->fileCount++)},
		{"MimeType", mime},
		{"Size", std::to_string(data.size())}
	});
}
