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

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <ostream>
#include <string>
#include <vector>

namespace libcdoc {

struct DataConsumer;

class XMLWriter
{
public:
	struct NS { std::string prefix, ns; };

	XMLWriter(std::ostream *ofs);
	XMLWriter(const std::string& path);
	XMLWriter(std::vector<uint8_t>& vec);
	XMLWriter(DataConsumer *dst);
	virtual ~XMLWriter();

	void writeStartElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr);
	void writeEndElement(const NS &ns);
	void writeElement(const NS &ns, const std::string &name, const std::function<void()> &f = nullptr);
	void writeElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<void()> &f = nullptr);
	void writeBase64Element(const NS &ns, const std::string &name, const std::vector<unsigned char> &data, const std::map<std::string, std::string> &attr = {});
	void writeTextElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::string &data);

private:
	struct Private;
	Private *d;
};

} // namespace libcdoc