// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct _xmlTextReader;

namespace libcdoc {

struct DataSource;

class XMLReader
{
public:
    XMLReader(libcdoc::DataSource &src);
    virtual ~XMLReader() noexcept;

	std::string attribute(const char *attr) const;
	bool isElement(const char *element) const;
	bool isEndElement() const;
	bool read();
	std::vector<uint8_t> readBase64();
	std::string readText();
    bool hasError() const { return error; }

private:
    _xmlTextReader *d;
    bool error = false;
};

} // namespace libcdoc
