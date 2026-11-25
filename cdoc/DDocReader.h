// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "XmlReader.h"

namespace libcdoc {

struct MultiDataConsumer;

struct DDOCReader: public XMLReader
{
    using XMLReader::XMLReader;
	struct File
	{
		std::string name, mime;
		std::vector<uint8_t> data;
	};
    int64_t parse(MultiDataConsumer *dst);

    int64_t files(std::vector<DDOCReader::File> &files);
};

} // namespace libcdoc
