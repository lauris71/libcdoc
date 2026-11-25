// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "XmlWriter.h"

namespace libcdoc {
struct DataSource;

class DDOCWriter final: public XMLWriter
{
public:
    DDOCWriter(DataConsumer &dst);
    ~DDOCWriter() noexcept final;

    int64_t addFile(const std::string &name, const std::string &mime, size_t size, libcdoc::DataSource &src);
    int64_t addFile(const std::string &name, const std::string &mime, const std::vector<unsigned char> &data);

private:
    DDOCWriter(const DDOCWriter &) = delete;
    DDOCWriter &operator=(const DDOCWriter &) = delete;
    int64_t state;
    int fileCount = 0;
};

}
