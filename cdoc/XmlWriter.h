// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "utils/memory.h"

#include <cstdint>
#include <functional>
#include <map>
#include <string>

struct _xmlTextWriter;

namespace libcdoc {

struct DataConsumer;

class XMLWriter
{
public:
    struct NS { const char *prefix, *ns; };

    XMLWriter(DataConsumer &dst);
    virtual ~XMLWriter() noexcept;

    int64_t writeStartElement(NS ns, const char *name, const std::map<const char *, std::string> &attr);
    int64_t writeEndElement(NS ns);
    int64_t writeElement(NS ns, const char *name, const std::function<int64_t()> &f = nullptr);
    int64_t writeElement(NS ns, const char *name, const std::map<const char *, std::string> &attr, const std::function<int64_t()> &f = nullptr);
    int64_t writeBase64Element(NS ns, const char *name, const std::function<int64_t(DataConsumer &)> &f, const std::map<const char *, std::string> &attr = {});
    int64_t writeBase64Element(NS ns, const char *name, const std::vector<unsigned char> &data, const std::map<const char *, std::string> &attr = {});
    int64_t writeTextElement(NS ns, const char *name, const std::map<const char *, std::string> &attr, const std::string &data);

private:
    unique_free_t<_xmlTextWriter> w;
    std::map<std::string_view, int> nsmap;
};

} // namespace libcdoc
