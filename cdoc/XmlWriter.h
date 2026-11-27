// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace libcdoc {

struct DataConsumer;

class XMLWriter
{
public:
    struct NS { std::string_view prefix, ns; };

    virtual ~XMLWriter() noexcept = default;

protected:
    XMLWriter(DataConsumer &dst);

    int64_t writeStartElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr);
    int64_t writeEndElement(NS ns);
    int64_t writeElement(NS ns, std::string_view name, const std::function<int64_t()> &f = nullptr);
    int64_t writeElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr, const std::function<int64_t()> &f = nullptr);
    int64_t writeBase64Element(NS ns, std::string_view name, const std::function<int64_t(DataConsumer &)> &f, const std::map<std::string_view, std::string> &attr = {});
    int64_t writeBase64Element(NS ns, std::string_view name, const std::vector<unsigned char> &data, const std::map<std::string_view, std::string> &attr = {});
    int64_t writeTextElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr, std::string_view data);

private:
    int64_t write(std::string_view str) noexcept;
    int64_t writeBase64(const uint8_t *src, size_t len) noexcept;
    void escape(std::string_view in, bool attribute);

    DataConsumer &dst;
    bool isStarted = false;
    std::string buf;
    std::vector<std::string> stack;
    std::map<std::string_view, int> nsmap;
};

} // namespace libcdoc
