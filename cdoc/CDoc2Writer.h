// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "CDocWriter.h"

#include <memory>

namespace libcdoc
{

struct TarConsumer;

class CDoc2Writer final: public libcdoc::CDocWriter {
public:
	explicit CDoc2Writer(libcdoc::DataConsumer *dst, bool take_ownership);
    CDOC_DISABLE_COPY(CDoc2Writer);
    ~CDoc2Writer() noexcept final;

    result_t beginEncryption() final;
    result_t addRecipient(const Recipient& rcpt) final;
    result_t addFile(const std::string& name, size_t size) final;
    result_t writeData(const uint8_t *src, size_t size) final;
    result_t finishEncryption() final;

    result_t encrypt(MultiDataSource& src, const std::vector<Recipient>& keys) final;
private:
    result_t writeHeader(const std::vector<Recipient> &recipients);
    result_t buildHeader(std::vector<uint8_t>& header, const std::vector<Recipient>& keys, const std::vector<uint8_t>& fmk);
    result_t fail(const std::string& message, result_t result);

    std::unique_ptr<TarConsumer> tar;
    std::vector<Recipient> recipients;
    bool finished = false;
};

}
