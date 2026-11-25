// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "CDocWriter.h"

#include <memory>

class CDoc1Writer final: public libcdoc::CDocWriter
{
public:
    CDoc1Writer(libcdoc::DataConsumer *dst, bool take_ownership);
    ~CDoc1Writer() noexcept final;

    libcdoc::result_t beginEncryption() final;
    libcdoc::result_t addRecipient(const libcdoc::Recipient& rcpt) final;
    libcdoc::result_t addFile(const std::string& name, size_t size) final;
    libcdoc::result_t writeData(const uint8_t *src, size_t size) final;
    libcdoc::result_t finishEncryption() final;

    libcdoc::result_t encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys) final;

private:
    CDOC_DISABLE_COPY(CDoc1Writer)
    std::vector<libcdoc::Recipient> rcpts;
    struct Private;
    std::unique_ptr<Private> d;
};
