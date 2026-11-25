// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "CDocWriter.h"

#include <memory>

namespace libcdoc { struct WriterTestAccess; }

class CDOC_EXPORT CDoc1Writer final: public libcdoc::CDocWriter
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

    // Test-only access: WriterTestAccess drives addFileInternal() to build
    // containers with arbitrary (hostile) entry names for the reader
    // policy tests. Production code must use addFile(), which validates.
    friend struct libcdoc::WriterTestAccess;

    // Entry-name policy shared by the push (addFile) and pull (encrypt)
    // paths so both behave identically: clean, unique names only.
    libcdoc::result_t validateEntryName(const std::string& name);

    // Store one entry without the writer name policy (tests only, via
    // WriterTestAccess).
    libcdoc::result_t addFileInternal(const std::string& name, size_t size);

    std::vector<libcdoc::Recipient> rcpts;
    struct Private;
    std::unique_ptr<Private> d;
};
