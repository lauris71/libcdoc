// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "CDocWriter.h"

#include <map>
#include <memory>

namespace libcdoc
{

struct TarConsumer;

class CDOC_EXPORT CDoc2Writer final: public libcdoc::CDocWriter {
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

    // Test-only access: WriterTestAccess drives addFileInternal() to build
    // containers with arbitrary (hostile) entry names for the reader
    // policy tests. Production code must use addFile(), which validates.
    friend struct WriterTestAccess;

    // Store one entry without the writer name policy (no validation, no
    // duplicate check). Used by addFile() after its checks and directly by
    // tests via WriterTestAccess.
    result_t addFileInternal(const std::string& name, size_t size);

    std::unique_ptr<TarConsumer> tar;
    std::vector<Recipient> recipients;
    bool finished = false;
    // Case-folded dedup keys of all filenames added so far; the CDoc2 spec
    // requires entry names to be unique.
    std::map<std::string, size_t> seen_names;
};

}
