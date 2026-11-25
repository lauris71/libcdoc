// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef CDOCCIPHER_H
#define CDOCCIPHER_H

#include "CDocReader.h"
#include "CDocWriter.h"
#include "RcptInfo.h"
#include "ToolConf.h"
#include "Exports.h"

#include <memory>

namespace libcdoc
{


class CDOC_EXPORT CDocCipher
{
public:
    CDocCipher() = default;
    CDocCipher(const CDocCipher&) = delete;
    CDocCipher(CDocCipher&&) = delete;

    static int Encrypt(ToolConf& conf, std::vector<libcdoc::RcptInfo>& recipients);

    static int Decrypt(ToolConf& conf, RcptInfo& recipient);

    static int ReEncrypt(ToolConf& conf, RcptInfo& lock_info, std::vector<libcdoc::RcptInfo>& recipients);

    static void Locks(const char* file);

private:
    static int writer_push(CDocWriter& writer, const std::vector<libcdoc::Recipient>& keys, const std::vector<std::string>& files);
    static int Decrypt(const std::unique_ptr<CDocReader>& rdr, unsigned int lock_idx, const std::string& base_path);
};

}

#endif // CDOCCIPHER_H
