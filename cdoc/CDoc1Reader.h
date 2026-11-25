// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "CDocReader.h"

#include <functional>

class Token;

class CDoc1Reader final : public libcdoc::CDocReader
{
public:
    CDoc1Reader(libcdoc::DataSource *src, bool take_ownership = false);
    ~CDoc1Reader() noexcept final;

    const std::vector<libcdoc::Lock>& getLocks() final;
    libcdoc::result_t getLockForCert(const std::vector<uint8_t>& cert) final;
    libcdoc::result_t getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx) final;
    libcdoc::result_t decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *dst) final;

	// Pull interface
    libcdoc::result_t beginDecryption(const std::vector<uint8_t>& fmk) final;
    libcdoc::result_t nextFile(std::string& name, int64_t& size) final;
    libcdoc::result_t readData(uint8_t *dst, size_t size) final;
    libcdoc::result_t finishDecryption() final;

    static bool isCDoc1File(libcdoc::DataSource *src);
private:
    CDOC_DISABLE_MOVE_COPY(CDoc1Reader);
    libcdoc::result_t decryptData(const std::vector<uint8_t>& fmk,
        const std::function<libcdoc::result_t(libcdoc::DataSource &src, const std::string &mime)>& f);
    struct Private;
	Private *d;
};
