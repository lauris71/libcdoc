// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef __CDOC2_READER_H__
#define __CDOC2_READER_H__

#include "CDocReader.h"

#include <memory>

class CDoc2Reader final: public libcdoc::CDocReader {
public:
	~CDoc2Reader() final;

    const std::vector<libcdoc::Lock>& getLocks() final;
    libcdoc::result_t getLockForCert(const std::vector<uint8_t>& cert) final;
    libcdoc::result_t getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx) final;
    libcdoc::result_t decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *consumer) final;

	// Pull interface
    libcdoc::result_t beginDecryption(const std::vector<uint8_t>& fmk) final;
    libcdoc::result_t nextFile(std::string& name, int64_t& size) final;
    libcdoc::result_t readData(uint8_t *dst, size_t size) final;
    libcdoc::result_t finishDecryption() final;

	CDoc2Reader(libcdoc::DataSource *src, bool take_ownership = false);

    static bool isCDoc2File(libcdoc::DataSource *src);
private:
    CDOC_DISABLE_MOVE_COPY(CDoc2Reader);

	struct Private;
	std::unique_ptr<Private> priv;
};

#endif
