#pragma once

#include <string>
#include <vector>

#include "CDocReader.h"

class Token;

class CDoc1Reader : public libcdoc::CDocReader
{
public:
    CDoc1Reader(libcdoc::DataSource *src, bool take_ownership = false);
    CDoc1Reader(const std::string& path);
    ~CDoc1Reader();

	const std::vector<libcdoc::Lock> getLocks() override final;
    libcdoc::result_t getLockForCert(const std::vector<uint8_t>& cert) override final;
    libcdoc::result_t getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx) override final;
    libcdoc::result_t decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *dst) override final;

	// Pull interface
    libcdoc::result_t beginDecryption(const std::vector<uint8_t>& fmk) override final;
    libcdoc::result_t nextFile(std::string& name, int64_t& size) override final;
    libcdoc::result_t readData(uint8_t *dst, size_t size) override final;
    libcdoc::result_t finishDecryption() override final;

    static bool isCDoc1File(libcdoc::DataSource *src);
private:
	CDoc1Reader(const CDoc1Reader &) = delete;
	CDoc1Reader &operator=(const CDoc1Reader &) = delete;
	std::vector<unsigned char> decryptData(const std::vector<unsigned char> &key);
	class Private;
	Private *d;
};
