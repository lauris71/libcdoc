/*
 * libcdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

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
