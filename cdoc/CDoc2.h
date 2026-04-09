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

#ifndef __CDOC2_H__
#define __CDOC2_H__

#include "CDoc.h"

#include <string_view>

namespace libcdoc {
namespace CDoc2 {

static constexpr std::string_view LABEL = "CDOC\x02";
static constexpr std::string_view CEK = "CDOC20cek";
static constexpr std::string_view HMAC = "CDOC20hmac";
static constexpr std::string_view KEK = "CDOC20kek";
static constexpr std::string_view KEKPREMASTER = "CDOC20kekpremaster";
static constexpr std::string_view PAYLOAD = "CDOC20payload";
static constexpr std::string_view SALT = "CDOC20salt";

static constexpr int KEY_LEN = 32;
static constexpr int NONCE_LEN = 12;

static constexpr int KEYLABELVERSION = 1;

// Get salt bitstring for HKDF expand method
std::string getSaltForExpand(const std::string& label);

// Get salt bitstring for HKDF expand method
std::string getSaltForExpand(const std::vector<uint8_t>& key_material, const std::vector<uint8_t>& rcpt_key);

/**
 * @brief Prefix with what starts machine generated Lock's label.
 */
constexpr std::string_view LABELPREFIX{"data:"};

/**
 * @brief String after label prefix indicating, the rest of the label is Base64 encoded.
 */
constexpr std::string_view LABELBASE64IND{";base64,"};

/**
 * @brief EID type values for machine-readable label
 */
static constexpr std::string_view eid_strs[] = {
    CDoc2::Label::TYPE_UNKNOWN,
    CDoc2::Label::TYPE_ID_CARD,
    CDoc2::Label::TYPE_DIGI_ID,
    CDoc2::Label::TYPE_DIGI_ID_E_RESIDENT
};

} // namespace CDoc2
} // namespace libcdoc

#endif
