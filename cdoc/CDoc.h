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

#ifndef __CDOC_H__
#define __CDOC_H__
 
#include "Exports.h"

#include <cstdint>
#include <string>

namespace libcdoc {

/**
 * @brief A typedef that indicates that integer value may contain libcdoc result code
 */
using result_t = int64_t;


/**
 * @brief The public key type
 */
enum class PKType : uint8_t {
    /**
     * Elliptic curve
     */
    ECC,
    /**
     * RSA
     */
    RSA
};

enum {
    /**
     * @brief Operation completed successfully
     */
    OK = 0,
    /**
     * @brief No more input data
     *
     * A pseudo-error that indicates that there are no more streams in MultiDataSource
     */
    END_OF_STREAM = 1,
    /**
     * @brief A method is not implemented
     */
    NOT_IMPLEMENTED = -100,
    /**
     * @brief An operation is not supported
     */
    NOT_SUPPORTED = -101,
    /**
     * @brief Conflicting or invalid arguments for a method
     * 
     * This does not set CDocReader/CDocWriter into error state - so invoking subsequent methods
     * with correct arguments will succeed
     */
    WRONG_ARGUMENTS = -102,
    /**
     * @brief Components of multi-method workflow are called in wrong order
     * 
     * This does not set CDocReader/CDocWriter into error state - so invoking subsequent methods
     * in correct order will succeed
     */
    WORKFLOW_ERROR = -103,
    /**
     * @brief A generic input/output error
     */
    IO_ERROR = -104,
    /**
     * @brief A generic output error
     */
    OUTPUT_ERROR = -105,
    /**
     * @brief An error while writing output stream
     */
    OUTPUT_STREAM_ERROR = -106,
    /**
     * @brief A generic input error
     */
    INPUT_ERROR = -107,
    /**
     * @brief An error while reading input stream
     */
    INPUT_STREAM_ERROR = -108,
    /**
     * @brief The supplied decryption key is wrong
     * 
     * This does not set CDocReader/CDocWriter into error state - so invoking subsequent methods
     * with correct key will succeed
     */
    WRONG_KEY = -109,
    /**
     * @brief Data format of a file (or sub-object inside a file) is wrong
     */
    DATA_FORMAT_ERROR = -110,
    /**
     * @brief Generic error in cryptography subsystem
     */
    CRYPTO_ERROR = -111,
    /**
     * @brief Comppression/decompression error in zlib
     */
    ZLIB_ERROR = -112,
    /**
     * @brief Generic error in PKCS11 subsystem
     */
    PKCS11_ERROR = -113,
    /**
     * @brief The value of cryptographic hash is not correct
     */
    HASH_MISMATCH = -114,
    /**
     * @brief Generic error in configuration susbsytem
     */
    CONFIGURATION_ERROR = -115,
    /**
     * @brief Object not found
     */
    NOT_FOUND = -116,
    /**
     * @brief Unspecified error
     */
    UNSPECIFIED_ERROR = -199,
};

CDOC_EXPORT std::string getErrorStr(int64_t code);

CDOC_EXPORT std::string getVersion();

// Logging interface

/**
 * @brief Log-level enumeration to indicate severity of the log message.
 */
enum LogLevel : uint8_t
{
    /**
     * @brief Most critical level. Application is about to abort.
     */
    LEVEL_FATAL,

    /**
     * @brief Errors where functionality has failed or an exception have been caught.
     */
    LEVEL_ERROR,

    /**
     * @brief Warnings about validation issues or temporary failures that can be recovered.
     */
    LEVEL_WARNING,

    /**
     * @brief Information that highlights progress or application lifetime events.
     */
    LEVEL_INFO,

    /**
     * @brief Debugging the application behavior from internal events of interest.
     */
    LEVEL_DEBUG,

    /**
     * @brief Most verbose level. Used for development, NOP in production code.
     */
    LEVEL_TRACE
};

class Logger;

CDOC_EXPORT void setLogger(Logger *logger);
CDOC_EXPORT void setLogLevel(LogLevel level);
CDOC_EXPORT void log(LogLevel level, std::string_view file, int line, std::string_view msg);

/**
 * @brief A simple container of file name and size
 *
 * A container struct to store file name and size, needed for wrapper interfaces
 */
struct FileInfo {
    std::string name;
    int64_t size;
};

#ifdef VERSION
#undef VERSION
#endif

namespace CDoc2 {
namespace Label {
    /**
     * @brief Recipient types for machine-readable labels
     * 
     */
    static constexpr std::string_view TYPE_PASSWORD = "pw";
    static constexpr std::string_view TYPE_SYMMETRIC = "secret";
    static constexpr std::string_view TYPE_PUBLIC_KEY = "pub_key";
    static constexpr std::string_view TYPE_CERTIFICATE = "cert";
    static constexpr std::string_view TYPE_UNKNOWN = "Unknown";
    static constexpr std::string_view TYPE_ID_CARD = "ID-card";
    static constexpr std::string_view TYPE_DIGI_ID = "Digi-ID";
    static constexpr std::string_view TYPE_DIGI_ID_E_RESIDENT = "Digi-ID E-RESIDENT";

    /**
     * @brief Recipient data for machine-readable labels
     * 
     */
    static constexpr std::string_view VERSION = "v";
    static constexpr std::string_view TYPE = "type";
    static constexpr std::string_view FILE = "file";
    static constexpr std::string_view LABEL = "label";
    static constexpr std::string_view CN = "cn";
    static constexpr std::string_view SERIAL_NUMBER = "serial_number";
    static constexpr std::string_view LAST_NAME = "last_name";
    static constexpr std::string_view FIRST_NAME = "first_name";
    static constexpr std::string_view CERT_SHA1 = "cert_sha1";
    static constexpr const char* EXPIRY = "server_exp";
}
}

}; // namespace libcdoc

#endif // CDOC_H
