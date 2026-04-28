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

#include "CDoc1Writer.h"
#include "CDoc1Reader.h"
#include "CDoc2Writer.h"
#include "CDoc2Reader.h"
#include "Configuration.h"
#include "Io.h"
#include "NetworkBackend.h"
#include "Utils.h"
#include "Logger.h"

#include <iostream>
#include <filesystem>

namespace libcdoc {

struct Result {
    const int64_t code;
    const std::string_view message;
};

static constexpr Result results[] = {
    {OK, "OK"},
    {END_OF_STREAM, "End of stream"},
    {NOT_IMPLEMENTED, "Method not implemented"},
    {NOT_SUPPORTED, "Method not supported"},
    {WRONG_ARGUMENTS, "Wrong arguments to a method"},
    {WORKFLOW_ERROR, "Wrong workflow sequence"},
    {IO_ERROR, "Input/Output error"},
    {OUTPUT_ERROR, "Output error"},
    {OUTPUT_STREAM_ERROR, "Output stream error"},
    {INPUT_ERROR, "Input error"},
    {INPUT_STREAM_ERROR, "Input stream error"},
    {WRONG_KEY, "Wrong key"},
    {DATA_FORMAT_ERROR, "Invalid data format"},
    {CRYPTO_ERROR, "Cryptography error"},
    {ZLIB_ERROR, "ZLib error"},
    {PKCS11_ERROR, "PKCS11 error"},
    {HASH_MISMATCH, "Hash mismatch"},
    {CONFIGURATION_ERROR, "Configuration error"},
    {NOT_FOUND, "Object not found"},
    {UNSPECIFIED_ERROR, "Unspecified error"},
    };

static constexpr int n_results = sizeof(results) / sizeof(Result);

std::string
getErrorStr(int64_t code) {
    for (const auto& r : results) {
        if (r.code == code) return std::string(r.message);
    }
    return FORMAT("Unknown result code {}", code);
}

std::string
getVersion()
{
    return VERSION_STR;
}

/**
 * @brief Console logger
 *
 * An ILogger subclass that logs text to console.
 *
 * Info messages are logged to cout, all others to cerr.
 */

class ConsoleLogger : public Logger
{
public:
    void logMessage(LogLevel level, std::string_view file, int line, std::string_view message) override
    {
        // We ignore by default the file name and line number, and call LogMessage with the level and message.
        std::ostream& ofs = (level == LEVEL_INFO) ? std::cout : std::cerr;
        if (!file.empty()) {
            ofs << std::filesystem::path(encodeName(file)).filename().string() << ':' << line << " " << message << '\n';
        } else {
            ofs << message << '\n';
        }
    }
};

static Logger *
getDefaultLogger()
{
    static ConsoleLogger clogger;
    return &clogger;
}

static Logger *sys_logger = nullptr;

void
setLogger(Logger *logger)
{
    sys_logger = logger;
}

void
setLogLevel(LogLevel level)
{
    Logger *logger = (sys_logger) ? sys_logger : getDefaultLogger();
    logger->setMinLogLevel(level);
}

void
log(LogLevel level, std::string_view file, int line, std::string_view msg)
{
    Logger *logger = (sys_logger) ? sys_logger : getDefaultLogger();
    logger->log(level, file, line, msg);
}

int
libcdoc::CDocReader::getCDocFileVersion(DataSource *src)
{
    if (src->seek(0) != libcdoc::OK) {
        LOG_DBG("CDocReader::getCDocFileVersion (A): Source does not support seek");
        return libcdoc::IO_ERROR;
    }
    if (CDoc2Reader::isCDoc2File(src)) return 2;
    if (src->seek(0) != libcdoc::OK) {
        LOG_DBG("CDocReader::getCDocFileVersion (B): Source does not support seek");
        return libcdoc::IO_ERROR;
    }
    if (CDoc1Reader::isCDoc1File(src)) return 1;
    LOG_DBG("CDocReader::getCDocFileVersion: File not supported");
    return libcdoc::NOT_SUPPORTED;
}

int
libcdoc::CDocReader::getCDocFileVersion(const std::string& path)
{
    IStreamSource ifs(path);
    return getCDocFileVersion(&ifs);
}

libcdoc::CDocReader *
libcdoc::CDocReader::createReader(DataSource *src, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
    if(!src)
        return nullptr;
    int version = getCDocFileVersion(src);
    LOG_DBG("CDocReader::createReader: version {}", version);
    if (src->seek(0) != libcdoc::OK) return nullptr;
    CDocReader *reader = nullptr;
	if (version == 1) {
        reader = new CDoc1Reader(src, take_ownership);
	} else if (version == 2) {
        reader = new CDoc2Reader(src, take_ownership);
    } else {
        if(take_ownership)
            delete src;
        return nullptr;
    }
    if (!reader->getLastErrorStr().empty()) {
        delete reader;
        return nullptr;
    }
    reader->conf = conf;
    reader->crypto = crypto;
    reader->network = network;
    return reader;
}

libcdoc::CDocReader *
libcdoc::CDocReader::createReader(const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
    if(path.empty())
        return nullptr;
    auto isrc = make_unique<IStreamSource>(path);
    return createReader(isrc.release(), true, conf, crypto, network);
}

libcdoc::CDocReader *
libcdoc::CDocReader::createReader(std::istream& ifs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
    auto isrc = make_unique<IStreamSource>(&ifs, false);
    return createReader(isrc.release(), true, conf, crypto, network);
}

libcdoc::CDocWriter::CDocWriter(int _version, DataConsumer *_dst, bool take_ownership)
	: version(_version), dst(_dst), owned(take_ownership)
{
};

libcdoc::CDocWriter::~CDocWriter() noexcept
{
	if (owned) delete(dst);
}

static NetworkBackend *
getDefaultNetworkBackend()
{
    static NetworkBackend network;
    return &network;
}

static CryptoBackend *
getDefaultCryptoBackend()
{
    static CryptoBackend crypto;
    return &crypto;
}

libcdoc::CDocWriter *
libcdoc::CDocWriter::createWriter(int version, DataConsumer *dst, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{

	CDocWriter *writer;
	if (version == 1) {
		writer = new CDoc1Writer(dst, take_ownership);
	} else if (version == 2) {
		writer = new CDoc2Writer(dst, take_ownership);
	} else {
		return nullptr;
	}
    writer->conf = conf;
	writer->crypto = crypto ? crypto : getDefaultCryptoBackend();
	writer->network = network ? network : getDefaultNetworkBackend();
	return writer;
}

libcdoc::CDocWriter *
libcdoc::CDocWriter::createWriter(int version, std::ostream& ofs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
	libcdoc::DataConsumer *dst = new libcdoc::OStreamConsumer(&ofs, false);
	return createWriter(version, dst, true, conf, crypto, network);
}

libcdoc::CDocWriter *
libcdoc::CDocWriter::createWriter(int version, const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
	libcdoc::DataConsumer *dst = new libcdoc::OStreamConsumer(path);
	return createWriter(version, dst, true, conf, crypto, network);
}

}

