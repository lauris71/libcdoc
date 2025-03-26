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
#include "ILogger.h"
#include "Io.h"
#include "NetworkBackend.h"

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

int
libcdoc::CDocReader::getCDocFileVersion(DataSource *src)
{
    if (src->seek(0) != libcdoc::OK) return libcdoc::IO_ERROR;
    if (CDoc2Reader::isCDoc2File(src)) return 2;
    if (src->seek(0) != libcdoc::OK) return libcdoc::IO_ERROR;
    if (CDoc1Reader::isCDoc1File(src)) return 1;
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
    int version = getCDocFileVersion(src);
    LOG_DBG("CDocReader::createReader: version ", version);
    if (src->seek(0) != libcdoc::OK) return nullptr;
    CDocReader *reader;
	if (version == 1) {
        reader = new CDoc1Reader(src, take_ownership);
	} else if (version == 2) {
        reader = new CDoc2Reader(src, take_ownership);
	} else {
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
    int version = getCDocFileVersion(path);
    CDocReader *reader;
    if (version == 1) {
        reader = new CDoc1Reader(path);
    } else if (version == 2) {
        reader = new CDoc2Reader(path);
    } else {
        return nullptr;
    }
    reader->conf = conf;
    reader->crypto = crypto;
    reader->network = network;
    return reader;
}

libcdoc::CDocReader *
libcdoc::CDocReader::createReader(std::istream& ifs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
    libcdoc::IStreamSource *isrc = new libcdoc::IStreamSource(&ifs, false);
    int version = getCDocFileVersion(isrc);
    CDocReader *reader;
    if (version == 1) {
        reader = new CDoc1Reader(isrc, true);
    } else if (version == 2) {
        reader = new CDoc2Reader(isrc, true);
    } else {
        delete isrc;
        return nullptr;
    }
    reader->conf = conf;
    reader->crypto = crypto;
    reader->network = network;
    return reader;
}

#if LIBCDOC_TESTING
int64_t
libcdoc::CDocReader::testConfig(std::vector<uint8_t>& dst)
{
    LOG_TRACE("CDocReader::testConfig::Native superclass");
    if (conf) {
        LOG_DBG("CDocReader::testConfig this={} conf={}", reinterpret_cast<void*>(this), reinterpret_cast<void*>(conf));
    }
    LOG_ERROR("CDocReader::testConfig::conf is null");
    return WORKFLOW_ERROR;
}

int64_t
libcdoc::CDocReader::testNetwork(std::vector<std::vector<uint8_t>>& dst)
{
    LOG_TRACE("CDocReader::testNetwork::Native superclass");
    if (network) {
        LOG_DBG("CDocReader::testNetwork this={} network={}", reinterpret_cast<void*>(this), reinterpret_cast<void*>(network));
        return network->test(dst);
    }
    LOG_ERROR("CDocReader::testNetwork::network is null");
    return WORKFLOW_ERROR;
}
#endif

libcdoc::CDocWriter::CDocWriter(int _version, DataConsumer *_dst, bool take_ownership)
	: version(_version), dst(_dst), owned(take_ownership)
{
};

libcdoc::CDocWriter::~CDocWriter()
{
	if (owned) delete(dst);
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
	writer->crypto = crypto;
	writer->network = network;
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

