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

#define BOOST_TEST_MODULE "C++ Unit Tests for libcdoc"

#include <boost/test/unit_test.hpp>
#include <filesystem>
#include <fstream>
#include <CDocCipher.h>
#include <CryptoBackend.h>
#include <Lock.h>
#include <Recipient.h>
#include <Tar.h>
#include <Utils.h>
#include <XmlReader.h>
#include <cdoc/Crypto.h>
#include <cdoc/Io.h>
#include <cdoc/KeyShares.h>
#include <cdoc/CDocWriter.h>
#include <cdoc/Configuration.h>
#include <cdoc/NetworkBackend.h>

#include <libxml/parser.h>

#include "pipe.h"

#ifndef DATA_DIR
#define DATA_DIR "data"
#endif

namespace btools = boost::test_tools;
namespace utf = boost::unit_test;
namespace fs = std::filesystem;

using namespace std;

/**
 * @brief Unencrypted file name.
 */
constexpr string_view SourceFile("test_data.txt");
constexpr string_view SourceFile2("test_data2.txt");
constexpr string_view SourceFile3("test_data3.txt");

/**
 * @brief Encrypted file name.
 */
constexpr string_view TargetFile("test_data.txt.cdoc");
constexpr string_view EC384PrivKeyFile("ec-secp384r1-priv.der");
constexpr string_view EC384PubKeyFile("ec-secp384r1-pub.der");
constexpr string_view EC384CertFile("ec-secp384r1-cert.der");
constexpr string_view EC256PrivKeyFile("ec-secp256r1-priv.der");
constexpr string_view EC256PubKeyFile("ec-secp256r1-pub.der");
constexpr string_view EC256CertFile("ec-secp256r1-cert.der");
constexpr string_view EC521PrivKeyFile("ec-secp521r1-priv.der");
constexpr string_view EC521PubKeyFile("ec-secp521r1-pub.der");
constexpr string_view EC521CertFile("ec-secp521r1-cert.der");
constexpr string_view RSAPrivKeyFile("rsa_2048_priv.der");
constexpr string_view RSAPubKeyFile("rsa_2048_pub.der");
constexpr string_view RSACertFile("rsa_2048_cert.der");

const string Label("Proov");

const std::vector<uint8_t> Password = {'P', 'r', 'o', 'o', 'v', '1', '2', '3'};

constexpr string_view AESKey = "E165475C6D8B9DD0B696EE2A37D7176DFDF4D7B510406648E70BAE8E80493E5E"sv;

constexpr string_view CDOC2HEADER = "CDOC\x02"sv;

struct XMLSource {
    explicit XMLSource(std::string_view xml)
        : data(xml.cbegin(), xml.cend())
        , source(data)
    {}

    std::vector<uint8_t> data;
    libcdoc::VectorSource source;
};

const map<string, string> ExpectedParsedLabel {
    {"v", "1"},
    {"type", "ID-card"},
    {"serial_number", "PNOEE-38001085718"},
    {"cn", "JÕEORG,JAAK-KRISTJAN,38001085718"}
};

/**
 * @brief The base class for Test Fixtures.
 */
class FixtureBase
{
public:
    FixtureBase()
    {
        int argc = utf::framework::master_test_suite().argc;
        for (int i = 0; i < argc; i++) {
            std::string_view arg = utf::framework::master_test_suite().argv[i];
            if (arg == "--data-path") {
                if (i >= argc) {
                    std::cerr << "Missing data path value" << std::endl;
                    ::exit(1);
                }
                i += 1;
                testDataPath = utf::framework::master_test_suite().argv[i];
            } else if (arg == "--max-filesize") {
                if (i >= argc) {
                    std::cerr << "Missing max filesize value" << std::endl;
                    ::exit(1);
                }
                i += 1;
                max_filesize = std::stoull(utf::framework::master_test_suite().argv[i]);
            }
        }
        if (!fs::exists(testDataPath)) {
            std::cerr << "Path " << testDataPath << " does not exist!" << std::endl;
            ::exit(1);
        }
        tmpDataPath = fs::path(DATA_DIR) / "tmp";
        if (!fs::exists(tmpDataPath)) {
            fs::create_directories(tmpDataPath);
        }
    }

    /**
     * @brief Concatenates test-data path with given file name and assigns it to given target.
     * @param fileName File's name to be appended to test data path.
     * @param target Target where the result is assigned.
     */
    void FormFilePath(string_view fileName, fs::path& target) const
    {
        target = testDataPath;
        target /= fileName;
    }

    std::string formTargetFile(const std::string_view name) const
    {
        fs::path path(fs::path(tmpDataPath) / name);
        if (fs::exists(path)) {
            error_code e;
            fs::remove(path, e);
            if(e) BOOST_TEST_MESSAGE("Failed to remove file");
        }
        return path.string();
    }

    std::string checkDataFile(const std::string_view name) const
    {
        fs::path path(fs::path(testDataPath) / name);
        BOOST_TEST_REQUIRE(fs::exists(path), "file " << name << " does not exist");
        return path.string();
    }

    std::string checkTargetFile(const std::string_view name) const
    {
        fs::path path(fs::path(tmpDataPath) / name);
        BOOST_TEST_REQUIRE(fs::exists(path), "file " << name << " does not exist");
        return path.string();
    }

    std::vector<uint8_t> fetchDataFile(const std::string_view name) const
    {
        fs::path path(fs::path(testDataPath) / name);
        BOOST_TEST_REQUIRE(fs::exists(path), "file " << name << " does not exist");
        return libcdoc::readAllBytes(path.string());
    }

    fs::path testDataPath = DATA_DIR;
    fs::path tmpDataPath;
    fs::path sourceFilePath;
    fs::path sourceFilePath2;
    fs::path sourceFilePath3;

    std::vector<std::string> sources = {"test_data.txt", "test_data2.txt", "test_data3.txt"};

    size_t max_filesize = 100000000;
};

/**
 * @brief The Test Fixture class for encrypt operations.
 */
class EncryptFixture : public FixtureBase
{
public:
    EncryptFixture()
    {
        BOOST_TEST_MESSAGE("Encrypt fixture setup");

        // Setup source, unencrypted file path
        FormFilePath(SourceFile, sourceFilePath);
        FormFilePath(SourceFile2, sourceFilePath2);
        FormFilePath(SourceFile3, sourceFilePath3);
    }

    ~EncryptFixture() { BOOST_TEST_MESSAGE("Encrypt fixture deardown"); }

    /**
     * @brief ValidateEncryptedFile Validates encrypted file.
     * @param encryptedFilePath Path to the file to be validated.
     * @return predicate_result object with the validation result.
     */
    btools::predicate_result ValidateEncryptedFile(const fs::path& encryptedFilePath)
    {
        // Check if the encrypted file exists
        btools::predicate_result resTargetFileExists(fs::exists(encryptedFilePath));
        if (!resTargetFileExists)
        {
            resTargetFileExists.message() << "File " << encryptedFilePath << " does not exist";
            return resTargetFileExists;
        }

        // Check if the file size is greater than 0.
        btools::predicate_result resGtZero(fs::file_size(encryptedFilePath) > 0);
        if (!resGtZero)
        {
            resGtZero.message() << "Encrypted file size is 0";
            return resGtZero;
        }

        // Check if the encrypted file starts with "CDOC"
        ifstream encryptedFile(encryptedFilePath, ios_base::binary);
        vector<char> header(CDOC2HEADER.size() + 1);
        encryptedFile.read(header.data(), CDOC2HEADER.size());
        btools::predicate_result resCdocHeaderOk(string_view(header.data()) == CDOC2HEADER);
        if (!resCdocHeaderOk)
        {
            resCdocHeaderOk.message() << "Encrypted file has no CDOC header";
        }

        return resCdocHeaderOk;
    }
};

/**
 * @brief The Test Fixture class for decrypt operations.
 */
class DecryptFixture : public FixtureBase
{
public:
    DecryptFixture()
    {
        BOOST_TEST_MESSAGE("Decrypt fixture setup");

        // Setup source, encrypted file path
        FormFilePath(TargetFile, sourceFilePath);
    }

    ~DecryptFixture()
    {
        BOOST_TEST_MESSAGE("Decrypt fixture deardown");
    }
};

static void
encrypt(unsigned int version, const std::vector<std::string>& files, const std::string& container, std::vector<libcdoc::RcptInfo>& rcpts) {
    libcdoc::ToolConf conf;
    for (auto file : files) {
        conf.input_files.push_back(file);
    }
    conf.out = container;
    conf.cdocVersion = version;

    libcdoc::CDocCipher cipher;
    BOOST_CHECK_EQUAL(cipher.Encrypt(conf, rcpts), 0);

    BOOST_TEST(fs::exists(fs::path(container)), "File " << container << " does not exist");
}

static void
encryptV1(const std::vector<std::string>& files, const std::string& container, const std::vector<uint8_t>& cert) {
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::CERT, {}, cert}
    };
    encrypt(1, files, container, rcpts);
}

static void
encryptV2(const std::vector<std::string>& files, const std::string& container, const std::vector<uint8_t>& cert) {
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::CERT, {}, cert}
    };
    encrypt(2, files, container, rcpts);
}

static void
decrypt(const std::vector<std::string>& files, const std::string& container, const std::string& dir, libcdoc::RcptInfo& rcpt, bool remove = true)
{
    libcdoc::ToolConf conf;
    conf.input_files.push_back(container);
    conf.out = dir;

    libcdoc::CDocCipher cipher;
    BOOST_CHECK_EQUAL(cipher.Decrypt(conf, rcpt), 0);

    fs::path path(dir);
    for (auto file : files) {
        BOOST_TEST(fs::exists(path / fs::path(file).filename()), "File " << file << " does not exist");
    }

    path = fs::path(container);
    if (remove && fs::exists(path)) {
        error_code e;
        fs::remove(path, e);
        if(e)
            BOOST_TEST_MESSAGE("Failed to remove file");
    }
}

static void
decrypt(const std::vector<std::string>& files, const std::string& container, const std::string& dir, const std::vector<uint8_t>& key, int idx = 0, bool remove = true)
{
    libcdoc::RcptInfo rcpt {.type=libcdoc::RcptInfo::LOCK, .secret=key, .lock_idx=idx};
    decrypt(files, container, dir, rcpt, remove);
}

static int
unicode_to_utf8 (unsigned int uval, uint8_t *d, uint64_t size)
{
	if ((uval < 0x80) && (size >= 1)) {
		d[0] = (uint8_t) uval;
		return 1;
	} else if ((uval < 0x800) && (size >= 2)) {
		d[0] = 0xc0 | (uval >> 6);
		d[1] = 0x80 | (uval & 0x3f);
		return 2;
	} else if ((uval < 0x10000) && (size >= 3)) {
		d[0] = 0xe0 | (uval >> 12);
		d[1] = 0x80 | ((uval >> 6) & 0x3f);
		d[2] = 0x80 | (uval & 0x3f);
		return 3;
	} else if ((uval < 0x110000) && (size >= 4)) {
		d[0] = 0xf0 | (uval >> 18);
		d[1] = 0x80 | ((uval >> 12) & 0x3f);
		d[2] = 0x80 | ((uval >> 6) & 0x3f);
		d[3] = 0x80 | (uval & 0x3f);
		return 4;
	}
	return 0;
}

static std::string
utf16_to_utf8(const std::u16string& utf16)
{
    std::string utf8;
    for (char16_t c16 : utf16) {
        char c[4];
        utf8.append(c, unicode_to_utf8(c16, (uint8_t *) c, 4));
    }
    return utf8;
}

static std::string
gen_random_filename()
{
    size_t len = std::rand() % 1000 + 1;
    std::u16string u16(len, ' ');
    for (int i = 0; i < len; i++) u16[i] = std::rand() % 10000 + 32;
    return utf16_to_utf8(u16);
}

// CDoc2 password and label

struct TestCrypto : public libcdoc::CryptoBackend {
    std::string_view password;

    libcdoc::result_t getSecret(std::vector<uint8_t>& dst, unsigned int idx) override final {
        // Mark empty password with bogus error to detect it
        if(password.empty()) return libcdoc::WRONG_ARGUMENTS;
        dst.assign(password.cbegin(), password.cend());
        return libcdoc::OK;
    };
};

BOOST_AUTO_TEST_SUITE(CDoc2Errors)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(CDoc2EncryptErrors, EncryptFixture,
        * utf::description("Cause various encryption errors"))
{
    std::string container = formTargetFile("CDoc2Errors.cdoc");
    uint8_t test_data[256];

    libcdoc::ToolConf conf;
    TestCrypto crypto;

    srand(0);
    // Create writer
    libcdoc::CDocWriter *wrt = libcdoc::CDocWriter::createWriter(2, container, &conf, &crypto, nullptr);
    BOOST_TEST(wrt != nullptr, "Cannot create writer");
    // Nothing can be done until at least one recipient is added
    BOOST_TEST(wrt->beginEncryption() == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->addFile("testfile", 1024) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->writeData(test_data, 256) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->finishEncryption() == libcdoc::WORKFLOW_ERROR);

    // Add recipient
    libcdoc::Recipient rcpt = libcdoc::Recipient::makeSymmetric("test-recipient", 600000);
    BOOST_TEST(wrt->addRecipient(rcpt) == libcdoc::OK);
    // Encryption cannot proceed before beginEncryption is called
    BOOST_TEST(wrt->addFile("testfile", 1024) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->writeData(test_data, 256) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->finishEncryption() == libcdoc::WORKFLOW_ERROR);

    // Begin encryption
    BOOST_TEST(wrt->beginEncryption() == libcdoc::WRONG_ARGUMENTS);
    crypto.password = "test-password";
    BOOST_TEST(wrt->beginEncryption() == libcdoc::OK);
    // Cannot do anything else than add files
    BOOST_TEST(wrt->addRecipient(rcpt) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->beginEncryption() == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->writeData(test_data, 256) == libcdoc::WORKFLOW_ERROR);
    // Finish encryption will succeed with empty tar

    // Add file
    BOOST_TEST(wrt->addFile("testfile", 1024) == libcdoc::OK);
    // Errors
    BOOST_TEST(wrt->addRecipient(rcpt) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->beginEncryption() == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->addFile("testfile", 1024) == libcdoc::WORKFLOW_ERROR);

    // Write data
    for (int i = 0; i < 256; i++) test_data[i] = uint8_t(rand() & 0xff);
    BOOST_TEST(wrt->writeData(test_data, 256) == libcdoc::OK);
    BOOST_TEST(wrt->addRecipient(rcpt) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->beginEncryption() == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->addFile("testfile", 1024) == libcdoc::WORKFLOW_ERROR);
    for (int i = 0; i < 256; i++) test_data[i] = uint8_t(rand() & 0xff);
    BOOST_TEST(wrt->writeData(test_data, 256) == libcdoc::OK);
    for (int i = 0; i < 256; i++) test_data[i] = uint8_t(rand() & 0xff);
    BOOST_TEST(wrt->writeData(test_data, 256) == libcdoc::OK);
    for (int i = 0; i < 256; i++) test_data[i] = uint8_t(rand() & 0xff);
    BOOST_TEST(wrt->writeData(test_data, 256) == libcdoc::OK);
    BOOST_TEST(wrt->writeData(test_data, 256) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->addRecipient(rcpt) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->beginEncryption() == libcdoc::WORKFLOW_ERROR);
    // Add file with unknown size
    BOOST_TEST(wrt->addFile("testfile2", 10000000000ULL) == libcdoc::WRONG_ARGUMENTS);
    BOOST_TEST(wrt->addFile("testfile2", 255) == libcdoc::OK);
    for (int i = 0; i < 256; i++) test_data[i] = uint8_t(rand() & 0xff);
    BOOST_TEST(wrt->writeData(test_data, 255) == libcdoc::OK);
    BOOST_TEST(wrt->addRecipient(rcpt) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->beginEncryption() == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->finishEncryption() == libcdoc::OK);

    BOOST_TEST(wrt->addRecipient(rcpt) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->beginEncryption() == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->addFile("testfile", 1024) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->writeData(test_data, 256) == libcdoc::WORKFLOW_ERROR);
    BOOST_TEST(wrt->finishEncryption() == libcdoc::WORKFLOW_ERROR);

    delete wrt;
}

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(CDoc2DecryptErrors, DecryptFixture,
        * utf::depends_on("CDoc2Errors/CDoc2EncryptErrors")
        * utf::description("Cause various decryption errors"))
{
    std::string container = checkTargetFile("CDoc2Errors.cdoc");
    libcdoc::ToolConf conf;
    TestCrypto crypto;
    uint8_t buf[1024];

    libcdoc::CDocReader *rdr = libcdoc::CDocReader::createReader(container, &conf, &crypto, nullptr);
    BOOST_TEST(rdr != nullptr, "Cannot create reader");
    std::vector<uint8_t> fmk(32);
    BOOST_TEST(rdr->getFMK(fmk, 10) == libcdoc::WRONG_ARGUMENTS);
    // Decryption should start with random key
    BOOST_TEST(rdr->beginDecryption(fmk) == libcdoc::OK);
    libcdoc::FileInfo fi;
    // But the first file should file
    BOOST_TEST(rdr->nextFile(fi) != libcdoc::OK);
    delete rdr;

    rdr = libcdoc::CDocReader::createReader(container, &conf, &crypto, nullptr);
    BOOST_TEST(rdr != nullptr, "Cannot create reader");
    BOOST_TEST(rdr->getFMK(fmk, 0) == libcdoc::WRONG_ARGUMENTS);
    crypto.password = "wrong-password";
    BOOST_TEST(rdr->getFMK(fmk, 0) == libcdoc::WRONG_KEY);
    crypto.password = "test-password";
    BOOST_TEST(rdr->getFMK(fmk, 0) == libcdoc::OK);
    BOOST_TEST(rdr->beginDecryption(fmk) == libcdoc::OK);
    BOOST_TEST(rdr->nextFile(fi) == libcdoc::OK);
    BOOST_TEST(fi.size == 1024);
    BOOST_TEST(rdr->readData(buf, 256) == 256);
    BOOST_TEST(rdr->readData(buf, 256) == 256);
    BOOST_TEST(rdr->readData(buf, 256) == 256);
    BOOST_TEST(rdr->readData(buf, 1024) == 256);
    BOOST_TEST(rdr->nextFile(fi) == libcdoc::OK);
    BOOST_TEST(fi.size == 255);
    BOOST_TEST(rdr->readData(buf, 1024) == 255);
    BOOST_TEST(rdr->finishDecryption() == libcdoc::OK);
    delete rdr;

    // Write over the end of file
    size_t fsize = std::filesystem::file_size(container);
    std::fstream file(container, std::ios::out | std::ios::in);
    BOOST_TEST(!file.bad());
    file.seekp(fsize - 16, std::ios::beg);
    file.write((char *) buf, 16);
    file.close();

    rdr = libcdoc::CDocReader::createReader(container, &conf, &crypto, nullptr);
    BOOST_TEST(rdr != nullptr, "Cannot create reader");
    BOOST_TEST(rdr->getFMK(fmk, 0) == libcdoc::OK);
    BOOST_TEST(rdr->beginDecryption(fmk) == libcdoc::OK);
    BOOST_TEST(rdr->nextFile(fi) == libcdoc::OK);
    BOOST_TEST(rdr->nextFile(fi) == libcdoc::OK);
    BOOST_TEST(rdr->finishDecryption() == libcdoc::HASH_MISMATCH);
    delete rdr;

    // Truncate file, should result zlib error
    std::filesystem::resize_file(container, fsize - 32);
    rdr = libcdoc::CDocReader::createReader(container, &conf, &crypto, nullptr);
    BOOST_TEST(rdr != nullptr, "Cannot create reader");
    BOOST_TEST(rdr->getFMK(fmk, 0) == libcdoc::OK);
    BOOST_TEST(rdr->beginDecryption(fmk) == libcdoc::OK);
    libcdoc::result_t rv = rdr->nextFile(fi);
    BOOST_TEST(((rv == libcdoc::OK) || (rv == libcdoc::HASH_MISMATCH)));
    for (int i = 0; i < 4; i++) {
        rv = rdr->readData(buf, 256);
        BOOST_TEST(((rv == 256) || (rv == libcdoc::HASH_MISMATCH)));
    }
    rv = rdr->nextFile(fi);
    BOOST_TEST(((rv == libcdoc::OK) || (rv == libcdoc::HASH_MISMATCH)));
    rv = rdr->readData(buf, 256);
    BOOST_TEST(((rv == 255) || (rv == libcdoc::HASH_MISMATCH)));
    BOOST_TEST(rdr->finishDecryption() == libcdoc::WORKFLOW_ERROR);
    delete rdr;
}
BOOST_AUTO_TEST_SUITE_END()

// CDoc2 password and label

BOOST_AUTO_TEST_SUITE(PasswordUsageWithLabel)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithPasswordAndLabel, EncryptFixture,
        * utf::description("Encrypting a file with password and given label"))
{
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::PASSWORD, Label, {}, Password}
    };
    encrypt(2, {checkDataFile(sources[0])}, formTargetFile("PasswordUsageWithoutLabel.cdoc"), rcpts);
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithPasswordAndLabel, DecryptFixture,
        * utf::depends_on("PasswordUsageWithLabel/EncryptWithPasswordAndLabel")
        * utf::description("Decrypting a file with password and given label"))
{
    libcdoc::RcptInfo rcpt {.type=libcdoc::RcptInfo::LOCK, .label=Label, .secret=Password};
    decrypt({checkDataFile(sources[0])}, checkTargetFile("PasswordUsageWithoutLabel.cdoc"), libcdoc::decodeName(tmpDataPath), rcpt);
}
BOOST_AUTO_TEST_SUITE_END()

// CDoc2 password and label

BOOST_AUTO_TEST_SUITE(PasswordUsageWithoutLabel)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithPasswordWithoutLabel, EncryptFixture,
        * utf::description("Encrypting a file with password and without label"))
{
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::PASSWORD, "auto", {}, Password}
    };
    encrypt(2, {checkDataFile(sources[0])}, formTargetFile("PasswordUsageWithoutLabel.cdoc"), rcpts);
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithPasswordLabelIndex, DecryptFixture,
                                   * utf::depends_on("PasswordUsageWithoutLabel/EncryptWithPasswordWithoutLabel")
                                   * utf::description("Decrypting a file with password and label index"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile("PasswordUsageWithoutLabel.cdoc"), tmpDataPath.string(), Password);
}
BOOST_AUTO_TEST_SUITE_END()

// CDoc2 public/private/symmetric key

BOOST_AUTO_TEST_SUITE(CDoc2KeyUsage)
static constexpr string_view CONTAINER("CDoc2KeyUsage.cdoc");
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithCDoc2Key, EncryptFixture,
        * utf::description("Encrypting a CDoc2 file with a key"))
{
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::PKEY, {}, {}, fetchDataFile(EC384PubKeyFile)},
        {libcdoc::RcptInfo::CERT, {}, fetchDataFile(EC384CertFile)},
        {libcdoc::RcptInfo::PKEY, {}, {}, fetchDataFile(EC256PubKeyFile)},
        {libcdoc::RcptInfo::CERT, {}, fetchDataFile(EC256CertFile)},
        {libcdoc::RcptInfo::PKEY, {}, {}, fetchDataFile(EC521PubKeyFile)},
        {libcdoc::RcptInfo::CERT, {}, fetchDataFile(EC521CertFile)},
        {libcdoc::RcptInfo::PKEY, {}, {}, fetchDataFile(RSAPubKeyFile)},
        {libcdoc::RcptInfo::SKEY, "AES", {}, libcdoc::fromHex(AESKey)}
    };
    encrypt(2, {checkDataFile(sources[0])}, formTargetFile(CONTAINER), rcpts);
}

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithCDoc2Key, DecryptFixture,
                     * utf::depends_on("CDoc2KeyUsage/EncryptWithCDoc2Key")
                     * utf::description("Decrypting a CDoc2 file with a key"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile(CONTAINER), tmpDataPath.string(), fetchDataFile(EC384PrivKeyFile), 0, false);
    decrypt({checkDataFile(sources[0])}, checkTargetFile(CONTAINER), tmpDataPath.string(), fetchDataFile(EC384PrivKeyFile), 1, false);
    decrypt({checkDataFile(sources[0])}, checkTargetFile(CONTAINER), tmpDataPath.string(), fetchDataFile(EC256PrivKeyFile), 2, false);
    decrypt({checkDataFile(sources[0])}, checkTargetFile(CONTAINER), tmpDataPath.string(), fetchDataFile(EC256PrivKeyFile), 3, false);
    decrypt({checkDataFile(sources[0])}, checkTargetFile(CONTAINER), tmpDataPath.string(), fetchDataFile(EC521PrivKeyFile), 4, false);
    decrypt({checkDataFile(sources[0])}, checkTargetFile(CONTAINER), tmpDataPath.string(), fetchDataFile(EC521PrivKeyFile), 5, false);
    decrypt({checkDataFile(sources[0])}, checkTargetFile(CONTAINER), tmpDataPath.string(), fetchDataFile(RSAPrivKeyFile), 6, false);
    decrypt({checkDataFile(sources[0])}, checkTargetFile(CONTAINER), tmpDataPath.string(), libcdoc::fromHex(AESKey), 7, true);
}
BOOST_AUTO_TEST_SUITE_END()

// CDoc1 tests

BOOST_AUTO_TEST_SUITE(CDoc1ECKeySingle)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithECKeyV1, EncryptFixture,
        * utf::description("Encrypting a file with EC key in CDoc1 format"))
{
    encryptV1({checkDataFile(sources[0])}, formTargetFile("ECKeyUsageV1.cdoc"), fetchDataFile(EC384CertFile));
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithECKeyV1, DecryptFixture,
                     * utf::depends_on("CDoc1ECKeySingle/EncryptWithECKeyV1")
                     * utf::description("Decrypting a file in CDoc1 format with with EC private key"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile("ECKeyUsageV1.cdoc"), tmpDataPath.string(), fetchDataFile(EC384PrivKeyFile));
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(CDoc1ECKeyMulti)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithECKeyV1Multi, EncryptFixture,
        * utf::description("Encrypting multiple files with EC key in CDoc1 format"))
{
    encryptV1({checkDataFile(sources[0]), checkDataFile(sources[1]), checkDataFile(sources[2])}, formTargetFile("ECKeyUsageV1Multi.cdoc"), fetchDataFile(EC384CertFile));
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithECKeyV1Multi, DecryptFixture,
                     * utf::depends_on("CDoc1ECKeyMulti/EncryptWithECKeyV1Multi")
                     * utf::description("Decrypting multiple files in CDoc1 format with with EC private key"))
{
    decrypt({checkDataFile(sources[0]), checkDataFile(sources[1]), checkDataFile(sources[2])}, checkTargetFile("ECKeyUsageV1Multi.cdoc"), tmpDataPath.string(), fetchDataFile(EC384PrivKeyFile));
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(CDoc1RSAKeySingle)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithRSAKeyV1, EncryptFixture, * utf::description("Encrypting a file with RSA key in CDoc1 format"))
{
    encryptV1({checkDataFile(sources[0])}, formTargetFile("RSAKeyUsageV1.cdoc"), fetchDataFile(RSACertFile));
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithRSAKeyV1, DecryptFixture,
                     * utf::depends_on("CDoc1RSAKeySingle/EncryptWithRSAKeyV1")
                     * utf::description("Decrypting a file in CDoc1 format with with RSA private key"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile("RSAKeyUsageV1.cdoc"), tmpDataPath.string(), fetchDataFile(RSAPrivKeyFile));
}
BOOST_AUTO_TEST_SUITE_END()

// Stream encryption/decryption of large files

BOOST_AUTO_TEST_SUITE(LargeFiles)

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithPasswordAndLabel, FixtureBase, * utf::description("Testing weird and large files"))
{
    std::srand(1);

    std::vector<uint8_t> data;
    bool eof = false;
    PipeConsumer pipec(data, eof);
    PipeSource pipes(data, eof);
    PipeCrypto pcrypto("password");

    // Create writer
    libcdoc::CDocWriter *writer = libcdoc::CDocWriter::createWriter(2, &pipec, false, nullptr, &pcrypto, nullptr);
    BOOST_TEST(writer != nullptr);
    libcdoc::Recipient rcpt = libcdoc::Recipient::makeSymmetric("test", 600000);
    BOOST_TEST(writer->addRecipient(rcpt) == libcdoc::OK);
    BOOST_TEST(writer->beginEncryption() == libcdoc::OK);

    // List of files: 0, 0, max_size...0
    std::vector<libcdoc::FileInfo> files;
    files.emplace_back(gen_random_filename(), 0);
    files.emplace_back(gen_random_filename(), 0);
    for (size_t size = max_filesize; size != 0; size = size / 100) {
        files.emplace_back(gen_random_filename(), size);
    }
    files.emplace_back(gen_random_filename(), 0);

    PipeWriter wrt(writer, files);

    // Create reader
    libcdoc::CDocReader *reader = libcdoc::CDocReader::createReader(&pipes, false, nullptr, &pcrypto, nullptr);
    BOOST_TEST(reader != nullptr);

    // Fill buffer
    while((data.size() < 2 * wrt.BUFSIZE) && !wrt.isEof()) {
        BOOST_TEST(wrt.writeMore() == libcdoc::OK);
    }
    std::vector<uint8_t> fmk;
    BOOST_TEST(reader->getFMK(fmk, 0) == libcdoc::OK);
    BOOST_TEST(reader->beginDecryption(fmk) == libcdoc::OK);
    libcdoc::FileInfo fi;
    for (int cfile = 0; cfile < files.size(); cfile++) {
        // Fill buffer
        while((data.size() < 2 * wrt.BUFSIZE) && !wrt.isEof()) {
            BOOST_TEST(wrt.writeMore() == libcdoc::OK);
        }
        // Get file
        BOOST_TEST(reader->nextFile(fi) == libcdoc::OK);
        BOOST_TEST(fi.name == files[cfile].name);
        BOOST_TEST(fi.size == files[cfile].size);
        for (size_t pos = 0; pos < files[cfile].size; pos += wrt.BUFSIZE) {
            // Fill buffer
            while((data.size() < 2 * wrt.BUFSIZE) && !wrt.isEof()) {
                BOOST_TEST(wrt.writeMore() == libcdoc::OK);
            }
            size_t toread = files[cfile].size - pos;
            if (toread > wrt.BUFSIZE) toread = wrt.BUFSIZE;
            uint8_t buf[wrt.BUFSIZE], cbuf[wrt.BUFSIZE];
            BOOST_TEST(reader->readData(buf, toread) == toread);
            for (size_t i = 0; i < toread; i++) cbuf[i] = wrt.getChar(cfile, pos + i);
            BOOST_TEST(std::memcmp(buf, cbuf, toread) == 0);
        }
    }
    BOOST_TEST(reader->nextFile(fi) == libcdoc::END_OF_STREAM);
    BOOST_TEST(reader->finishDecryption() == libcdoc::OK);

    delete writer;
    delete reader;
}

BOOST_AUTO_TEST_SUITE_END()

// Label parsing

BOOST_AUTO_TEST_SUITE(MachineLabelParsing)
BOOST_AUTO_TEST_CASE(PlainLabelParsing)
{
    const string label("data:v=1&type=ID-card&serial_number=PNOEE-38001085718&cn=J%C3%95EORG%2CJAAK-KRISTJAN%2C38001085718");

    auto result = libcdoc::Lock::parseLabel(label);
    for (const auto& [key, value] : ExpectedParsedLabel)
    {
        auto result_pair = result.find(key);
        BOOST_TEST((result_pair != result.cend()), "Field " << key << " presented");
        if (result_pair != result.end())
        {
            BOOST_CHECK_EQUAL(result_pair->second, value);
        }
    }
}

BOOST_AUTO_TEST_CASE(PlainLabelParsingUpper)
{
    const string label("data:,TYPE=ID-card&serial_number=PNOEE-38001085718&CN=J%C3%95EORG%2CJAAK-KRISTJAN%2C38001085718&V=1");

    auto result = libcdoc::Lock::parseLabel(label);
    for (const auto& [key, value] : ExpectedParsedLabel)
    {
        auto result_pair = result.find(key);
        BOOST_TEST((result_pair != result.cend()), "Field " << key << " presented");
        if (result_pair != result.end())
        {
            BOOST_CHECK_EQUAL(result_pair->second, value);
        }
    }
}

BOOST_AUTO_TEST_CASE(Base64LabelParsing)
{
    const string label("data:;base64,dj0xJnR5cGU9SUQtY2FyZCZzZXJpYWxfbnVtYmVyPVBOT0VFLTM4MDAxMDg1NzE4JmNuPUolQzMlOTVFT1JHJTJDSkFBSy1LUklTVEpBTiUyQzM4MDAxMDg1NzE4");

    auto result = libcdoc::Lock::parseLabel(label);
    for (const auto& [key, value] : ExpectedParsedLabel)
    {
        auto result_pair = result.find(key);
        BOOST_TEST((result_pair != result.cend()), "Field " << key << " presented");
        if (result_pair != result.end())
        {
            BOOST_CHECK_EQUAL(result_pair->second, value);
        }
    }
}

BOOST_AUTO_TEST_CASE(Base64LabelParsingWithMediaType)
{
    const string label("data:application/x-www-form-urlencoded;base64,dj0xJnR5cGU9SUQtY2FyZCZzZXJpYWxfbnVtYmVyPVBOT0VFLTM4MDAxMDg1NzE4JmNuPUolQzMlOTVFT1JHJTJDSkFBSy1LUklTVEpBTiUyQzM4MDAxMDg1NzE4");

    auto result = libcdoc::Lock::parseLabel(label);
    for (const auto& [key, value] : ExpectedParsedLabel)
    {
        auto result_pair = result.find(key);
        BOOST_TEST((result_pair != result.cend()), "Field " << key << " presented");
        if (result_pair != result.end())
        {
            BOOST_CHECK_EQUAL(result_pair->second, value);
        }
    }
}

BOOST_AUTO_TEST_CASE(LabelParsingEmptyLabel)
{
    const string label("data:v=1&type=pw&label=");

    auto result = libcdoc::Lock::parseLabel(label);
    for (const auto& [key, value] : {
            pair<string, string> {"v", "1"},
            pair<string, string> {"type", "pw"},
            pair<string, string> {"label", ""},
        })
    {
        auto result_pair = result.find(key);
        BOOST_TEST((result_pair != result.cend()), "Field " << key << " presented");
        if (result_pair != result.end())
        {
            BOOST_CHECK_EQUAL(result_pair->second, value);
        }
    }
}

// N3 regression: the base64 decoder (jwt::base::decode) throws
// std::runtime_error on malformed input. A crafted container label must
// not crash the process; the label is reported as unparseable instead.
BOOST_AUTO_TEST_CASE(Base64LabelParsingInvalidBase64)
{
    // Characters outside the base64 alphabet.
    BOOST_CHECK(libcdoc::Lock::parseLabel("data:;base64,###").empty());
    // Valid alphabet but impossible length (single character).
    BOOST_CHECK(libcdoc::Lock::parseLabel("data:;base64,A").empty());
    // Too much padding.
    BOOST_CHECK(libcdoc::Lock::parseLabel("data:;base64,QQ===").empty());
    // Same, with a media type part in front.
    BOOST_CHECK(libcdoc::Lock::parseLabel("data:application/x-www-form-urlencoded;base64,###").empty());
    // Trailing garbage after otherwise valid base64.
    BOOST_CHECK(libcdoc::Lock::parseLabel("data:;base64,dj0x###").empty());
}

BOOST_AUTO_TEST_SUITE_END()

// N3 regression: libcdoc::fromBase64 decodes untrusted data (key server
// and share server responses). Malformed input must yield an empty vector,
// not an exception.
BOOST_AUTO_TEST_SUITE(FromBase64)

BOOST_AUTO_TEST_CASE(ValidInput)
{
    // "hello world"
    std::vector<uint8_t> expected {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    BOOST_CHECK(libcdoc::fromBase64("aGVsbG8gd29ybGQ=") == expected);
    BOOST_CHECK(libcdoc::fromBase64("").empty());
}

BOOST_AUTO_TEST_CASE(InvalidInputReturnsEmpty)
{
    // Characters outside the alphabet.
    BOOST_CHECK(libcdoc::fromBase64("###").empty());
    BOOST_CHECK(libcdoc::fromBase64("aGVsbG8###").empty());
    // Impossible lengths (not a multiple of 4 after padding rules).
    BOOST_CHECK(libcdoc::fromBase64("A").empty());
    // Excess padding.
    BOOST_CHECK(libcdoc::fromBase64("QQ===").empty());
    // Padding in the middle.
    BOOST_CHECK(libcdoc::fromBase64("QQ==QQ==").empty());
}

// S2 regression: same non-throwing contract for fromBase64URL (session
// token parts, SD-JWT disclosures - all server-controlled).
BOOST_AUTO_TEST_CASE(UrlValidInput)
{
    // "hello world" in unpadded base64url (fromBase64URL pads it).
    std::vector<uint8_t> expected {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    BOOST_CHECK(libcdoc::fromBase64URL("aGVsbG8gd29ybGQ") == expected);
    BOOST_CHECK(libcdoc::fromBase64URL("").empty());
}

BOOST_AUTO_TEST_CASE(UrlInvalidInputReturnsEmpty)
{
    // Characters outside the base64url alphabet.
    BOOST_CHECK(libcdoc::fromBase64URL("###").empty());
    BOOST_CHECK(libcdoc::fromBase64URL("aGVsbG8+//").empty());
    // Padding character in the middle hits the alphabet check.
    BOOST_CHECK(libcdoc::fromBase64URL("QQ==QQ").empty());
    // Impossible length.
    BOOST_CHECK(libcdoc::fromBase64URL("A").empty());
    // Trailing padding is tolerated (RFC 4648 allows '=' in base64url):
    // fromBase64URL strips it before decoding, so "QQ===" == "QQ" == {0x41}.
    std::vector<uint8_t> expected {0x41};
    BOOST_CHECK(libcdoc::fromBase64URL("QQ===") == expected);
    BOOST_CHECK(libcdoc::fromBase64URL("QQ") == expected);
}

// S2 regression: decodeTicket parses server-issued JWTs; malformed input
// must yield an empty string, not an exception.
BOOST_AUTO_TEST_CASE(DecodeTicketInvalidReturnsEmpty)
{
    BOOST_CHECK(libcdoc::decodeTicket("").empty());
    BOOST_CHECK(libcdoc::decodeTicket("not-a-jwt").empty());
    // Three parts but payload is not valid base64url JSON.
    BOOST_CHECK(libcdoc::decodeTicket("AAA.###.BBB").empty());
    // Valid base64url parts but the payload is not JSON.
    BOOST_CHECK(libcdoc::decodeTicket("dHlw.bm90LWpzb24.c2ln").empty());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(TarPaxHeader)

struct PaxFixture : public FixtureBase
{
    static void encryptDecrypt(const fs::path& srcFile, const fs::path& cdocFile, const fs::path& outDir)
    {
        std::vector<libcdoc::RcptInfo> rcpts {
            {libcdoc::RcptInfo::PASSWORD, "label", {}, Password}
        };
        encrypt(2, {libcdoc::decodeName(srcFile)}, libcdoc::decodeName(cdocFile), rcpts);

        libcdoc::RcptInfo rcpt {
            .type=libcdoc::RcptInfo::LOCK,
            .label="label",
            .secret=Password
        };
        libcdoc::ToolConf conf;
        conf.input_files.push_back(libcdoc::decodeName(cdocFile));
        conf.out = libcdoc::decodeName(outDir);
        libcdoc::CDocCipher cipher;
        BOOST_CHECK_EQUAL(cipher.Decrypt(conf, rcpt), 0);
    }
};

BOOST_FIXTURE_TEST_CASE(LongFilename, PaxFixture)
{
    const std::string name(110, 'a');
    const fs::path src = tmpDataPath / name;
    std::ofstream(src) << "hello";
    BOOST_TEST_REQUIRE(fs::exists(src));

    const fs::path cdoc = tmpDataPath / "pax_long.cdoc";
    const fs::path outDir = tmpDataPath / "pax_long_out";
    fs::create_directories(outDir);

    encryptDecrypt(src, cdoc, outDir);
    BOOST_TEST(fs::exists(outDir / name));
}

BOOST_FIXTURE_TEST_CASE(NonAsciiFilename, PaxFixture)
{
    // Include characters outside Windows-1252 to catch accidental ACP conversions.
    const fs::path namePath(u8"\u00f5\u00e4\u00f6\u00fc-\u03b4-\u0436.txt");
    const fs::path src = tmpDataPath / namePath;
    std::ofstream(src) << "hello";
    BOOST_TEST_REQUIRE(fs::exists(src));

    const fs::path cdoc = tmpDataPath / "pax_unicode.cdoc";
    const fs::path outDir = tmpDataPath / "pax_unicode_out";
    fs::create_directories(outDir);

    encryptDecrypt(src, cdoc, outDir);
    BOOST_TEST(fs::exists(outDir / namePath));
}

// Build a single 512-byte ustar header block with the given typeflag,
// name and declared size. The checksum is computed correctly so the
// header passes Header::verify(). Returns a 512-byte vector.
static std::vector<uint8_t>
makeTarHeader(char typeflag, std::string_view name, int64_t size)
{
    std::vector<uint8_t> block(512, 0);

    // name (100 bytes, NUL-terminated within the field)
    std::copy(name.begin(),
              name.begin() + std::min<size_t>(name.size(), 99),
              block.begin());

    // mode "0000600\0", uid "0000000\0", gid "0000000\0"
    auto write_octal_field = [&](size_t offset, size_t width, int64_t value) {
        std::string s(width - 1, '0');
        for (size_t i = 0; i < width - 1 && value > 0; ++i) {
            s[width - 2 - i] = char('0' + (value & 7));
            value >>= 3;
        }
        std::copy(s.begin(), s.end(), block.begin() + offset);
        // trailing NUL is already zero-filled
    };
    write_octal_field(100, 8, 0600);             // mode
    write_octal_field(108, 8, 0);                // uid
    write_octal_field(116, 8, 0);                // gid
    write_octal_field(124, 12, size);            // size  <-- attacker-tamperable
    write_octal_field(136, 12, 0);               // mtime

    // chksum field: 8 spaces during checksum calculation
    std::fill(block.begin() + 148, block.begin() + 156, uint8_t(' '));

    // typeflag
    block[156] = uint8_t(typeflag);

    // ustar magic + version
    constexpr std::string_view magic{"ustar\0", 6};
    std::copy(magic.begin(), magic.end(), block.begin() + 257);
    block[263] = '0';
    block[264] = '0';

    // Compute and write the checksum: unsigned sum of all bytes with
    // chksum replaced by spaces. Field is 6 octal digits + NUL + space.
    int64_t sum = 0;
    for (uint8_t b : block) sum += b;
    std::string chk(7, '0');
    for (size_t i = 0; i < 6 && sum > 0; ++i) {
        chk[5 - i] = char('0' + (sum & 7));
        sum >>= 3;
    }
    chk[6] = '\0';
    std::copy(chk.begin(), chk.end(), block.begin() + 148);
    block[155] = ' ';

    return block;
}

BOOST_AUTO_TEST_CASE(RejectsOversizedPaxExtendedHeader)
{
    // Craft a valid 'x' (extended PAX) header that declares a 100 MiB
    // payload. The traditional ustar size field is 12 bytes (11 octal
    // digits + NUL), capping the directly-encoded size at ~8 GiB minus
    // one; we pick a value comfortably below that ceiling but still
    // many orders of magnitude above the 64 KiB cap on auxiliary
    // headers. Without H-2 in place, TarSource::readPaxHeader would
    // happily allocate 100 MiB and try to read 100 MiB from the stream
    // - times every malicious 'x' header, which is the DoS the cap
    // exists to prevent.
    constexpr int64_t kBadSize = 100LL * 1024 * 1024;
    std::vector<uint8_t> stream = makeTarHeader('x', "PaxHeaders/x", kBadSize);

    libcdoc::VectorSource src(stream);
    libcdoc::TarSource tar_src(&src, /*take_ownership=*/false);
    std::string name;
    int64_t size = 0;
    libcdoc::result_t rv = tar_src.next(name, size);

    BOOST_CHECK_EQUAL(rv, libcdoc::DATA_FORMAT_ERROR);
    BOOST_CHECK(tar_src.isError());
}

BOOST_AUTO_TEST_CASE(RejectsOversizedGlobalPaxHeader)
{
    // Same defence on the 'g' (global PAX) skip path. next() must reject
    // the header without spinning the upstream source through 100 MiB.
    constexpr int64_t kBadSize = 100LL * 1024 * 1024;
    std::vector<uint8_t> stream = makeTarHeader('g', "PaxHeaders/g", kBadSize);

    libcdoc::VectorSource src(stream);
    libcdoc::TarSource tar_src(&src, /*take_ownership=*/false);
    std::string name;
    int64_t size = 0;
    libcdoc::result_t rv = tar_src.next(name, size);

    BOOST_CHECK_EQUAL(rv, libcdoc::DATA_FORMAT_ERROR);
    BOOST_CHECK(tar_src.isError());
}

BOOST_AUTO_TEST_CASE(AllowsReasonablePaxHeaderSize)
{
    // Sanity check: a PAX header with a small, plausible size (one
    // 'path' record for a 50-byte name) must still parse. We do not
    // include the actual data in the stream, so readPaxHeader will
    // surface INPUT_STREAM_ERROR after the cap check passes - the
    // important thing is that DATA_FORMAT_ERROR is NOT returned.
    std::vector<uint8_t> stream = makeTarHeader('x', "PaxHeaders/x", 60);
    libcdoc::VectorSource src(stream);
    libcdoc::TarSource tar_src(&src, /*take_ownership=*/false);
    std::string name;
    int64_t size = 0;
    libcdoc::result_t rv = tar_src.next(name, size);
    BOOST_CHECK_NE(rv, libcdoc::DATA_FORMAT_ERROR);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(StreamingDecryption)
using BufTypes = std::tuple<std::array<uint8_t, 4>, std::array<uint8_t, 16>, std::array<uint8_t, 20>, std::array<uint8_t, 36>>;
BOOST_AUTO_TEST_CASE_TEMPLATE(constructor, Buf, BufTypes)
{
    const std::vector<uint8_t> srouce_text {
        's', 'o', 'm', 'e', ' ', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't', '.', '\n',
        's', 'o', 'm', 'e', ' ', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't', '.', '\n',
        's', 'o', 'm', 'e', ' ', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't', '.', '\n',
    };
    //std::vector<uint8_t> aad = {'A', 'A', 'D'};
    Buf buffer{};
    const auto key = libcdoc::Crypto::generateKey(std::string(libcdoc::Crypto::AES256GCM_MTH));
    const auto method = std::string(libcdoc::Crypto::AES256GCM_MTH);

    for(const auto &plaintext_size : {14, 16, 29, 32, 36})
    {
        auto plaintext = srouce_text;
        plaintext.resize(plaintext_size);
        // Encrypt
        std::vector<uint8_t> encrypted_data;
        libcdoc::VectorConsumer encrypted_dst(encrypted_data);
        libcdoc::EncryptionConsumer encrypt(encrypted_dst, method, key);
        BOOST_CHECK_EQUAL_COLLECTIONS(encrypted_data.begin(), encrypted_data.end(), key.iv.begin(), key.iv.end());
        //BOOST_CHECK_EQUAL(encrypt.writeAAD(aad), libcdoc::OK);
        libcdoc::VectorSource plain_src(plaintext);
        for(libcdoc::result_t read_len = 0; (read_len = plain_src.read(buffer.data(), buffer.size())) > 0; ) {
            BOOST_CHECK_EQUAL(encrypt.write(buffer.data(), read_len), read_len);
        }
        BOOST_CHECK_EQUAL(encrypt.close(), libcdoc::OK);

        // Decrypt
        libcdoc::VectorSource encrypted_src(encrypted_data);
        libcdoc::DecryptionSource decrypt(encrypted_src, method, key.key);
        //BOOST_CHECK_EQUAL(decrypt.readAAD(aad), libcdoc::OK);
        std::vector<uint8_t> decrypted_text;
        for(libcdoc::result_t read_len = 0; (read_len = decrypt.read(buffer.data(), buffer.size())) > 0; ) {
            decrypted_text.insert(decrypted_text.end(), buffer.data(), buffer.data() + read_len);
        }
        BOOST_CHECK_EQUAL(decrypt.isError(), false);
        BOOST_CHECK_EQUAL(decrypt.close(), libcdoc::OK);

        BOOST_CHECK_EQUAL_COLLECTIONS(plaintext.begin(), plaintext.end(), decrypted_text.begin(), decrypted_text.end());
    }
}

BOOST_AUTO_TEST_SUITE_END()

// Regression coverage for libcdoc::sanitiseExtractedFilename(). All inputs
// here come from attacker-controlled archive headers (tar / DDoc); the
// helper is the single chokepoint that decides whether an entry can ever
// reach the filesystem.
BOOST_AUTO_TEST_SUITE(SanitiseExtractedFilename)

BOOST_AUTO_TEST_CASE(PassesThroughOrdinaryNames)
{
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("hello.txt"), "hello.txt");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("a-b_c.dat"), "a-b_c.dat");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("file with spaces.txt"),
                      "file with spaces.txt");
    // Non-ASCII (UTF-8) names must round-trip - libcdoc treats names as
    // opaque UTF-8.
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("\xC3\xB5\xC3\xA4\xC3\xB6.txt"),
                      "\xC3\xB5\xC3\xA4\xC3\xB6.txt");
}

BOOST_AUTO_TEST_CASE(StripsLeadingDirectoryComponents)
{
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("a/b/c.txt"), "c.txt");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("a\\b\\c.txt"), "c.txt");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("/etc/passwd"), "passwd");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("../foo.txt"), "foo.txt");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("a/../foo.txt"), "foo.txt");
}

BOOST_AUTO_TEST_CASE(RejectsTraversalAndEmpty)
{
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename(""), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("."), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename(".."), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("../"), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("..\\"), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("foo/.."), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("/"), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("a/b/"), "");
}

BOOST_AUTO_TEST_CASE(StripsWindowsDriveRelativeNames)
{
    // "C:foo" with NO slash is a drive-relative path on Windows. On POSIX
    // it would normally pass through, but libcdoc applies the same filter
    // on every platform so a malicious archive cannot rely on platform-
    // specific quirks.
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("C:foo.txt"), "foo.txt");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("z:bar"), "bar");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("C:"), "");
    // After a slash strip, the drive prefix on the leaf is also handled.
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("a/C:foo"), "foo");
}

BOOST_AUTO_TEST_CASE(RejectsControlCharsAndNul)
{
    // Embedded NUL is a Windows API truncation hazard.
    std::string with_nul("foo\0bar.txt", 11);
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename(with_nul), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename(std::string("a\x01" "b")), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename(std::string("a\x1F" "b")), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename(std::string("a\nb")), "");
    // Tab is allowed (whitespace, not a control character that breaks
    // filesystems on the platforms libcdoc supports).
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("a\tb"), "a\tb");
}

BOOST_AUTO_TEST_CASE(TrimsTrailingDotsAndSpaces)
{
    // Windows silently strips trailing dots/spaces when creating files,
    // so "evil.exe " and "evil.exe." both resolve to "evil.exe". Strip
    // them before composing the path so we can't be tricked into
    // colliding with a legitimate name.
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("foo.txt..."), "foo.txt");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("foo.txt   "), "foo.txt");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("foo.txt . . "), "foo.txt");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("..."), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("   "), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("  hello  "), "hello");
}

BOOST_AUTO_TEST_CASE(RejectsReservedWindowsDeviceNames)
{
    // On Windows these are device handles regardless of working
    // directory. They would not actually create a file at base/CON, but
    // would open the console device and any subsequent write goes there.
    for (auto name : {"CON", "PRN", "AUX", "NUL",
                      "com1", "Com2", "LPT1", "lpt9"}) {
        BOOST_TEST_INFO("name=" << name);
        BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename(name), "");
    }
    // Reserved name with extension is also reserved on Windows.
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("CON.txt"), "");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("nul.tar.gz"), "");
    // Names that *contain* a reserved word as a substring are NOT
    // reserved (e.g. "console.log").
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("console.log"), "console.log");
    BOOST_CHECK_EQUAL(libcdoc::sanitiseExtractedFilename("nullable"), "nullable");
}

BOOST_AUTO_TEST_CASE(TruncatesOverlongNames)
{
    std::string long_stem(300, 'a');
    auto result = libcdoc::sanitiseExtractedFilename(long_stem + ".dat");
    BOOST_CHECK_LE(result.size(), 255u);
    BOOST_CHECK(result.ends_with(".dat"));     // extension preserved
    // No-extension version simply truncates.
    auto truncated = libcdoc::sanitiseExtractedFilename(std::string(400, 'b'));
    BOOST_CHECK_EQUAL(truncated.size(), 255u);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(XMLReaderEntityHandling)

BOOST_AUTO_TEST_CASE(ReadsPlainXml)
{
    XMLSource input("<root a=\"value\"><child>text</child></root>");
    libcdoc::XMLReader reader(input.source);

    BOOST_REQUIRE(reader.read());
    BOOST_TEST(reader.isElement("root"));
    BOOST_TEST(reader.attribute("a") == "value");

    BOOST_REQUIRE(reader.read());
    BOOST_TEST(reader.isElement("child"));
    BOOST_TEST(reader.readText() == "text");
}

static void rejectsUnsupportedXml(std::string_view xml)
{
    XMLSource input(xml);
    libcdoc::XMLReader reader(input.source);
    BOOST_CHECK(!reader.read());
}

BOOST_AUTO_TEST_CASE(RejectsDoctype)
{
    rejectsUnsupportedXml("<!DOCTYPE root><root/>");
}

BOOST_AUTO_TEST_CASE(RejectsInternalEntityInAttribute)
{
    rejectsUnsupportedXml("<!DOCTYPE root [<!ENTITY xxe 'SECRET'>]><root a='&xxe;'/>");
}

BOOST_AUTO_TEST_CASE(RejectsInternalEntityInText)
{
    rejectsUnsupportedXml("<!DOCTYPE root [<!ENTITY xxe 'SECRET'>]><root>&xxe;</root>");
}

BOOST_AUTO_TEST_CASE(RejectsExternalEntityInAttribute)
{
    rejectsUnsupportedXml("<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root a='&xxe;'/>");
}

BOOST_AUTO_TEST_CASE(RejectsExternalEntityInText)
{
    rejectsUnsupportedXml("<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>");
}

BOOST_AUTO_TEST_CASE(DoesNotChangeGlobalExternalEntityLoader)
{
    auto loader = xmlGetExternalEntityLoader();
    XMLSource input("<root/>");
    libcdoc::XMLReader reader(input.source);

    BOOST_REQUIRE(reader.read());
    BOOST_TEST(xmlGetExternalEntityLoader() == loader);
}

BOOST_AUTO_TEST_SUITE_END()

// Coverage for libcdoc::Cleanser, the RAII guard used by CDoc2Reader::getFMK
// and CDoc2Writer::buildHeader to wipe short-lived KEK / FMK material on
// every exit including exceptions.
BOOST_AUTO_TEST_SUITE(CleanserGuard)

BOOST_AUTO_TEST_CASE(WipesVectorOnScopeExit)
{
    std::vector<uint8_t> secret(32, 0xAA);
    {
        libcdoc::Cleanser guard(secret);
        BOOST_CHECK_EQUAL(secret.front(), 0xAA);     // not yet wiped
    }
    // After the scope exits the destructor runs OPENSSL_cleanse on the
    // current allocation; the vector keeps its size but every byte is 0.
    BOOST_CHECK_EQUAL(secret.size(), 32u);
    for (uint8_t b : secret)
        BOOST_CHECK_EQUAL(b, 0u);
}

BOOST_AUTO_TEST_CASE(WipesArrayOnScopeExit)
{
    std::array<uint8_t, 16> secret{};
    secret.fill(0x55);
    {
        libcdoc::Cleanser guard(secret);
    }
    for (uint8_t b : secret)
        BOOST_CHECK_EQUAL(b, 0u);
}

BOOST_AUTO_TEST_CASE(WipesOnException)
{
    // The whole point of the RAII guard: on an exception thrown out of
    // the protected scope, the destructor still fires and the secret is
    // wiped before the exception unwinds past the caller. This is the
    // failure mode where the audit found the missing cleanses in
    // CDoc2Reader::getFMK.
    std::vector<uint8_t> secret(8, 0xCC);
    auto throws = [&]{
        libcdoc::Cleanser guard(secret);
        throw std::runtime_error("boom");
    };
    BOOST_CHECK_THROW(throws(), std::runtime_error);
    for (uint8_t b : secret)
        BOOST_CHECK_EQUAL(b, 0u);
}

BOOST_AUTO_TEST_CASE(EmptyVectorIsHarmless)
{
    // Edge case: cleanse() short-circuits on an empty container. The
    // guard must not crash or call OPENSSL_cleanse with a null pointer.
    std::vector<uint8_t> empty;
    {
        libcdoc::Cleanser guard(empty);
    }
    BOOST_CHECK(empty.empty());
}

BOOST_AUTO_TEST_SUITE_END()

// Coverage for libcdoc::parseEtsiRecipientId. The helper is the input-
// validation chokepoint for the Mobile-ID / Smart-ID code paths;
// signMID in particular previously called rcpt_id.substr(11, 11)
// without checking the input, which threw std::out_of_range on short
// ids and silently truncated medium-length ones.
BOOST_AUTO_TEST_SUITE(EtsiRecipientIdParsing)

BOOST_AUTO_TEST_CASE(AcceptsCanonicalEstonian)
{
    auto p = libcdoc::parseEtsiRecipientId("etsi/PNOEE-30303039914");
    BOOST_TEST_REQUIRE(p.valid());
    BOOST_CHECK_EQUAL(p.country, "EE");
    BOOST_CHECK_EQUAL(p.national_id, "30303039914");
}

BOOST_AUTO_TEST_CASE(AcceptsOtherCountryCodes)
{
    // The PNO format is shared across SK markets; all that matters is
    // that the country code is two ASCII letters.
    auto p = libcdoc::parseEtsiRecipientId("etsi/PNOLT-12345678901");
    BOOST_TEST_REQUIRE(p.valid());
    BOOST_CHECK_EQUAL(p.country, "LT");
    BOOST_CHECK_EQUAL(p.national_id, "12345678901");
}

BOOST_AUTO_TEST_CASE(NormalisesCountryToUpperCase)
{
    auto p = libcdoc::parseEtsiRecipientId("etsi/PNOee-30303039914");
    BOOST_TEST_REQUIRE(p.valid());
    BOOST_CHECK_EQUAL(p.country, "EE");
}

BOOST_AUTO_TEST_CASE(RejectsShortInput)
{
    // The previous implementation in signMID threw std::out_of_range
    // for any input shorter than 11 characters. The helper must reject
    // these cleanly with .valid() == false.
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNO").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNOEE").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNOEE-").valid());
    // 11 characters but not the right shape.
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/short!").valid());
}

BOOST_AUTO_TEST_CASE(RejectsBadPrefix)
{
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("ETSI/PNOEE-30303039914").valid());   // case-sensitive prefix
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/IDEE-30303039914").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("foo/PNOEE-30303039914").valid());
}

BOOST_AUTO_TEST_CASE(RejectsNonLetterCountryCode)
{
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNO12-30303039914").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNO-E-30303039914").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNOE -30303039914").valid());
}

BOOST_AUTO_TEST_CASE(RejectsMissingSeparator)
{
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNOEE.30303039914").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNOEE/30303039914").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNOEEX0303039914").valid());
}

BOOST_AUTO_TEST_CASE(RejectsNonDigitNationalId)
{
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNOEE-30303039 14").valid());
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId("etsi/PNOEE-3030303991a").valid());
    // Embedded NUL. (sizeof - 1: the literal is 20 chars; a hard-coded
    // length of 22 read 2 bytes past it - caught by ASan.)
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId(std::string("etsi/PNOEE-3030\0039914", sizeof("etsi/PNOEE-3030\0039914") - 1)).valid());
}

BOOST_AUTO_TEST_CASE(RejectsOversizedNationalId)
{
    // 32-byte national id is the documented upper bound; one byte more
    // is rejected.
    auto p32 = libcdoc::parseEtsiRecipientId("etsi/PNOEE-" + std::string(32, '1'));
    BOOST_CHECK(p32.valid());
    auto p33 = libcdoc::parseEtsiRecipientId("etsi/PNOEE-" + std::string(33, '1'));
    BOOST_CHECK(!p33.valid());
    auto pHuge = libcdoc::parseEtsiRecipientId("etsi/PNOEE-" + std::string(1024, '1'));
    BOOST_CHECK(!pHuge.valid());
}

BOOST_AUTO_TEST_SUITE_END()

// S1 regression: the session token's disclosures are the allowlist of share
// servers authorized by the authentication server. The reader must refuse to
// contact (and send credentials to) any container-supplied share server that
// has no disclosure. Matching is by origin (scheme, host, port).
BOOST_AUTO_TEST_SUITE(SessionTokenAuthorization)

// ["salt","https://share1.example.com"]
static const char *DISC1 = "WyJzYWx0IiwiaHR0cHM6Ly9zaGFyZTEuZXhhbXBsZS5jb20iXQ";
// ["salt","https://share2.example.com:8443/v1"]
static const char *DISC2 = "WyJzYWx0IiwiaHR0cHM6Ly9zaGFyZTIuZXhhbXBsZS5jb206ODQ0My92MSJd";

static libcdoc::SessionToken makeToken()
{
    std::string str = std::string("jwt~aud~") + DISC1 + "~" + DISC2;
    return libcdoc::SessionToken(str);
}

BOOST_AUTO_TEST_CASE(AuthorizedServers)
{
    auto st = makeToken();
    // Exact origin.
    BOOST_CHECK(st.hasDisclosureForUrl("https://share1.example.com"));
    // Trailing slash and sub-paths of the same origin.
    BOOST_CHECK(st.hasDisclosureForUrl("https://share1.example.com/"));
    BOOST_CHECK(st.hasDisclosureForUrl("https://share1.example.com/key-shares"));
    // Host names are case-insensitive.
    BOOST_CHECK(st.hasDisclosureForUrl("https://SHARE1.EXAMPLE.COM"));
    // Explicit default port matches the implicit one.
    BOOST_CHECK(st.hasDisclosureForUrl("https://share1.example.com:443"));
    // Disclosure with a non-default port and a path.
    BOOST_CHECK(st.hasDisclosureForUrl("https://share2.example.com:8443"));
    BOOST_CHECK(st.hasDisclosureForUrl("https://share2.example.com:8443/other"));
}

BOOST_AUTO_TEST_CASE(UnauthorizedServers)
{
    auto st = makeToken();
    // Unknown host.
    BOOST_CHECK(!st.hasDisclosureForUrl("https://evil.com"));
    // Domain-suffix confusion.
    BOOST_CHECK(!st.hasDisclosureForUrl("https://share1.example.com.evil.com"));
    // Subdomain is a different origin.
    BOOST_CHECK(!st.hasDisclosureForUrl("https://sub.share1.example.com"));
    // Wrong port.
    BOOST_CHECK(!st.hasDisclosureForUrl("https://share2.example.com"));
    BOOST_CHECK(!st.hasDisclosureForUrl("https://share2.example.com:8444"));
    // Plain http is never authorized (parseURL enforces https).
    BOOST_CHECK(!st.hasDisclosureForUrl("http://share1.example.com"));
    // Not a URL at all.
    BOOST_CHECK(!st.hasDisclosureForUrl("share1.example.com"));
    BOOST_CHECK(!st.hasDisclosureForUrl(""));
}

// S7 regression: discloseForUrl binds a disclosure to its server by origin
// (scheme, host, port) - not by substring. A disclosure for
// share1.example.com must not be disclosed to share1.example.com.evil.com.
BOOST_AUTO_TEST_CASE(DiscloseForUrlBindsByOrigin)
{
    auto st = makeToken();
    // Exact origin -> the matching disclosure is appended.
    BOOST_CHECK_EQUAL(st.discloseForUrl("https://share1.example.com"),
                      std::string("jwt~aud~") + DISC1 + "~");
    // Sub-path of the same origin still matches (nonces live on the path).
    BOOST_CHECK_EQUAL(st.discloseForUrl("https://share1.example.com/key-shares"),
                      std::string("jwt~aud~") + DISC1 + "~");
    // Non-default port matches only with the same port.
    BOOST_CHECK_EQUAL(st.discloseForUrl("https://share2.example.com:8443"),
                      std::string("jwt~aud~") + DISC2 + "~");
    // Domain-suffix confusion -> no disclosure.
    BOOST_CHECK(st.discloseForUrl("https://share1.example.com.evil.com").empty());
    // Unknown host / subdomain / wrong port / plain http -> no disclosure.
    BOOST_CHECK(st.discloseForUrl("https://evil.com").empty());
    BOOST_CHECK(st.discloseForUrl("https://sub.share1.example.com").empty());
    BOOST_CHECK(st.discloseForUrl("https://share2.example.com").empty());
    BOOST_CHECK(st.discloseForUrl("http://share1.example.com").empty());
}

BOOST_AUTO_TEST_CASE(MalformedDisclosuresAreSkipped)
{
    // Bad base64url and non-JSON disclosures must not throw or match.
    std::string str = std::string("jwt~aud~###~bm90LWpzb24~") + DISC1;
    libcdoc::SessionToken st(str);
    BOOST_CHECK(st.hasDisclosureForUrl("https://share1.example.com"));
    BOOST_CHECK(!st.hasDisclosureForUrl("https://evil.com"));
}

BOOST_AUTO_TEST_CASE(EmptyOrDisclosurelessTokenFailsClosed)
{
    libcdoc::SessionToken empty("");
    BOOST_CHECK(!empty.hasDisclosureForUrl("https://share1.example.com"));
    // jwt~aud with no disclosures.
    libcdoc::SessionToken twopart("jwt~aud");
    BOOST_CHECK(!twopart.hasDisclosureForUrl("https://share1.example.com"));
}

BOOST_AUTO_TEST_SUITE_END()

// Regression coverage for the constant-time PKCS#1 v1.5 unpadding used by
// the RSA implicit-rejection path (N1 in SecurityReview_Kilo_2026-07.md).
// The index-clamping mask in unpadPKCS1v15CT was a single byte (0x00/0xFF)
// instead of a full-width size_t mask, which spliced the low byte of the
// source index with the high bits of (em.size() - 1) and read past the end
// of the EM buffer for modulus lengths that are not a multiple of 256
// bytes (e.g. the 384-byte EM of a 3072-bit RSA key, up to 128 bytes OOB).
BOOST_AUTO_TEST_SUITE(RsaImplicitRejectUnpad)

// Sweep the zero separator across the whole EM block: output must be the
// real message exactly when the padding is valid (00 02 || PS>=8 || 00 ||
// M of expected_len) and the synthetic plaintext in every other case.
// Under ASAN this also fails on any out-of-bounds EM access.
static void sweepSeparatorPositions(size_t em_len)
{
    constexpr size_t expected_len = 32;
    std::vector<uint8_t> synth(expected_len);
    for (size_t i = 0; i < expected_len; i++)
        synth[i] = uint8_t(0xA0 + i);

    for (size_t sep = 2; sep < em_len; sep++) {
        std::vector<uint8_t> em(em_len, 0x55);
        em[0] = 0x00;
        em[1] = 0x02;
        em[sep] = 0x00;

        std::vector<uint8_t> dst;
        BOOST_REQUIRE_EQUAL(libcdoc::Crypto::rsaImplicitRejectFromEM(dst, em, {0x01}, synth, expected_len), libcdoc::OK);
        BOOST_REQUIRE_EQUAL(dst.size(), expected_len);

        const size_t msg_len = em_len - sep - 1;
        const bool expect_real = (sep >= 10) && (msg_len == expected_len);
        for (size_t i = 0; i < expected_len; i++) {
            const uint8_t want = expect_real ? em[sep + 1 + i] : synth[i];
            BOOST_CHECK_EQUAL(dst[i], want);
        }
    }
}

BOOST_AUTO_TEST_CASE(SeparatorSweepAllModulusSizes)
{
    sweepSeparatorPositions(192);   // 1536-bit RSA
    sweepSeparatorPositions(256);   // 2048-bit RSA
    sweepSeparatorPositions(384);   // 3072-bit RSA (read up to +128 bytes OOB before the fix)
    sweepSeparatorPositions(512);   // 4096-bit RSA
}

BOOST_AUTO_TEST_CASE(ValidPaddingReturnsMessage3072)
{
    // Valid-padding 3072-bit case (message at the end of the EM block);
    // the old byte-wide mask happened to compute these indices correctly.
    // The actual OOB reproducer is the separator sweep above: for 384-byte
    // EMs, separator positions 127..254 made the old mask splice read past
    // the buffer (padding is invalid there, so only ASAN observes it).
    constexpr size_t em_len = 384;
    constexpr size_t expected_len = 32;
    constexpr size_t sep = em_len - expected_len - 1;
    std::vector<uint8_t> em(em_len, 0x55);
    em[0] = 0x00;
    em[1] = 0x02;
    em[sep] = 0x00;
    std::vector<uint8_t> synth(expected_len, 0xAA);

    std::vector<uint8_t> dst;
    BOOST_REQUIRE_EQUAL(libcdoc::Crypto::rsaImplicitRejectFromEM(dst, em, {0x01}, synth, expected_len), libcdoc::OK);
    BOOST_REQUIRE_EQUAL(dst.size(), expected_len);
    for (size_t i = 0; i < expected_len; i++)
        BOOST_CHECK_EQUAL(dst[i], em[sep + 1 + i]);
}

BOOST_AUTO_TEST_CASE(BadHeaderReturnsSynthetic)
{
    constexpr size_t em_len = 384;
    constexpr size_t expected_len = 32;
    std::vector<uint8_t> em(em_len, 0x55);
    em[0] = 0x01;   // wrong leading byte
    em[1] = 0x02;
    em[em_len - expected_len - 1] = 0x00;
    std::vector<uint8_t> synth(expected_len, 0xAA);

    std::vector<uint8_t> dst;
    BOOST_REQUIRE_EQUAL(libcdoc::Crypto::rsaImplicitRejectFromEM(dst, em, {0x01}, synth, expected_len), libcdoc::OK);
    BOOST_CHECK(dst == synth);
}

BOOST_AUTO_TEST_CASE(NoSeparatorReturnsSynthetic)
{
    constexpr size_t em_len = 384;
    constexpr size_t expected_len = 32;
    std::vector<uint8_t> em(em_len, 0x55);
    em[0] = 0x00;
    em[1] = 0x02;
    std::vector<uint8_t> synth(expected_len, 0xAA);

    std::vector<uint8_t> dst;
    BOOST_REQUIRE_EQUAL(libcdoc::Crypto::rsaImplicitRejectFromEM(dst, em, {0x01}, synth, expected_len), libcdoc::OK);
    BOOST_CHECK(dst == synth);
}

BOOST_AUTO_TEST_SUITE_END()

// S5 regression: a keyshare recipient with fewer than 2 share servers would
// hand the complete KEK to a single server (the XOR split degenerates).
// CDoc2Writer must refuse with CONFIGURATION_ERROR.
BOOST_AUTO_TEST_SUITE(KeyShareWriter)

namespace {

struct ShareServerConf : public libcdoc::Configuration {
    std::string urls;
    explicit ShareServerConf(std::string u) : urls(std::move(u)) {}
    std::string getValue(std::string_view domain, std::string_view param) const override {
        if (param == libcdoc::Configuration::SHARE_SERVER_URLS)
            return urls;
        return {};
    }
};

// Avoids real network connections for the two-server control case.
struct StubNetworkBackend : public libcdoc::NetworkBackend {
    libcdoc::result_t sendShare(std::vector<uint8_t>&, const std::string&, const std::string&, const std::vector<uint8_t>&) override {
        return libcdoc::NOT_IMPLEMENTED;
    }
};

libcdoc::result_t encryptWithShareServers(libcdoc::Configuration& conf, libcdoc::NetworkBackend& network)
{
    std::vector<uint8_t> out;
    libcdoc::VectorConsumer consumer(out);
    libcdoc::CryptoBackend crypto;
    std::unique_ptr<libcdoc::CDocWriter> writer(libcdoc::CDocWriter::createWriter(2, &consumer, false, &conf, &crypto, &network));
    libcdoc::Recipient rcpt = libcdoc::Recipient::makeShare("label", "server1", "PNOEE-30303039914");
    if (auto rv = writer->addRecipient(rcpt); rv != libcdoc::OK)
        return rv;
    return writer->beginEncryption();
}

} // namespace

BOOST_AUTO_TEST_CASE(MissingServerListIsConfigurationError)
{
    ShareServerConf conf({});
    StubNetworkBackend network;
    BOOST_CHECK_EQUAL(encryptWithShareServers(conf, network), libcdoc::CONFIGURATION_ERROR);
}

BOOST_AUTO_TEST_CASE(SingleServerIsConfigurationError)
{
    ShareServerConf conf(R"(["https://share1.example.com"])");
    StubNetworkBackend network;
    BOOST_CHECK_EQUAL(encryptWithShareServers(conf, network), libcdoc::CONFIGURATION_ERROR);
}

BOOST_AUTO_TEST_CASE(TwoServersPassTheCountCheck)
{
    ShareServerConf conf(R"(["https://share1.example.com", "https://share2.example.com"])");
    StubNetworkBackend network;
    // Gets past the URL-count check and fails later in the (stubbed) share
    // upload - i.e. NOT with CONFIGURATION_ERROR.
    BOOST_CHECK_EQUAL(encryptWithShareServers(conf, network), libcdoc::NOT_IMPLEMENTED);
}

BOOST_AUTO_TEST_SUITE_END()

// S8 regression: client-side validation of Smart-ID (ACSP_V2) auth tickets.
// All vectors come from a cdoc-tool Smart-ID session log (2026-08-06) using a
// Smart-ID TEST identity (serialNumber PNOEE-30303039903) - no real PII.
// The signature was independently verified with OpenSSL.
BOOST_AUTO_TEST_SUITE(SidTicketValidation)

namespace {

static const char *SID_CERT_B64 =
        "MIIGqDCCBi6gAwIBAgIQfCl8dqrXBKOVGG0OTfMqTzAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0"
        "aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkG"
        "A1UEBhMCRUUwHhcNMjYwNTE4MTI0NTEzWhcNMjkwNTE3MTI0NTEyWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzEN"
        "MAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTMwMzAzMDM5OTAzMIIDIjANBgkqhkiG9w0BAQEFAAOC"
        "Aw8AMIIDCgKCAwEAsbP7GwkiyLnVk4Xneq76DuDklgie/LurancUp5Mw13Pn7Sp/XTnie1PtWHIgZFsvKKHRWwHFB4H/XQisgZS7"
        "yfRYVe2u3cfSuoH/W5oRpnAnojaltBQZRE6LM5WRhqI6+sdcoGM938AWEkr/gThU3DPSGglZ0mNEOR7SvVHtaKz4KAc1XQZtyHmo"
        "iZ/eqNW7Nlj1s3A66jmEBTq4aiqlx0JXhfgmNV+1yw81vEwB0LHQLadp3Ca2G60bDMQItzWpe8pzd2gUv6smxjKq3MnVVsgYEAFw"
        "kbeuDR3OLUbWbnSTAn9Y5DfDW30xRg4if1I+ruDWLicv5vJXsHCgjgUqLlk9/v+gIFuieJhczyZh9+FOSmCOREqrWOyGUNzCFruV"
        "yg+Z6o8NRZkz9cNqFCUU7O3FnpIHC/1Vz08hJJZLzaF3Ao9qg7WkdNEz28wCuFeVSq/yp1gEEpvnMdYM6FUUUM+y+/b7N61pgk1M"
        "P7ljTREJ0bHY5O8y0/YynP4NI36nKyNbGhsgtqhquHfLWCaCm/kLdgymQUNI1VCl1XcmYtCZkFFB9Ru7EtmTfuk2Lc7mdQYEHutH"
        "qWIUywSJvm1P878PYXRtqNY2hu6MuyarN5uQIO887R1ho+IeN2BUGsEArUeN8RCuqr2J5DZj4GloReZ7GYFWFBXTNKaDRu+deLOj"
        "/41Hztg4ITjOSUnh6/Z2kkRPkH7rhNT4+irtRfiXG2MMsV+kEVO4p/j+l7lofbL0NbkUlskd4Od6iox3YCXIicxY+5JSj63QLU1r"
        "Gv6EbFHkPAseZ+MYys2J99KGToAtz+XOMyKr3VJp7vc4RWBhNcRygm/Oj60DgXQS/ph2y1ZMfl7NL3m2jAJQzADTqBahOuTuJj57"
        "BObdI7xV8bwOI8sFSFG3xVfKpoPkvi4C+G+rxErims2CC5rezJBwwVJtLCQ2CA1e/+4kv1DBja8Z1jzBfFXypXQfT1fXN+jL54+0"
        "85JNiBeCfXUnUPUW+gjl+ea+17m9Y0b5XTu4QyF5AgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4"
        "zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5k"
        "ZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQD"
        "DBhQTk9FRS0zMDMwMzAzOTkwMy1ERU0xLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93"
        "d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAo"
        "BgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDMwMzAzMTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTAr"
        "MCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUFxWovRQENDMS4BItkheOSBR1dPcw"
        "DgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMDA2gAMGUCMQDcI/ZV6SPo13ZPwsjhLMS9n6ZN1czKd02I/eKj67RBOOD1HWkW0DJ6"
        "QxDoUoeaTcACMFdNOAY2BotlUO6uZWlWdUFjoqVZOGEgZVHGJkIxPZ04+SrO4jMOukWuZQqJYM4WZQ==";

static const char *SID_CERT_B64URL =
        "MIIGqDCCBi6gAwIBAgIQfCl8dqrXBKOVGG0OTfMqTzAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0"
        "aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkG"
        "A1UEBhMCRUUwHhcNMjYwNTE4MTI0NTEzWhcNMjkwNTE3MTI0NTEyWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzEN"
        "MAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTMwMzAzMDM5OTAzMIIDIjANBgkqhkiG9w0BAQEFAAOC"
        "Aw8AMIIDCgKCAwEAsbP7GwkiyLnVk4Xneq76DuDklgie_LurancUp5Mw13Pn7Sp_XTnie1PtWHIgZFsvKKHRWwHFB4H_XQisgZS7"
        "yfRYVe2u3cfSuoH_W5oRpnAnojaltBQZRE6LM5WRhqI6-sdcoGM938AWEkr_gThU3DPSGglZ0mNEOR7SvVHtaKz4KAc1XQZtyHmo"
        "iZ_eqNW7Nlj1s3A66jmEBTq4aiqlx0JXhfgmNV-1yw81vEwB0LHQLadp3Ca2G60bDMQItzWpe8pzd2gUv6smxjKq3MnVVsgYEAFw"
        "kbeuDR3OLUbWbnSTAn9Y5DfDW30xRg4if1I-ruDWLicv5vJXsHCgjgUqLlk9_v-gIFuieJhczyZh9-FOSmCOREqrWOyGUNzCFruV"
        "yg-Z6o8NRZkz9cNqFCUU7O3FnpIHC_1Vz08hJJZLzaF3Ao9qg7WkdNEz28wCuFeVSq_yp1gEEpvnMdYM6FUUUM-y-_b7N61pgk1M"
        "P7ljTREJ0bHY5O8y0_YynP4NI36nKyNbGhsgtqhquHfLWCaCm_kLdgymQUNI1VCl1XcmYtCZkFFB9Ru7EtmTfuk2Lc7mdQYEHutH"
        "qWIUywSJvm1P878PYXRtqNY2hu6MuyarN5uQIO887R1ho-IeN2BUGsEArUeN8RCuqr2J5DZj4GloReZ7GYFWFBXTNKaDRu-deLOj"
        "_41Hztg4ITjOSUnh6_Z2kkRPkH7rhNT4-irtRfiXG2MMsV-kEVO4p_j-l7lofbL0NbkUlskd4Od6iox3YCXIicxY-5JSj63QLU1r"
        "Gv6EbFHkPAseZ-MYys2J99KGToAtz-XOMyKr3VJp7vc4RWBhNcRygm_Oj60DgXQS_ph2y1ZMfl7NL3m2jAJQzADTqBahOuTuJj57"
        "BObdI7xV8bwOI8sFSFG3xVfKpoPkvi4C-G-rxErims2CC5rezJBwwVJtLCQ2CA1e_-4kv1DBja8Z1jzBfFXypXQfT1fXN-jL54-0"
        "85JNiBeCfXUnUPUW-gjl-ea-17m9Y0b5XTu4QyF5AgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4"
        "zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5k"
        "ZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQD"
        "DBhQTk9FRS0zMDMwMzAzOTkwMy1ERU0xLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93"
        "d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAo"
        "BgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDMwMzAzMTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTAr"
        "MCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUFxWovRQENDMS4BItkheOSBR1dPcw"
        "DgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMDA2gAMGUCMQDcI_ZV6SPo13ZPwsjhLMS9n6ZN1czKd02I_eKj67RBOOD1HWkW0DJ6"
        "QxDoUoeaTcACMFdNOAY2BotlUO6uZWlWdUFjoqVZOGEgZVHGJkIxPZ04-SrO4jMOukWuZQqJYM4WZQ";

static const char *SID_SIG_B64 =
        "XN6OijUhZvTQDMME7I2OLzYu84lNhWl9FjKG8sfHBNvpVhsmaz2LR/WzTrJJ+QyVpz9A+o0i+Dl4Zf0v1MR79cjAHIhpsbrQVhC3"
        "vlWmoE1s3tKoqWNLxyr2ub46J8H3Aac8x/62RiELsxhBO0JrEA8Vf4N0gXTqoSXxFBK/vbH7ANxbCP+Nx/DsnK1dUPLUQO+44Srs"
        "qTv6ZVCO5QFV0cnQIS7wITbx41qCukKwL4nglNV52dGfzoLQh9LP+OlSbFkj3+gYWyoVKniBXXPb4G5wBVVSnjsfWaT5RyELNpV5"
        "9A6Ucp7Kj9MUVi/pZY3iDl79AZM71QMfx9VMiR/nBVcwxINDsqW56WQiVzKqLqeys6eI6J4udqSctdNybYUuYhQIq7qYc1Up8sLQ"
        "RZcpVHvD13648aMgCheyf7TnamA2fmtOFj/0Lnu3TPMX2Nyg+TWpRLYVlIsYO1fyQTkquST0QlONn5ayhL9nPzbEOwuEea6kWEuM"
        "aakt0jLOSvs2dwwFIvypmisv/ywjJhC7pbinpE8M3RK7u9AS915SKNnBAgJXURKCO2HQ91fnNuz0KlpUODTKKpU1DN8pjskRodos"
        "SBdRjsUuzsegw1QJAO9o/OL7qV1p1mDf48GlrPwz9VNVxqjh0Y2OjcWkdzQBgnPZwzBNErWVPgm0YOx75D3Wpp4dkgWeZkEItlxW"
        "im8DNyBsOwOahsn/EMrqm3MYpv1SPMAFZH0aIAdvIbzEfapacqIHgFX4U4HrXSHzpLGsjs8dNlIrJtHZoN8d5HfxCS1wHZnv8whP"
        "h5+Us4jAbAGz+Z/mUBg45AQPB8cTSnqgOlpOHqDri7/XoK0S8wYwlNjwrVXSuZjj++vAIudh5Q4QBrxKuT7ASMeZwjVhw384kWhK"
        "RDck7Y0wTHOBSG+pVY7VCiWNsbd8Kc1Jy8DGtvtUiIdCJv/KZNjjckvoBVKN/NDthwZMxj8iIfVtsf+GWx+D6CvytpxwXFR+RFtz"
        "5efHmlxhyK2fnE3DLJ6J1NKK";

static const char *SID_TICKET_JWT =
        "eyJhbGciOiJSU0FTU0EtUFNTK0FDU1BfVjIiLCJ0eXAiOiJ2bmQuY2RvYzIuYXV0aC10b2tlbi52MStzZC1qd3QifQ.eyJfc2QiO"
        "lsiX1NvQmRrZlVoeHJSbGpFRHhuazVrbkdkOWs4QVlKdUxya2s2NkZkVVI4byJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6I"
        "mV0c2lcL1BOT0VFLTMwMzAzMDM5OTAzIn0.XN6OijUhZvTQDMME7I2OLzYu84lNhWl9FjKG8sfHBNvpVhsmaz2LR_WzTrJJ-QyVp"
        "z9A-o0i-Dl4Zf0v1MR79cjAHIhpsbrQVhC3vlWmoE1s3tKoqWNLxyr2ub46J8H3Aac8x_62RiELsxhBO0JrEA8Vf4N0gXTqoSXxF"
        "BK_vbH7ANxbCP-Nx_DsnK1dUPLUQO-44SrsqTv6ZVCO5QFV0cnQIS7wITbx41qCukKwL4nglNV52dGfzoLQh9LP-OlSbFkj3-gYW"
        "yoVKniBXXPb4G5wBVVSnjsfWaT5RyELNpV59A6Ucp7Kj9MUVi_pZY3iDl79AZM71QMfx9VMiR_nBVcwxINDsqW56WQiVzKqLqeys"
        "6eI6J4udqSctdNybYUuYhQIq7qYc1Up8sLQRZcpVHvD13648aMgCheyf7TnamA2fmtOFj_0Lnu3TPMX2Nyg-TWpRLYVlIsYO1fyQ"
        "TkquST0QlONn5ayhL9nPzbEOwuEea6kWEuMaakt0jLOSvs2dwwFIvypmisv_ywjJhC7pbinpE8M3RK7u9AS915SKNnBAgJXURKCO"
        "2HQ91fnNuz0KlpUODTKKpU1DN8pjskRodosSBdRjsUuzsegw1QJAO9o_OL7qV1p1mDf48GlrPwz9VNVxqjh0Y2OjcWkdzQBgnPZw"
        "zBNErWVPgm0YOx75D3Wpp4dkgWeZkEItlxWim8DNyBsOwOahsn_EMrqm3MYpv1SPMAFZH0aIAdvIbzEfapacqIHgFX4U4HrXSHzp"
        "LGsjs8dNlIrJtHZoN8d5HfxCS1wHZnv8whPh5-Us4jAbAGz-Z_mUBg45AQPB8cTSnqgOlpOHqDri7_XoK0S8wYwlNjwrVXSuZjj-"
        "-vAIudh5Q4QBrxKuT7ASMeZwjVhw384kWhKRDck7Y0wTHOBSG-pVY7VCiWNsbd8Kc1Jy8DGtvtUiIdCJv_KZNjjckvoBVKN_NDth"
        "wZMxj8iIfVtsf-GWx-D6CvytpxwXFR-RFtz5efHmlxhyK2fnE3DLJ6J1NKK";

static const char *SID_PARAMS_JSON = R"({"interactionTypeUsed":"confirmationMessageAndVerificationCodeChoice","interactionsDigest":"l3Fawq7fsklfb+ZkDsZcJICehrtVrMmhidQ4Ha+gTM0=","signature":{"flowType":"Notification","serverRandom":"tjB5sLBWR8OVEJDOgUPRKhk4","signatureAlgorithm":"rsassa-pss","signatureAlgorithmParameters":{"hashAlgorithm":"SHA-256","maskGenAlgorithm":{"algorithm":"id-mgf1","parameters":{"hashAlgorithm":"SHA-256"}},"saltLength":32,"trailerField":"0xbc"},"userChallenge":"_eegCn9XBOQSqQRUQPRflc7r1CDJcz0k4jBL1AqpPmk"}})";

std::vector<uint8_t> sidCert() { return libcdoc::fromBase64(SID_CERT_B64); }
std::vector<uint8_t> sidSig() { return libcdoc::fromBase64(SID_SIG_B64); }

std::vector<uint8_t> sidPayload()
{
    std::string p = libcdoc::buildAcspV2Payload("smart-id-demo", "tjB5sLBWR8OVEJDOgUPRKhk4",
        "p6jwyzPizfS8+DozeW4fytXf0OVDp4hCHqvJWIlKLfg=", "_eegCn9XBOQSqQRUQPRflc7r1CDJcz0k4jBL1AqpPmk",
        "DEMO", "l3Fawq7fsklfb+ZkDsZcJICehrtVrMmhidQ4Ha+gTM0=",
        "confirmationMessageAndVerificationCodeChoice", "Notification");
    return {p.begin(), p.end()};
}

std::string sidTicket()
{
    // The disclosures are irrelevant for validation; any suffix works.
    return std::string(SID_TICKET_JWT) + "~aud~ZGlzY2xvc3VyZQ";
}

std::string makeSessionToken(const std::string& payload_json)
{
    std::string h = libcdoc::toBase64URL(R"({"typ":"vnd.cdoc2.session-token.v2+sd-jwt","alg":"ES256"})");
    std::string p = libcdoc::toBase64URL(payload_json);
    // jwt~aud~disclosure (SessionToken needs >= 3 parts)
    return h + "." + p + ".c2ln~aud~ZGlzYw";
}

} // namespace

BOOST_AUTO_TEST_CASE(ValidateSignatureReferenceVector)
{
    const auto algo = libcdoc::Crypto::SignatureAlgorithm::RSASSA_PSS_SHA256;
    // The ACSP_V2 signature from the log verifies (verified independently with OpenSSL).
    BOOST_CHECK(libcdoc::Crypto::validateSignature(sidCert(), sidPayload(), sidSig(), algo));
    // Tampered payload must not verify.
    auto bad = sidPayload();
    bad[10] ^= 0x01;
    BOOST_CHECK(!libcdoc::Crypto::validateSignature(sidCert(), bad, sidSig(), algo));
    // Garbage certificate must not verify (and must not crash).
    BOOST_CHECK(!libcdoc::Crypto::validateSignature({1, 2, 3}, sidPayload(), sidSig(), algo));
}

BOOST_AUTO_TEST_CASE(ValidateCertificateIdentity)
{
    libcdoc::CryptoBackend crypto;
    // The test certificate's subject serialNumber is PNOEE-30303039903.
    BOOST_CHECK_EQUAL(crypto.validateCertificate("etsi/PNOEE-30303039903", sidCert()), libcdoc::OK);
    // Also accepted without the etsi/ prefix.
    BOOST_CHECK_EQUAL(crypto.validateCertificate("PNOEE-30303039903", sidCert()), libcdoc::OK);
    // Different person (another Smart-ID test number).
    BOOST_CHECK_EQUAL(crypto.validateCertificate("etsi/PNOEE-30303039914", sidCert()), libcdoc::CRYPTO_ERROR);
    // Garbage DER.
    BOOST_CHECK_EQUAL(crypto.validateCertificate("etsi/PNOEE-30303039903", {1, 2, 3}), libcdoc::CRYPTO_ERROR);
    // Empty id.
    BOOST_CHECK_EQUAL(crypto.validateCertificate("etsi/", sidCert()), libcdoc::CryptoBackend::INVALID_PARAMS);
}

BOOST_AUTO_TEST_CASE(ValidateAuthTicketReferenceVector)
{
    libcdoc::CryptoBackend crypto;
    std::string err;
    // Full ticket from the log validates.
    BOOST_CHECK_EQUAL(libcdoc::validateAuthTicket(&crypto, "etsi/PNOEE-30303039903", sidTicket(),
                                                  sidCert(), SID_PARAMS_JSON, "smart-id-demo", "DEMO", err),
                      libcdoc::OK);
    // Wrong recipient: identity mismatch.
    BOOST_CHECK_EQUAL(libcdoc::validateAuthTicket(&crypto, "etsi/PNOEE-30303039914", sidTicket(),
                                                  sidCert(), SID_PARAMS_JSON, "smart-id-demo", "DEMO", err),
                      libcdoc::CRYPTO_ERROR);
    // Wrong rpName: ACSP_V2 payload mismatch -> signature failure.
    BOOST_CHECK_EQUAL(libcdoc::validateAuthTicket(&crypto, "etsi/PNOEE-30303039903", sidTicket(),
                                                  sidCert(), SID_PARAMS_JSON, "smart-id-demo", "EVIL", err),
                      libcdoc::CRYPTO_ERROR);
    // Tampered serverRandom: signature failure.
    std::string badParams(SID_PARAMS_JSON);
    badParams.replace(badParams.find("tjB5sLBWR8OVEJDOgUPRKhk4"), 24, "AAAAAAAAAAAAAAAAAAAAAA");
    BOOST_CHECK_EQUAL(libcdoc::validateAuthTicket(&crypto, "etsi/PNOEE-30303039903", sidTicket(),
                                                  sidCert(), badParams, "smart-id-demo", "DEMO", err),
                      libcdoc::CRYPTO_ERROR);
    // Missing params entirely.
    BOOST_CHECK_EQUAL(libcdoc::validateAuthTicket(&crypto, "etsi/PNOEE-30303039903", sidTicket(),
                                                  sidCert(), "{}", "smart-id-demo", "DEMO", err),
                      libcdoc::DATA_FORMAT_ERROR);
}

BOOST_AUTO_TEST_CASE(ValidateSessionDataChecks)
{
    libcdoc::CryptoBackend crypto;
    std::string err, scheme, rp;
    std::string good = makeSessionToken(R"({"schemeName":"smart-id-demo","rpName":"DEMO","exp":2000000000})");
    BOOST_CHECK_EQUAL(libcdoc::validateSessionData(&crypto, "etsi/PNOEE-30303039903", false, good, SID_CERT_B64URL,
                                                   scheme, rp, err),
                      libcdoc::OK);
    BOOST_CHECK_EQUAL(scheme, "smart-id-demo");
    BOOST_CHECK_EQUAL(rp, "DEMO");
    // Expired session token.
    std::string expired = makeSessionToken(R"({"schemeName":"smart-id-demo","rpName":"DEMO","exp":1000000000})");
    BOOST_CHECK_EQUAL(libcdoc::validateSessionData(&crypto, "etsi/PNOEE-30303039903", false, expired, SID_CERT_B64URL,
                                                   scheme, rp, err),
                      libcdoc::NetworkBackend::NETWORK_ERROR);
    // Identity mismatch.
    BOOST_CHECK_EQUAL(libcdoc::validateSessionData(&crypto, "etsi/PNOEE-30303039914", false, good, SID_CERT_B64URL,
                                                   scheme, rp, err),
                      libcdoc::CRYPTO_ERROR);
    // Missing scheme claims.
    std::string noclaims = makeSessionToken(R"({"exp":2000000000})");
    BOOST_CHECK_EQUAL(libcdoc::validateSessionData(&crypto, "etsi/PNOEE-30303039903", false, noclaims, SID_CERT_B64URL,
                                                   scheme, rp, err),
                      libcdoc::DATA_FORMAT_ERROR);
}

BOOST_AUTO_TEST_SUITE_END()
