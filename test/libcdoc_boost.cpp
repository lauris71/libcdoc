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
    // Embedded NUL.
    BOOST_CHECK(!libcdoc::parseEtsiRecipientId(std::string("etsi/PNOEE-3030\0039914", 22)).valid());
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
