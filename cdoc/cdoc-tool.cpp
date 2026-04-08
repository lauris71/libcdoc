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

#include <iostream>
#ifndef _WIN32
#include <termios.h>
#include <unistd.h>
#endif

#include "CDocCipher.h"
#include "Utils.h"
#include "Logger.h"

#include "json/jwt.h"

using namespace std;
using namespace libcdoc;

static std::map<std::string_view,libcdoc::LogLevel> str2level = {
    {"FATAL", libcdoc::LEVEL_FATAL},
    {"ERROR", libcdoc::LEVEL_ERROR},
    {"WARNING", libcdoc::LEVEL_WARNING},
    {"INFO", libcdoc::LEVEL_INFO},
    {"DEBUG", libcdoc::LEVEL_DEBUG},
    {"TRACE", libcdoc::LEVEL_TRACE}
};

enum {
    RESULT_OK = 0,
    RESULT_ERROR,
    RESULT_USAGE
};

static void print_usage(ostream& ofs)
{
    ofs << "cdoc-tool version: " << VERSION_STR << endl;
    ofs << "libcdoc version: " << libcdoc::getVersion() << endl;
    ofs << "cdoc-tool encrypt --rcpt RECIPIENT [--rcpt...] [-v1] [--genlabel] --out OUTPUTFILE FILE [FILE...]" << endl;
    ofs << "  Encrypt files for one or more recipients" << endl;
    ofs << "  RECIPIENT has to be one of the following:" << endl;
    ofs << "    [label]:cert:CERTIFICATE_FILE - public key from certificate" << endl;
    ofs << "    [label]:pkey:PUB_KEY_HEX - hex-encoded public key from command line" << endl;
    ofs << "    [label]:pfkey:PUB_KEY_FILE - path to DER file with EC (secp384r1 curve) public key" << endl;
    ofs << "    [label]:skey:SECRET_KEY_HEX - AES key" << endl;
    ofs << "    [label]:pw:PASSWORD - Derive key from provided password using PWBKDF" << endl;
    ofs << "    [label]:p11sk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL] - use AES key from PKCS11 module" << endl;
    ofs << "    [label]:p11pk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL] - use public key from PKCS11 module" << endl;
    ofs << "  -v1 - creates CDOC1 version container. Supported only for encryption with certificate." << endl;
    ofs << "  --genlabel - If specified, the lock label is generated." << endl;
    ofs << endl;
    ofs << "cdoc-tool decrypt ARGUMENTS FILE [OUTPU_DIR]" << endl;
    ofs << "  Decrypt container using lock specified by label" << endl;
    ofs << "  Supported arguments" << endl;
    ofs << "    --label LABEL - CDOC container's lock label" << endl;
    ofs << "    --label_idx INDEX - CDOC container's lock 1-based label index" << endl;
    ofs << "    --slot SLOT - PKCS11 slot number" << endl;
    ofs << "    --password PASSWORD - lock's password" << endl;
    ofs << "    --secret SECRET - secret phrase (AES key)" << endl;
    ofs << "    --pin PIN - PKCS11 pin" << endl;
    ofs << "    --key-id - PKCS11 key ID" << endl;
    ofs << "    --key-label - PKCS11 key label" << endl;
    ofs << endl;
    ofs << "cdoc-tool locks FILE" << endl;
    ofs << endl;
    ofs << "cdoc-tool re-encrypt DECRYPT_ARGUMENTS ENCRYPT_ARGUMENTS FILE --out OUTPUTFILE" << endl;
    ofs << "  Re-encrypts container for different recipient(s)" << endl;
    ofs << endl;
    ofs << "Common arguments:" << endl;
    ofs << "  --library - path to the PKCS11 library to be used" << endl;
    ofs << "  --server ID URL(S) - specifies a key or share server. The recipient key will be stored in server instead of in the document." << endl;
    ofs << "                       for key server the url is either fetch or send url. For share server it is comma-separated list of share server urls." << endl;
    ofs << "  --accept FILENAME  - specifies an accepted server certificate (in der encoding)" << endl;
    ofs << "  --log-level LEVEL  - set logging level (FATAL, ERROR, WARNING, INFO, DEBUG, TRACE)" << endl;
}

static std::vector<uint8_t>
fromB64(const std::string& data)
{
    std::string str = jwt::base::details::decode(data, jwt::alphabet::base64::rdata(), "=");
    return std::vector<uint8_t>(str.cbegin(), str.cend());
}

static void
load_certs(ToolConf& conf, const std::string& filename)
{
    std::vector<uint8_t> content = readAllBytes(filename);
    if ((content.size() > 3) && (content[0] == 'M') && (content[1] == 'I') && (content[2] == 'I')) {
        std::string cstr(content.cbegin(), content.cend());
        std::vector<std::string> parts = split(cstr, '\n');
        for (auto part : parts) {
            if (part.size() > 3) {
                std::vector<uint8_t> v = fromB64(part);
                conf.accept_certs.push_back(v);
            }
        }
    } else {
        conf.accept_certs.push_back(content);
    }
}

// Return the number of arguments consumed or error code

static int
parse_common(ToolConf& conf, int arg_idx, int argc, char *argv[])
{
    string_view arg(argv[arg_idx]);
    if ((arg == "--library") && ((arg_idx + 1) < argc)) {
        conf.library = argv[arg_idx + 1];
        return 2;
    } else if ((arg == "--server") && ((arg_idx + 2) < argc)) {
        ToolConf::ServerData sdata;
        sdata.ID = argv[arg_idx + 1];
        sdata.url = argv[arg_idx + 2];
        conf.servers.push_back(sdata);
        return 3;
    } else if ((arg == "--accept") && ((arg_idx + 1) < argc)) {
        load_certs(conf, argv[arg_idx + 1]);
        return 2;
    } else if ((arg == "--conf") && ((arg_idx + 1) < argc)) {
        conf.parse(argv[arg_idx + 1]);
        return 2;
    } else if ((arg == "--log-level") && ((arg_idx + 1) < argc)) {
        if (!str2level.contains(argv[arg_idx + 1])) return 0;
        libcdoc::setLogLevel(str2level[argv[arg_idx + 1]]);
        return 2;
    }
    return 0;
}

static int
parse_rcpt(ToolConf& conf, std::vector<libcdoc::RcptInfo>& rcpts, int& arg_idx, int argc, char *argv[])
{
    string_view arg(argv[arg_idx]);
    if ((arg != "--rcpt") || ((arg_idx + 1) >= argc)) return 0;

    vector<string> parts(split(argv[arg_idx + 1]));
    if (parts.size() < 3) return RESULT_USAGE;

    RcptInfo rcpt;
    rcpt.label = parts[0];
    string_view method(parts[1]);
    if (method == "cert") {
        // label:cert:FILENAME
        if (parts.size() != 3) return RESULT_USAGE;

        rcpt.type = RcptInfo::CERT;
        rcpt.cert = readAllBytes(parts[2]);
        rcpt.key_file_name = filesystem::path(parts[2]).filename().string();
    } else if (method == "pkey") {
        // label:pkey:PUBLIC_KEY
        if (parts.size() != 3) return RESULT_USAGE;

        rcpt.type = RcptInfo::PKEY;
        rcpt.secret = fromHex(parts[2]);
    } else if (method == "pfkey") {
        // label:pfkey:PUBLIC_KEY_FILE
        if (parts.size() != 3) return RESULT_USAGE;

        rcpt.type = RcptInfo::PKEY;
        rcpt.secret = readAllBytes(parts[2]);
        if (rcpt.secret.empty()) {
            // Occurs when the file does not exist. readAllBytes already output the error message.
            return 1;
        }

        filesystem::path key_file(parts[2]);
        rcpt.key_file_name = key_file.filename().string();
    } else if (method == "key" || method == "skey") {
        // label:skey:SECRET_KEY_HEX
        // For backward compatibility leave also "key" as the synonym for "skey" method.
        if (parts.size() != 3) return RESULT_USAGE;

        rcpt.type = RcptInfo::SKEY;
        rcpt.secret = fromHex(parts[2]);
        if (rcpt.secret.size() != 32) {
            LOG_ERROR("Symmetric key has to be exactly 32 bytes long");
            return RESULT_ERROR;
        }
    } else if (method == "pw") {
        // label:pw:PASSWORD
        if (parts.size() != 3) return RESULT_USAGE;

        rcpt.type = RcptInfo::PASSWORD;
        rcpt.secret.assign(parts[2].cbegin(), parts[2].cend());
    } else if (method == "p11sk" || method == "p11pk") {
        // label:p11sk:slot[:pin:key_id:key_label]
        rcpt.type = (method == "p11sk") ? RcptInfo::P11_SYMMETRIC : RcptInfo::P11_PKI;

        conf.libraryRequired = true;

        size_t last_char_idx;
        if (parts[2].starts_with("0x")) {
            rcpt.p11.slot = std::stoul(parts[2].substr(2), &last_char_idx, 16);
            last_char_idx += 2;
        } else {
            rcpt.p11.slot = std::stoul(parts[2], &last_char_idx);
        }
        if (last_char_idx < parts[2].size()) {
            LOG_ERROR("Slot is not a number");
            return RESULT_USAGE;
        }

        if (parts.size() > 3) {
            rcpt.secret.assign(parts[3].cbegin(), parts[3].cend());
            if (parts.size() > 4) {
                if (!parts[4].empty()) rcpt.p11.key_id = fromHex(parts[4]);
                if (parts.size() > 5)
                    rcpt.p11.key_label = parts[5];
            }
        }

#ifndef NDEBUG
        // For debugging
        LOG_DBG("Method: {}", method);
        LOG_DBG("Slot: {}", rcpt.p11.slot);
        if (!rcpt.secret.empty()) {
            string str(rcpt.secret.cbegin(), rcpt.secret.cend());
            LOG_TRACE("Pin: {}", str);
        }
        if (!rcpt.p11.key_id.empty())
            LOG_DBG("Key ID: {}", toHex(rcpt.p11.key_id));
        if (!rcpt.p11.key_label.empty())
            LOG_DBG("Key label: {}", rcpt.p11.key_label);
#endif
    } else if (method == "ncrypt") {
        // label:ncrypt:key_label[:pin]
        rcpt.type = RcptInfo::NCRYPT;

        if (parts.size() > 2) {
            rcpt.p11.key_label = parts[2];
            if (parts.size() > 3) {
                rcpt.secret.assign(parts[3].cbegin(), parts[3].cend());
            }
        }

#ifndef NDEBUG
        // For debugging
        cout << "Method: " << method << endl;
        cout << "Slot: " << rcpt.p11.slot << endl;
        if (!rcpt.secret.empty())
            cout << "Pin: " << string(rcpt.secret.cbegin(), rcpt.secret.cend()) << endl;
        if (!rcpt.p11.key_id.empty())
            cout << "Key ID: " << toHex(rcpt.p11.key_id) << endl;
        if (!rcpt.p11.key_label.empty())
            cout << "Key label: " << rcpt.p11.key_label << endl;
#endif
    } else if (method == "share") {
        // label:share:RECIPIENT_ID
        if (parts.size() != 3) return RESULT_USAGE;

        rcpt.type = RcptInfo::SHARE;
        rcpt.id = parts[2];
    } else {
        LOG_ERROR("Unknown method: {}", method);
        return RESULT_USAGE;
    }
    rcpts.push_back(std::move(rcpt));
    return 2;
}

//
// cdoc-tool encrypt --rcpt RECIPIENT [--rcpt...] --out OUTPUTFILE FILE [FILE...]
// Where RECIPIENT has a format:
//   label:cert:CERTIFICATE_HEX
//	 label:key:SECRET_KEY_HEX
//   label:pw:PASSWORD
//	 label:p11sk:SLOT:[PIN]:[ID]:[LABEL]
//	 label:p11pk:SLOT:[PIN]:[ID]:[LABEL]
//

static int ParseAndEncrypt(int argc, char *argv[])
{
    LOG_INFO("Encrypting");

    ToolConf conf;
    std::vector<libcdoc::RcptInfo> rcpts;

    //
    // Parse all arguments into ToolConf structure
    //
    int arg_idx = 0;
    while (arg_idx < argc) {
        int result = parse_common(conf, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;
        result = parse_rcpt(conf, rcpts, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;

        string_view arg(argv[arg_idx]);
        if (arg == "--out" && ((arg_idx + 1) < argc)) {
            conf.out = argv[arg_idx + 1];
            arg_idx += 1;
        } else if (arg == "-v1") {
            conf.cdocVersion = 1;
        } else if (arg == "--genlabel") {
            conf.gen_label = true;
        } else if (arg[0] == '-') {
            LOG_ERROR("Unknown argument: {}", arg);
            return 2;
        } else {
            conf.input_files.push_back(argv[arg_idx]);
        }
        arg_idx += 1;
    }

    // Validate input parameters
    if (rcpts.empty()) {
        LOG_ERROR("No recipients");
        return RESULT_USAGE;
    }
    if (!conf.gen_label) {
        // If labels must not be generated then is there any Recipient without provided label?
        auto rcpt_wo_label{ find_if(rcpts.cbegin(), rcpts.cend(), [](const libcdoc::RcptInfo &rcpt) -> bool {return rcpt.label.empty();}) };
        if (rcpt_wo_label != rcpts.cend()) {
            if (rcpts.size() > 1) {
                LOG_ERROR("Not all Recipients have label");
            } else {
                LOG_ERROR("Label not provided");
            }
            return 2;
        }
    }

    if (conf.input_files.empty()) {
        LOG_ERROR("No files specified");
        return 2;
    }
    if (conf.out.empty()) {
        LOG_ERROR("No output specified");
        return 2;
    }

    if (conf.libraryRequired && conf.library.empty()) {
        LOG_ERROR("Cryptographic library is required");
        return 2;
    }

    // CDOC1 is supported only for encryption with certificate.
    if (conf.cdocVersion == 1) {
        auto rcpt_type_non_cert{ find_if(rcpts.cbegin(), rcpts.cend(), [](const libcdoc::RcptInfo &rcpt) -> bool {return rcpt.type != RcptInfo::CERT;}) };
        if (rcpt_type_non_cert != rcpts.cend()) {
            LOG_ERROR("CDOC version 1 container can be used for encryption with certificate only.");
            return 1;
        }
    }

    CDocCipher cipher;
    return cipher.Encrypt(conf, rcpts);
}

struct LockData {
    string lock_label;
    int lock_idx = -1;
    long slot = -1;
    vector<uint8_t> key_id;
    string key_label;
    vector<uint8_t> secret;

    int validate(ToolConf& conf) {
        if (lock_label.empty() && (lock_idx == -1) && (slot < 0)) {
            LOG_ERROR("No label nor index was provided");
            return RESULT_USAGE;
        }
        if ((slot >= 0) && conf.library.empty()) {
            LOG_ERROR("Cryptographic library is required");
            return RESULT_USAGE;
        }
        return RESULT_OK;
    }
};

static int
parse_key_data(LockData& ldata, const int& arg_idx, int argc, char *argv[])
{
    string_view arg(argv[arg_idx]);
    if ((arg == "--label" || arg == "--label_idx") && (arg_idx + 1) < argc) {
        // Make sure the label or label index is provided only once.
        if (!ldata.lock_label.empty() || ldata.lock_idx != -1) {
            LOG_ERROR("The label or label's index was already provided");
            return RESULT_USAGE;
        }
        if (arg == "--label_idx") {
            size_t last_char_idx;
            string str(argv[arg_idx + 1]);
            ldata.lock_idx = std::stol(str, &last_char_idx);
            if (last_char_idx < str.size()) {
                LOG_ERROR("Label index is not a number");
                return RESULT_USAGE;
            }
        } else {
            ldata.lock_label = argv[arg_idx + 1];
        }
        return 2;
    } else if (arg == "--password" || arg == "--pin") {
        if ((arg_idx + 1) >= argc) return RESULT_USAGE;

        string_view s(argv[arg_idx + 1]);
        ldata.secret.assign(s.cbegin(), s.cend());
        return 2;
    } else if (arg == "--secret") {
        if ((arg_idx + 1) >= argc) return RESULT_USAGE;
        ldata.secret = fromHex(argv[arg_idx + 1]);
        return 2;
    } else if (arg == "--pkey") {
        if ((arg_idx + 1) >= argc) return RESULT_USAGE;
        ldata.secret = fromHex(argv[arg_idx + 1]);
        return 2;
    } else if (arg == "--pfkey") {
        if ((arg_idx + 1) >= argc) return RESULT_USAGE;
        ldata.secret = readAllBytes(argv[arg_idx + 1]);
        return 2;
    } else if (arg == "--slot") {
        if ((arg_idx + 1) >= argc) return RESULT_USAGE;

        string str(argv[arg_idx + 1]);
        size_t last_char_idx;
        if (str.starts_with("0x")) {
            ldata.slot = std::stol(str.substr(2), &last_char_idx, 16);
            last_char_idx += 2;
        } else {
            ldata.slot = std::stol(str, &last_char_idx);
        }
        if (last_char_idx < str.size()) {
            LOG_ERROR("Slot is not a number");
            return 2;
        }
        return 2;
    } else if (arg == "--key-id") {
        if ((arg_idx + 1) >= argc) return RESULT_USAGE;
        string_view s(argv[arg_idx + 1]);
        ldata.key_id.assign(s.cbegin(), s.cend());
        return 2;
    } else if (arg == "--key-label") {
        if ((arg_idx + 1) >= argc) return RESULT_USAGE;
        ldata.key_label = argv[arg_idx + 1];
        return 2;
    }
    return 0;
}

static std::string
inputSecret(std::string_view text)
{
    cout << text;
#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
#else
    termios o {};
    tcgetattr(STDIN_FILENO, &o);
    termios n = o;
    n.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &n);
#endif
    string result;
    getline(std::cin, result);
#ifdef _WIN32
    SetConsoleMode(hStdin, mode);
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &o);
    cout << endl;
#endif
    return result;
}

//
// cdoc-tool decrypt ARGUMENTS FILE [OUTPU_DIR]
//   --label LABEL   CDoc container lock label
//   --slot SLOT     PKCS11 slot number
//   --secret|password|pin SECRET    Secret phrase (either lock password or PKCS11 pin)
//   --key-id        PKCS11 key id
//   --key-label     PKCS11 key label
//   --library       full path to cryptographic library to be used (needed for decryption with PKCS11)

static int ParseAndDecrypt(int argc, char *argv[])
{
    ToolConf conf;

    LockData ldata;

    int arg_idx = 0;
    while (arg_idx < argc) {
        int result = parse_common(conf, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;
        result = parse_key_data(ldata, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;

        if (argv[arg_idx][0] != '-') {
            if (conf.input_files.empty()) {
                conf.input_files.push_back(argv[arg_idx]);
            } else {
                conf.out = argv[arg_idx];
            }
            arg_idx += 1;
        } else {
            return RESULT_USAGE;
        }
    }

    // Validating the input parameters
    int result = ldata.validate(conf);
    if (result != RESULT_OK) return result;

    if (conf.input_files.empty()) {
        LOG_ERROR("No file to decrypt");
        return RESULT_USAGE;
    }

    // If output directory was not specified, use current directory
    if (conf.out.empty()) {
        conf.out = ".";
    }

    // Ask secret if not provided
    if (ldata.secret[0] == '?') {
        std::string secret = inputSecret("Enter password: ");
        ldata.secret.assign(secret.cbegin(), secret.cend());
    }

    CDocCipher cipher;
    RcptInfo rcpt {.type=RcptInfo::LOCK, .label=ldata.lock_label, .secret=ldata.secret, .p11={ldata.slot, ldata.key_id, ldata.key_label}, .lock_idx=ldata.lock_idx - 1};
    return cipher.Decrypt(conf, rcpt);
}

static int ParseAndReEncrypt(int argc, char *argv[])
{
    ToolConf conf;
    std::vector<libcdoc::RcptInfo> rcpts;
    LockData ldata;

    int arg_idx = 0;
    while (arg_idx < argc) {
        int result = parse_common(conf, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;
        result = parse_key_data(ldata, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;
        result = parse_rcpt(conf, rcpts, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;

        string_view arg(argv[arg_idx]);
        if (arg == "--out" && ((arg_idx + 1) < argc)) {
            conf.out = argv[arg_idx + 1];
            arg_idx += 1;
        } else if (arg == "-v1") {
            conf.cdocVersion = 1;
        } else if (arg == "--genlabel") {
            conf.gen_label = true;
        } else if (argv[arg_idx][0] != '-') {
            conf.input_files.push_back(argv[arg_idx]);
        } else {
            LOG_ERROR("Unknown argument: {}", arg);
            return RESULT_USAGE;
        }
        arg_idx += 1;
    }

    // Validating the input parameters
    int result = ldata.validate(conf);
    if (result != RESULT_OK) return result;

    if (rcpts.empty()) {
        LOG_ERROR("No recipients");
        return RESULT_USAGE;
    }

    if (!conf.gen_label) {
        // If labels must not be generated then is there any Recipient without provided label?
        auto rcpt_wo_label{ find_if(rcpts.cbegin(), rcpts.cend(), [](const libcdoc::RcptInfo &rcpt) -> bool {return rcpt.label.empty();}) };
        if (rcpt_wo_label != rcpts.cend()) {
            if (rcpts.size() > 1) {
                LOG_ERROR("Not all Recipients have label");
            } else {
                LOG_ERROR("Label not provided");
            }
            return RESULT_USAGE;
        }
    }

    if (conf.out.empty()) {
        LOG_ERROR("No output specified");
        return RESULT_USAGE;
    }

    if (conf.libraryRequired && conf.library.empty()) {
        LOG_ERROR("Cryptographic library is required");
        return RESULT_USAGE;
    }

    // CDOC1 is supported only for encryption with certificate.
    if (conf.cdocVersion == 1) {
        auto rcpt_type_non_cert{ find_if(rcpts.cbegin(), rcpts.cend(), [](const libcdoc::RcptInfo &rcpt) -> bool {return rcpt.type != RcptInfo::CERT;}) };
        if (rcpt_type_non_cert != rcpts.cend()) {
            LOG_ERROR("CDOC version 1 container can be used for encryption with certificate only.");
            return 1;
        }
    }

    CDocCipher cipher;
    RcptInfo rcpt {.type=RcptInfo::LOCK, .label=ldata.lock_label, .secret=ldata.secret, .p11={ldata.slot, ldata.key_id, ldata.key_label}, .lock_idx=ldata.lock_idx};
    if (ldata.lock_idx != -1) {
        return cipher.ReEncrypt(conf, rcpt, rcpts);
    }
    return true;
}

//
// cdoc-tool locks FILE
//

static int ParseAndGetLocks(int argc, char *argv[])
{
    ToolConf conf;
    std::string container;

    //
    // Parse all arguments into ToolConf structure
    //
    int arg_idx = 0;
    while (arg_idx < argc) {
        int result = parse_common(conf, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;
        if (argv[arg_idx][0] == '-') {
            return RESULT_USAGE;
        } else {
            if (!container.empty()) return RESULT_USAGE;
            container = argv[arg_idx];
        }
        arg_idx += 1;
    }
    if (container.empty()) return RESULT_USAGE;

    CDocCipher cipher;
    cipher.Locks(container.c_str());
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(cerr);
        return 1;
    }

    libcdoc::setLogLevel(LEVEL_TRACE);

    string_view command(argv[1]);

    CDocCipher cipher;
    int retVal = 2;     // Output the help by default.
    if (command == "encrypt") {
        retVal = ParseAndEncrypt(argc - 2, argv + 2);
    } else if (command == "decrypt") {
        retVal = ParseAndDecrypt(argc - 2, argv + 2);
    } else if (command == "re-encrypt") {
        retVal = ParseAndReEncrypt(argc - 2, argv + 2);
    } else if (command == "locks") {
        retVal = ParseAndGetLocks(argc - 2, argv + 2);
    } else {
        cerr << "Invalid command: " << command << endl;
    }

    if (retVal == 2) {
        // We print usage information only in case the parse-function returned 2. Value 1 indicates other error.
        print_usage(cout);
    }

    setLogger(nullptr);
    return retVal;
}
