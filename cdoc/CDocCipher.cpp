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

#include "CDocCipher.h"
#include "CDocReader.h"
#include "Io.h"
#include "Lock.h"
#include "NetworkBackend.h"
#include "PKCS11Backend.h"
#include "Recipient.h"
#include "Utils.h"
#include "utils/memory.h"
#ifdef _WIN32
#include "WinBackend.h"
#endif

#include <sstream>
#include <map>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

using namespace std;
using namespace libcdoc;

static string GenerateRandomSequence();

struct ToolPKCS11 : public libcdoc::PKCS11Backend {
    const std::map<unsigned int, libcdoc::RcptInfo>& rcpts;

    ToolPKCS11(const std::string& library, const std::map<unsigned int, libcdoc::RcptInfo>& vec) : libcdoc::PKCS11Backend(library), rcpts(vec) {}

    libcdoc::result_t connectToKey(int idx, bool priv) override final {
        if (!rcpts.contains(idx)) return libcdoc::CRYPTO_ERROR;
        libcdoc::RcptInfo rcpt = rcpts.at(idx);
        if (!priv) {
            return useSecretKey(rcpt.p11.slot, rcpt.secret, rcpt.p11.key_id, rcpt.p11.key_label);
        } else {
            return usePrivateKey(rcpt.p11.slot, rcpt.secret, rcpt.p11.key_id, rcpt.p11.key_label);
        }
    }
};

#ifdef _WIN32
struct ToolWin : public libcdoc::WinBackend {
    const std::map<unsigned int, libcdoc::RcptInfo>& rcpts;

    ToolWin(const std::string& provider, const std::map<unsigned int, libcdoc::RcptInfo>& vec) : libcdoc::WinBackend(provider), rcpts(vec) {}

    result_t connectToKey(int idx, bool priv) {
        if (!rcpts.contains(idx)) return libcdoc::CRYPTO_ERROR;
        const libcdoc::RcptInfo &rcpt = rcpts.at(idx);
        return useKey(rcpt.p11.key_label, std::string(rcpt.secret.cbegin(), rcpt.secret.cend()));
    }
};
#endif

struct ToolCrypto : public libcdoc::CryptoBackend {
    const std::map<unsigned int, libcdoc::RcptInfo>& rcpts;
    std::unique_ptr<libcdoc::PKCS11Backend> p11;
#ifdef _WIN32
    std::unique_ptr<libcdoc::WinBackend> ncrypt;
#endif

    ToolCrypto(const std::map<unsigned int, libcdoc::RcptInfo>& recipients) : rcpts(recipients) {
    }

    bool connectLibrary(const std::string& library) {
        p11 = std::make_unique<ToolPKCS11>(library, rcpts);
        return true;
    }

    bool connectNCrypt() {
#ifdef _WIN32
        ncrypt = std::make_unique<ToolWin>("", rcpts);
        return true;
#else
        return false;
#endif
    }

    libcdoc::result_t decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t> &data, bool oaep, unsigned int idx) override final {
        if (p11) return p11->decryptRSA(dst, data, oaep, idx);
        if (!rcpts.contains(idx)) return libcdoc::CRYPTO_ERROR;
        const libcdoc::RcptInfo &rcpt = rcpts.at(idx);
        if (rcpt.secret.empty()) return libcdoc::CRYPTO_ERROR;
        const uint8_t *p = rcpt.secret.data();

        auto key = make_unique_ptr<EVP_PKEY_free>(d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, rcpt.secret.size()));
        if (!key) return libcdoc::CRYPTO_ERROR;

        auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new(key.get(), nullptr));
        if (!ctx) return libcdoc::CRYPTO_ERROR;

        int result = EVP_PKEY_decrypt_init(ctx.get());
        if (result < 0) return libcdoc::CRYPTO_ERROR;
        if (oaep) {
            if ((EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) < 0) ||
                (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) < 0) ||
                (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) < 0))
                return libcdoc::CRYPTO_ERROR;
        }

        size_t outlen;
        result = EVP_PKEY_decrypt(ctx.get(), NULL, &outlen, data.data(), data.size());
        if (result < 0) return libcdoc::CRYPTO_ERROR;
        dst.resize(outlen);
        result = EVP_PKEY_decrypt(ctx.get(), dst.data(), &outlen, data.data(), data.size());
        if (result < 0) return libcdoc::CRYPTO_ERROR;
        dst.resize(outlen);

        return libcdoc::OK;
    }

    libcdoc::result_t deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx) override final {
        if (!rcpts.contains(idx)) return libcdoc::CRYPTO_ERROR;
        const libcdoc::RcptInfo &rcpt = rcpts.at(idx);
        if (rcpt.secret.empty()) return libcdoc::CRYPTO_ERROR;
        const uint8_t *p = rcpt.secret.data();

        auto key = make_unique_ptr<EVP_PKEY_free>(d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, rcpt.secret.size()));
        if (!key) return libcdoc::CRYPTO_ERROR;

        auto ctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new(key.get(), nullptr));
        if (!ctx) return libcdoc::CRYPTO_ERROR;

        EVP_PKEY *params = nullptr;
        if ((EVP_PKEY_paramgen_init(ctx.get()) < 0) ||
            (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_secp384r1) < 0) ||
            (EVP_PKEY_CTX_set_ec_param_enc(ctx.get(), OPENSSL_EC_NAMED_CURVE) < 0) ||
            (EVP_PKEY_paramgen(ctx.get(), &params) < 0))
            return libcdoc::CRYPTO_ERROR;

        p = public_key.data();
        auto pubkey = make_unique_ptr<EVP_PKEY_free>(d2i_PublicKey(EVP_PKEY_EC, &params, &p, long(public_key.size())));
        if (!pubkey) return libcdoc::CRYPTO_ERROR;

        size_t dlen;
        if ((EVP_PKEY_derive_init(ctx.get()) < 0) ||
            (EVP_PKEY_derive_set_peer(ctx.get(), pubkey.get()) < 0) ||
            (EVP_PKEY_derive(ctx.get(), nullptr, &dlen) < 0))
            return libcdoc::CRYPTO_ERROR;

        dst.resize(dlen);
        if (EVP_PKEY_derive(ctx.get(), dst.data(), &dlen) < 0)
            return libcdoc::CRYPTO_ERROR;
        dst.resize(dlen);

        return libcdoc::OK;
    }

    libcdoc::result_t deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::string &digest,
                        const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo, unsigned int idx) override final {
        if (p11) return p11->deriveConcatKDF(dst, publicKey, digest, algorithmID, partyUInfo, partyVInfo, idx);
        return libcdoc::CryptoBackend::deriveConcatKDF(dst, publicKey, digest, algorithmID, partyUInfo, partyVInfo, idx);
    }

    libcdoc::result_t deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::vector<uint8_t> &salt, unsigned int idx) override final {
        if (p11) return p11->deriveHMACExtract(dst, publicKey, salt, idx);
        return libcdoc::CryptoBackend::deriveHMACExtract(dst, publicKey, salt, idx);
    }

    libcdoc::result_t extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx) override {
        if (p11) return p11->extractHKDF(kek, salt, pw_salt, kdf_iter, idx);
        return libcdoc::CryptoBackend::extractHKDF(kek, salt, pw_salt, kdf_iter, idx);
    }

    libcdoc::result_t getSecret(std::vector<uint8_t>& secret, unsigned int idx) override final {
        if (!rcpts.contains(idx)) return libcdoc::CRYPTO_ERROR;
        const libcdoc::RcptInfo &rcpt = rcpts.at(idx);
        secret = rcpt.secret;
        return secret.empty() ? INVALID_PARAMS : libcdoc::OK;
    }

    libcdoc::result_t sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, int idx) {
        if (p11) return p11->sign(dst, algorithm, digest, idx);
        return libcdoc::NOT_IMPLEMENTED;
    }
};

struct ToolNetwork : public libcdoc::NetworkBackend {
    ToolCrypto *crypto;

    int rcpt_idx = -1;

    std::vector<std::vector<uint8_t>> certs;

    explicit ToolNetwork(ToolCrypto *_crypto) : crypto(_crypto) {
    }

    libcdoc::result_t getClientTLSCertificate(std::vector<uint8_t>& dst) override final {
        if (!crypto->rcpts.contains(rcpt_idx)) return libcdoc::CRYPTO_ERROR;
        const RcptInfo& rcpt = crypto->rcpts.at(rcpt_idx);
        bool rsa = false;
        return crypto->p11->getCertificate(dst, rsa, rcpt.p11.slot, rcpt.secret, rcpt.p11.key_id, rcpt.p11.key_label);
    }

    libcdoc::result_t getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst) override final {
        dst = certs;
        return libcdoc::OK;
    }

    libcdoc::result_t signTLS(std::vector<uint8_t>& dst, libcdoc::CryptoBackend::HashAlgorithm algorithm, const std::vector<uint8_t> &digest) override final {
        if (!crypto->rcpts.contains(rcpt_idx)) return libcdoc::CRYPTO_ERROR;
        return crypto->p11->sign(dst, algorithm, digest, rcpt_idx);
    }

};

int CDocCipher::writer_push(CDocWriter& writer, const vector<Recipient>& rcpts, const vector<string>& files)
{
    for (const libcdoc::Recipient& rcpt : rcpts) {
        int64_t result = writer.addRecipient(rcpt);
        if (result != libcdoc::OK) return result;
    }
    int64_t result = writer.beginEncryption();
    if (result != libcdoc::OK) return result;
    for (const std::string& file : files) {
        std::filesystem::path path(file);
        if (!std::filesystem::exists(path)) {
            LOG_ERROR("File does not exist: {}", file);
            return 1;
        }
        size_t size = std::filesystem::file_size(path);
        int result = writer.addFile(file, size);
        if (result != libcdoc::OK) return result;
        libcdoc::IStreamSource src(file);
        while (!src.isEof()) {
            uint8_t b[256];
            int64_t len = src.read(b, 256);
            if (len < 0) {
                LOG_ERROR("IO error: {}", file);
                return 1;
            }
            int64_t nbytes = writer.writeData(b, len);
            if (nbytes < 0) return (int) nbytes;
        }
    }
    return writer.finishEncryption();
}

#define PUSH true

static bool
fill_recipients_from_rcpt_info(ToolConf& conf, ToolCrypto& crypto, std::vector<libcdoc::Recipient>& rcpts, std::map<unsigned int, libcdoc::RcptInfo>& crypto_rcpts, const std::vector<libcdoc::RcptInfo>& recipients)
{
    int idx = 0;
    for (const auto& rcpt : recipients) {
        // Generate the labels if needed
        string label;
        if (!conf.gen_label) label = rcpt.label;

        crypto_rcpts[idx++] = rcpt;

        Recipient key;
        if (rcpt.type == RcptInfo::Type::CERT) {
            if (!conf.servers.empty()) {
                key = libcdoc::Recipient::makeServer(label, rcpt.cert, conf.servers[0].ID);
            } else {
                key = libcdoc::Recipient::makeCertificate(label, rcpt.cert);
            }
        } else if (rcpt.type == RcptInfo::Type::SKEY) {
            key = libcdoc::Recipient::makeSymmetric(label, 0);
            if (conf.gen_label)
                key.setLabelValue(CDoc2::Label::LABEL, rcpt.label);
            LOG_DBG("Creating symmetric key:");
        } else if (rcpt.type == RcptInfo::Type::PKEY) {
            if (!conf.servers.empty()) {
                key = libcdoc::Recipient::makeServer(label, rcpt.secret, libcdoc::PKType::ECC, conf.servers[0].ID);
            } else {
                const uint8_t *der = rcpt.secret.data();
                EVP_PKEY *pkey = d2i_PUBKEY(nullptr, &der, rcpt.secret.size());
                int id = EVP_PKEY_get_id(pkey);
                std::vector<uint8_t> d(i2d_PublicKey(pkey, nullptr), 0);
                uint8_t *p = d.data();
                i2d_PublicKey(pkey, &p);
                if (id == EVP_PKEY_EC) {
                    key = libcdoc::Recipient::makePublicKey(label, rcpt.secret, libcdoc::PKType::ECC);
                } else if (id == EVP_PKEY_RSA) {
                    key = libcdoc::Recipient::makePublicKey(label, rcpt.secret, libcdoc::PKType::RSA);
                }
            }
            LOG_DBG("Creating public key:");
        } else if (rcpt.type == RcptInfo::Type::P11_SYMMETRIC) {
            key = libcdoc::Recipient::makeSymmetric(label, 0);
            if (conf.gen_label)
                key.setLabelValue(CDoc2::Label::LABEL, rcpt.label);
        } else if (rcpt.type == RcptInfo::Type::P11_PKI) {
            std::vector<uint8_t> val;
            bool rsa;
            ToolPKCS11* p11 = dynamic_cast<ToolPKCS11*>(crypto.p11.get());
            int result = p11->getPublicKey(val, rsa, rcpt.p11.slot, rcpt.secret, rcpt.p11.key_id, rcpt.p11.key_label);
            if (result != libcdoc::OK) {
                LOG_ERROR("No such public key: {}", rcpt.p11.key_label);
                continue;
            }
            LOG_DBG("Public key ({}): {}", rsa ? "rsa" : "ecc", toHex(val));
            if (!conf.servers.empty()) {
                key = libcdoc::Recipient::makeServer(label, val, rsa ? libcdoc::PKType::RSA : libcdoc::PKType::ECC, conf.servers[0].ID);
            } else {
                key = libcdoc::Recipient::makePublicKey(label, val, rsa ? libcdoc::PKType::RSA : libcdoc::PKType::ECC);
            }
        } else if (rcpt.type == RcptInfo::Type::PASSWORD) {
            LOG_DBG("Creating password key:");
            key = libcdoc::Recipient::makeSymmetric(label, 65535);
            if (conf.gen_label)
                key.setLabelValue(CDoc2::Label::LABEL, rcpt.label);
        } else if (rcpt.type == RcptInfo::Type::SHARE) {
            LOG_DBG("Creating keyshare recipient:");
            key = libcdoc::Recipient::makeShare(label, conf.servers[0].ID, "PNOEE-" + rcpt.id);
        }

        rcpts.push_back(std::move(key));
    }
    return true;
}

int CDocCipher::Encrypt(ToolConf& conf, std::vector<libcdoc::RcptInfo>& recipients)
{
    std::map<unsigned int, libcdoc::RcptInfo> crypto_rcpts;
    ToolCrypto crypto(crypto_rcpts);
    ToolNetwork network(&crypto);
    network.certs = std::move(conf.accept_certs);

    if (!conf.library.empty()) {
        crypto.connectLibrary(conf.library);
    }
    for (const auto& rcpt : recipients) {
        if (rcpt.type == RcptInfo::NCRYPT) {
            crypto.connectNCrypt();
        }
    }

    vector<libcdoc::Recipient> rcpts;
    fill_recipients_from_rcpt_info(conf, crypto, rcpts, crypto_rcpts, recipients);

    if (rcpts.empty()) {
        LOG_ERROR("No key for encryption was found");
        return 1;
    }

    unique_ptr<CDocWriter> writer(CDocWriter::createWriter(conf.cdocVersion, conf.out, &conf, &crypto, &network));

    int result;
    if (PUSH) {
        result = writer_push(*writer, rcpts, conf.input_files);
    } else {
        libcdoc::FileListSource src({}, conf.input_files);
        result = writer->encrypt(src, rcpts);
    }
    if (result < 0) {
        LOG_ERROR("Encryption failed: error {}", result);
        cerr << writer->getLastErrorStr() << endl;
    } else {
        LOG_INFO("File encrypted successfully: {}", conf.out);
    }

    return result;
}

int CDocCipher::Decrypt(ToolConf& conf, const RcptInfo& recipient)
{
    std::map<unsigned int, libcdoc::RcptInfo> rcpts;
    ToolCrypto crypto(rcpts);
    ToolNetwork network(&crypto);
    network.certs = std::move(conf.accept_certs);

    if (!conf.library.empty())
        crypto.connectLibrary(conf.library);

    unique_ptr<CDocReader> rdr(CDocReader::createReader(conf.input_files[0], &conf, &crypto, &network));
    if (!rdr) {
        LOG_ERROR("Cannot create reader (invalid file?)");
        return 1;
    }
    LOG_DBG("Reader created");

    // Find lock by label/index/certificate
    int lock_idx = -1;
    const vector<Lock>& locks = rdr->getLocks();
    if (!recipient.label.empty()) {
        LOG_DBG("Looking for lock by label");
        for (unsigned int i = 0; i < locks.size(); i++) {
            if (locks[i].label == recipient.label) {
                lock_idx = i;
                break;
            }
        }
    } else if (recipient.lock_idx >= 0) {
        if (recipient.lock_idx >= locks.size()) {
            LOG_ERROR("Label index is out of range");
            return 1;
        }
        lock_idx = recipient.lock_idx;
    } else if (crypto.p11) {
        bool isRsa;
        vector<uint8_t> cert_bytes;
        ToolPKCS11* p11 = dynamic_cast<ToolPKCS11*>(crypto.p11.get());
        int64_t result = p11->getCertificate(cert_bytes, isRsa, (int) recipient.p11.slot, recipient.secret, recipient.p11.key_id, recipient.p11.key_label);
        if (result != libcdoc::OK) {
            LOG_ERROR("Certificate reading from SC card failed. Key label: {}", recipient.p11.key_label);
            return 1;
        }
        LOG_DBG("Got certificate from P11 module");
        result = rdr->getLockForCert(cert_bytes);
        if (result < 0) {
            LOG_ERROR("No lock for certificate {}", recipient.p11.key_label);
            return 1;
        }
        lock_idx = (int) result;
    }
    if (lock_idx < 0) {
        LOG_ERROR("Lock not found: {}", recipient.label);
        return 1;
    }
    LOG_INFO("Found matching lock: {}", recipient.label);
    rcpts[lock_idx] = recipient;

    network.rcpt_idx = lock_idx;
    return Decrypt(rdr, lock_idx, conf.out);
}

int CDocCipher::Decrypt(const unique_ptr<CDocReader>& rdr, unsigned int lock_idx, const string& base_pathname)
{
    vector<uint8_t> fmk;
    LOG_DBG("Fetching FMK, idx=", lock_idx);
    int result = rdr->getFMK(fmk, lock_idx);
    LOG_DBG("Got FMK");
    if (result != libcdoc::OK) {
        LOG_ERROR("Error on extracting FMK: {} {}", result, rdr->getLastErrorStr());
        return 1;
    }
    filesystem::path base_path(base_pathname);

    /* Do pull */
    result = rdr->beginDecryption(fmk);
    if (result != libcdoc::OK) {
        LOG_ERROR("Error while decrypting files: {} {}", result, rdr->getLastErrorStr());
        return 1;
    }
    std::string name;
    int64_t size;
    result = rdr->nextFile(name, size);
    while (result == libcdoc::OK) {
        LOG_DBG("Got file: {} {}", name, size);
        filesystem::path fpath(name);
        if (fpath.is_absolute()) {
            LOG_WARN("File has absolute path, stripping");
            fpath = fpath.filename();
        } else if (fpath.has_parent_path()) {
            LOG_WARN("File has parent path, stripping");
            fpath = fpath.filename();
        }
        fpath = base_path / fpath;
        std::ofstream ofs(fpath, std::ios_base::binary);
        if (ofs.bad()) {
            LOG_ERROR("Cannot open file {} for writing", fpath.string());
            return 1;
        }
        int64_t n_copied = 0;
        while (n_copied < size) {
            uint8_t b[4096];
            int64_t n_to_read = min<int64_t>((size - n_copied), 4096);
            int64_t n_read = rdr->readData(b, n_to_read);
            if (n_read < 0) {
                LOG_ERROR("Cannot read {} from container: {}", name, rdr->getLastErrorStr());
                return 1;
            } else if (n_read == 0) {
                break;
            }
            ofs.write((const char *) b, n_read);
            if (ofs.bad()) {
                LOG_ERROR("Cannot write to  {}", fpath.string());
                return 1;
            }
            n_copied += n_read;
        }
        if (n_copied != size) {
            LOG_ERROR("Cannot extract full {}: {}", name, rdr->getLastErrorStr());
            return 1;
        }        
        result = rdr->nextFile(name, size);
    }
    if (result != libcdoc::END_OF_STREAM) {
        LOG_ERROR("Error while decrypting files: {} {}", result, rdr->getLastErrorStr());
        return 1;
    }
    result = rdr->finishDecryption();
    if (result != libcdoc::OK) {
        LOG_ERROR("Error finalizing decryption: ({}) {}", result, rdr->getLastErrorStr());
        return 1;
    }
    /*
    FileListConsumer fileWriter(base_pathname);
    result = rdr->decrypt(fmk, &fileWriter);
    if (result != libcdoc::OK) {
        LOG_ERROR("Error on decrypting files: {} {}", result, rdr->getLastErrorStr());
        return 1;
    }
    */
    LOG_INFO("File decrypted successfully");
    return 0;
}

int
CDocCipher::ReEncrypt(ToolConf& conf, const RcptInfo& lock_info, std::vector<libcdoc::RcptInfo>& recipients)
{
    // Decryption part
    std::map<unsigned int, libcdoc::RcptInfo> dec_info;
    ToolCrypto crypto(dec_info);
    ToolNetwork network(&crypto);
    network.certs = std::move(conf.accept_certs);

    if (!conf.library.empty()) {
        crypto.connectLibrary(conf.library);
    }

    unique_ptr<CDocReader> rdr(CDocReader::createReader(conf.input_files[0], &conf, &crypto, &network));
    if (!rdr) {
        LOG_ERROR("Cannot create reader (invalid file?)");
        return 1;
    }
    LOG_DBG("Reader created");

    const vector<Lock>& locks = rdr->getLocks();

    int lock_idx = -1;
    if (!lock_info.label.empty()) {
        for (unsigned int i = 0; i < locks.size(); i++) {
            if (locks[i].label == lock_info.label) {
                lock_idx = i;
                break;
            }
        }
    } else if (lock_info.lock_idx >= 0) {
        if (lock_info.lock_idx >= locks.size()) {
            LOG_ERROR("Label index is out of range");
            return 1;
        }
        lock_idx = lock_info.lock_idx;
    }
    if (lock_idx < 0) {
        LOG_ERROR("Lock not found: {}", lock_info.label);
        return 1;
    }

    dec_info[lock_idx] = lock_info;

    network.rcpt_idx = lock_idx;

    // Encryption part
    std::map<unsigned int, libcdoc::RcptInfo> crypto_rcpts;
    ToolCrypto enc_crypto(crypto_rcpts);
    ToolNetwork enc_network(&enc_crypto);
    enc_network.certs = std::move(conf.accept_certs);

    if (!conf.library.empty()) {
        enc_crypto.connectLibrary(conf.library);
    }
    for (const auto& rcpt : recipients) {
        if (rcpt.type == RcptInfo::NCRYPT) {
            enc_crypto.connectNCrypt();
            break;
        }
    }

    vector<libcdoc::Recipient> rcpts;
    fill_recipients_from_rcpt_info(conf, enc_crypto, rcpts, crypto_rcpts, recipients);

    if (rcpts.empty()) {
        LOG_ERROR("No key for encryption was found");
        return 1;
    }

    unique_ptr<CDocWriter> wrtr(CDocWriter::createWriter(conf.cdocVersion, conf.out, &conf, &enc_crypto, &enc_network));

    // Begin
    vector<uint8_t> fmk;
    LOG_DBG("Fetching FMK, idx=", lock_idx);
    int64_t result = rdr->getFMK(fmk, lock_idx);
    LOG_DBG("Got FMK");
    if (result != libcdoc::OK) {
        LOG_ERROR("Error on extracting FMK: {} {}", result, rdr->getLastErrorStr());
        return 1;
    }
    for (const libcdoc::Recipient& rcpt : rcpts) {
        int64_t result = wrtr->addRecipient(rcpt);
        if (result != libcdoc::OK) {
            LOG_ERROR("Error adding recipient: {} {}", result, wrtr->getLastErrorStr());
            return 1;
        }
    }

    result = rdr->beginDecryption(fmk);
    if (result != libcdoc::OK) {
        LOG_ERROR("Error while decrypting files: {} {}", result, rdr->getLastErrorStr());
        return 1;
    }
    result = wrtr->beginEncryption();
    if (result != libcdoc::OK) {
        LOG_ERROR("Error starting encryption: {} {}", result, wrtr->getLastErrorStr());
        return 1;
    }

    std::string name;
    int64_t size;
    result = rdr->nextFile(name, size);
    while (result == libcdoc::OK) {
        LOG_DBG("Got file: {} {}", name, size);
        result = wrtr->addFile(name, size);
        if (result != libcdoc::OK) {
            LOG_ERROR("Error adding file: {} {}", result, wrtr->getLastErrorStr());
            return 1;
        }
        int64_t n_copied = 0;
        while (n_copied < size) {
            uint8_t b[4096];
            int64_t n_to_read = min<int64_t>((size - n_copied), 4096);
            int64_t n_read = rdr->readData(b, n_to_read);
            if (n_read < 0) {
                LOG_ERROR("Cannot read {} from container: {}", name, rdr->getLastErrorStr());
                return 1;
            } else if (n_read == 0) {
                break;
            }
            int64_t nbytes = wrtr->writeData(b, n_read);
            if (nbytes < 0) {
                LOG_ERROR("Error writing data: {} {}", result, wrtr->getLastErrorStr());
                return 1;
            }
            n_copied += n_read;
        }
        if (n_copied != size) {
            LOG_ERROR("Cannot extract full {}: {}", name, rdr->getLastErrorStr());
            return 1;
        }        
        result = rdr->nextFile(name, size);
    }
    if (result != libcdoc::END_OF_STREAM) {
        LOG_ERROR("Error while decrypting files: {} {}", result, rdr->getLastErrorStr());
        return 1;
    }
    result = rdr->finishDecryption();
    if (result != libcdoc::OK) {
        LOG_ERROR("Error finalizing decryption: ({}) {}", result, rdr->getLastErrorStr());
        return 1;
    }
    result = wrtr->finishEncryption();
    if (result != libcdoc::OK) {
        LOG_ERROR("Error finalizing encryption: ({}) {}", result, wrtr->getLastErrorStr());
        return 1;
    }
    return 0;
}

void CDocCipher::Locks(const char* file) const
{
    unique_ptr<CDocReader> rdr(CDocReader::createReader(file, nullptr, nullptr, nullptr));
    if (!rdr) {
        LOG_ERROR("{} is not a valid CDoc file", file);
        return;
    }

    int lock_id = 1;
    for (const Lock& lock : rdr->getLocks()) {
        map<string, string> parsed_label(Lock::parseLabel(lock.label));
        if (parsed_label.empty()) {
            // Human-readable label
            cout << lock_id << ": " << lock.label << endl;
        } else {
            // Machine generated label
            // Find the longest field
            int maxFieldLength = 0;
            for (map<string, string>::const_reference pair : parsed_label) {
                if (pair.first.size() > maxFieldLength) {
                    maxFieldLength = static_cast<int>(pair.first.size());
                }
            }

            // Output the fields with their values
            cout << lock_id << ":" << lock.label << endl;
            for (map<string, string>::const_reference pair : parsed_label) {
                cout << "  " << setw(maxFieldLength + 1) << left << pair.first << ": " << pair.second << endl;
            }

            cout << endl;
        }

        lock_id++;
    }
}

static string GenerateRandomSequence()
{
    constexpr uint32_t upperbound = 'z' - '0' + 1;
    constexpr int MaxSequenceLength = 11;

    uint32_t rnd;
    uint8_t rndByte;
    ostringstream sequence;
    for (int cnt = 0; cnt < MaxSequenceLength;)
    {
        if (RAND_bytes(&rndByte, 1) < 1)
        {
            rnd = rand() % upperbound + '0';
        }
        else
        {
            rnd = rndByte % upperbound + '0';
        }

        // arc4random_uniform tends to be not available on all platforms.
        // rnd = arc4random_uniform(upperbound) + '0';

        if (isalnum(rnd))
        {
            sequence << static_cast<char>(rnd);
            cnt++;
        }
    }

    return sequence.str();
}
