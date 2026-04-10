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

#include "CDoc2Writer.h"

#include "Configuration.h"
#include "Crypto.h"
#include "CDoc2.h"
#include "NetworkBackend.h"
#include "Recipient.h"
#include "Tar.h"
#include "Utils.h"
#include "ZStream.h"

#include "header_generated.h"

#include <openssl/x509.h>

#define FAIL(m,r) return fail(m, r)

using namespace libcdoc;

CDoc2Writer::CDoc2Writer(libcdoc::DataConsumer *dst, bool take_ownership)
    : CDocWriter(2, dst, take_ownership)
{
}

CDoc2Writer::~CDoc2Writer() noexcept = default;

libcdoc::result_t
CDoc2Writer::writeHeader(const std::vector<libcdoc::Recipient> &recipients)
{
    if(recipients.empty())
        FAIL("No recipients specified", libcdoc::WRONG_ARGUMENTS);
    std::vector<uint8_t> rnd;
    if(auto rv = crypto->random(rnd, libcdoc::CDoc2::KEY_LEN); rv < 0)
        return rv;
    std::vector<uint8_t> fmk = libcdoc::Crypto::extract(rnd, {libcdoc::CDoc2::SALT.cbegin(), libcdoc::CDoc2::SALT.cend()});
    std::fill(rnd.begin(), rnd.end(), 0);
    LOG_TRACE_KEY("fmk: {}", fmk);

    std::vector<uint8_t> header;
    if(auto rv = buildHeader(header, recipients, fmk); rv < 0)
    {
        std::fill(fmk.begin(), fmk.end(), 0);
        return rv;
    }

    auto hhk = libcdoc::Crypto::expand(fmk, libcdoc::CDoc2::HMAC);
    auto cek = libcdoc::Crypto::expand(fmk, libcdoc::CDoc2::CEK);
    std::fill(fmk.begin(), fmk.end(), 0);
    LOG_TRACE_KEY("cek: {}", cek);
    LOG_TRACE_KEY("hhk: {}", hhk);
    std::vector<uint8_t> headerHMAC = libcdoc::Crypto::sign_hmac(hhk, header);
    std::fill(hhk.begin(), hhk.end(), 0);
    LOG_TRACE_KEY("hmac: {}", headerHMAC);

    uint32_t hs = uint32_t(header.size());
    // FIXME: not big/little endian friendly
    uint8_t header_len[] {uint8_t(hs >> 24), uint8_t((hs >> 16) & 0xff), uint8_t((hs >> 8) & 0xff), uint8_t(hs & 0xff)};

    dst->write((const uint8_t *) libcdoc::CDoc2::LABEL.data(), libcdoc::CDoc2::LABEL.size());
    dst->write((const uint8_t *) &header_len, 4);
    dst->write(header.data(), header.size());
    dst->write(headerHMAC.data(), headerHMAC.size());

    std::vector<uint8_t> nonce;
    crypto->random(nonce, libcdoc::CDoc2::NONCE_LEN);
    LOG_TRACE_KEY("nonce: {}", nonce);
    auto cipher = std::make_unique<EncryptionConsumer>(*dst, EVP_chacha20_poly1305(), Crypto::Key(std::move(cek), nonce));
    std::vector<uint8_t> aad(libcdoc::CDoc2::PAYLOAD.cbegin(), libcdoc::CDoc2::PAYLOAD.cend());
    aad.insert(aad.end(), header.cbegin(), header.cend());
    aad.insert(aad.end(), headerHMAC.cbegin(), headerHMAC.cend());
    if(auto rv = cipher->writeAAD(aad); rv < 0)
        return rv;

    auto *zcons = new ZConsumer(cipher.release(), true);
    tar = std::make_unique<TarConsumer>(zcons, true);
    return OK;
}

static flatbuffers::Offset<cdoc20::header::RecipientRecord>
createRSACapsule(flatbuffers::FlatBufferBuilder& builder, const libcdoc::Recipient& rcpt, const std::vector<uint8_t>& encrypted_kek, const std::vector<uint8_t>& xor_key)
{
    auto capsule = cdoc20::recipients::CreateRSAPublicKeyCapsule(builder,
                                                                 builder.CreateVector(rcpt.rcpt_key),
                                                                 builder.CreateVector(encrypted_kek));
    return cdoc20::header::CreateRecipientRecord(builder,
                                                        cdoc20::header::Capsule::recipients_RSAPublicKeyCapsule,
                                                        capsule.Union(),
                                                        builder.CreateString(rcpt.getLabel({{CDoc2::Label::EXPIRY, rcpt.expiry_ts == 0 ? std::string() : std::to_string(rcpt.expiry_ts)}})),
                                                        builder.CreateVector(xor_key),
                                                        cdoc20::header::FMKEncryptionMethod::XOR);
}

static flatbuffers::Offset<cdoc20::header::RecipientRecord>
createRSAServerCapsule(flatbuffers::FlatBufferBuilder& builder, const libcdoc::Recipient& rcpt, const std::string& transaction_id, uint64_t expiry_time, const std::vector<uint8_t>& xor_key)
{
    auto rsaKeyServer = cdoc20::recipients::CreateRsaKeyDetails(builder,
                                                                builder.CreateVector(rcpt.rcpt_key));
    auto capsule = cdoc20::recipients::CreateKeyServerCapsule(builder,
                                                              cdoc20::recipients::KeyDetailsUnion::RsaKeyDetails,
                                                              rsaKeyServer.Union(),
                                                              builder.CreateString(rcpt.server_id),
                                                              builder.CreateString(transaction_id));
    if (rcpt.expiry_ts) expiry_time = std::min(rcpt.expiry_ts, expiry_time);
    return cdoc20::header::CreateRecipientRecord(builder,
                                                        cdoc20::header::Capsule::recipients_KeyServerCapsule,
                                                        capsule.Union(),
                                                        builder.CreateString(rcpt.getLabel({{CDoc2::Label::EXPIRY, std::to_string(expiry_time)}})),
                                                        builder.CreateVector(xor_key),
                                                        cdoc20::header::FMKEncryptionMethod::XOR);
}

static flatbuffers::Offset<cdoc20::header::RecipientRecord>
createECCCapsule(flatbuffers::FlatBufferBuilder& builder, const libcdoc::Recipient& rcpt, const std::vector<uint8_t>& eph_public_key, const std::vector<uint8_t>& xor_key)
{
    auto capsule = cdoc20::recipients::CreateECCPublicKeyCapsule(builder,
                                                                 cdoc20::recipients::EllipticCurve::secp384r1,
                                                                 builder.CreateVector(rcpt.rcpt_key),
                                                                 builder.CreateVector(eph_public_key));
    return cdoc20::header::CreateRecipientRecord(builder,
                                                        cdoc20::header::Capsule::recipients_ECCPublicKeyCapsule,
                                                        capsule.Union(),
                                                        builder.CreateString(rcpt.getLabel({{CDoc2::Label::EXPIRY, rcpt.expiry_ts == 0 ? std::string() : std::to_string(rcpt.expiry_ts)}})),
                                                        builder.CreateVector(xor_key),
                                                        cdoc20::header::FMKEncryptionMethod::XOR);
}

static flatbuffers::Offset<cdoc20::header::RecipientRecord>
createECCServerCapsule(flatbuffers::FlatBufferBuilder& builder, const libcdoc::Recipient& rcpt, const std::string& transaction_id, uint64_t expiry_time, const std::vector<uint8_t>& xor_key)
{
    auto eccKeyServer = cdoc20::recipients::CreateEccKeyDetails(builder,
                                                                cdoc20::recipients::EllipticCurve::secp384r1,
                                                                builder.CreateVector(rcpt.rcpt_key));
    auto capsule = cdoc20::recipients::CreateKeyServerCapsule(builder,
                                                              cdoc20::recipients::KeyDetailsUnion::EccKeyDetails,
                                                              eccKeyServer.Union(),
                                                              builder.CreateString(rcpt.server_id),
                                                              builder.CreateString(transaction_id));
    if (rcpt.expiry_ts) expiry_time = std::min(rcpt.expiry_ts, expiry_time);
    return cdoc20::header::CreateRecipientRecord(builder,
                                                        cdoc20::header::Capsule::recipients_KeyServerCapsule,
                                                        capsule.Union(),
                                                        builder.CreateString(rcpt.getLabel({{CDoc2::Label::EXPIRY, std::to_string(expiry_time)}})),
                                                        builder.CreateVector(xor_key),
                                                        cdoc20::header::FMKEncryptionMethod::XOR);
}

static flatbuffers::Offset<cdoc20::header::RecipientRecord>
createSymmetricKeyCapsule(flatbuffers::FlatBufferBuilder& builder, const libcdoc::Recipient& rcpt, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& xor_key)
{
    auto capsule = cdoc20::recipients::CreateSymmetricKeyCapsule(builder,
                                                                 builder.CreateVector(salt));
    return cdoc20::header::CreateRecipientRecord(builder,
                                                      cdoc20::header::Capsule::recipients_SymmetricKeyCapsule,
                                                      capsule.Union(),
                                                      builder.CreateString(rcpt.getLabel({})),
                                                      builder.CreateVector(xor_key),
                                                      cdoc20::header::FMKEncryptionMethod::XOR);
}

static flatbuffers::Offset<cdoc20::header::RecipientRecord>
createPasswordCapsule(flatbuffers::FlatBufferBuilder& builder, const libcdoc::Recipient& rcpt, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, const std::vector<uint8_t>& xor_key)
{
    auto capsule = cdoc20::recipients::CreatePBKDF2Capsule(builder,
                                                           builder.CreateVector(salt),
                                                           builder.CreateVector(pw_salt),
                                                           cdoc20::recipients::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256,
                                                           rcpt.kdf_iter);
    return cdoc20::header::CreateRecipientRecord(builder,
                                                      cdoc20::header::Capsule::recipients_PBKDF2Capsule,
                                                      capsule.Union(),
                                                      builder.CreateString(rcpt.getLabel({})),
                                                      builder.CreateVector(xor_key),
                                                      cdoc20::header::FMKEncryptionMethod::XOR);
}

libcdoc::result_t
CDoc2Writer::buildHeader(std::vector<uint8_t>& header, const std::vector<libcdoc::Recipient>& recipients, const std::vector<uint8_t>& fmk)
{
    flatbuffers::FlatBufferBuilder builder;
    std::vector<flatbuffers::Offset<cdoc20::header::RecipientRecord>> fb_rcpts;

    std::vector<uint8_t> xor_key(libcdoc::CDoc2::KEY_LEN);
    for (unsigned int rcpt_idx = 0; rcpt_idx < recipients.size(); rcpt_idx++) {
        const libcdoc::Recipient& rcpt = recipients.at(rcpt_idx);
        if (rcpt.isPKI()) {
            std::vector<uint8_t> key_material, kek;
            std::string send_url;
            if(rcpt.isKeyServer()) {
                if(!conf)
                    FAIL("Configuration is missing", libcdoc::CONFIGURATION_ERROR);
                if(!network)
                    FAIL("Network backend is missing", libcdoc::CONFIGURATION_ERROR);
                send_url = conf->getValue(rcpt.server_id, libcdoc::Configuration::KEYSERVER_SEND_URL);
                if (send_url.empty())
                    FAIL("Missing keyserver URL for ID " + rcpt.server_id, libcdoc::CONFIGURATION_ERROR);
            }
            if(rcpt.pk_type == libcdoc::PKType::RSA) {
                crypto->random(kek, libcdoc::CDoc2::KEY_LEN);
                if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK)
                    FAIL("Internal error", libcdoc::CRYPTO_ERROR);
                auto publicKey = libcdoc::Crypto::fromRSAPublicKeyDer(rcpt.rcpt_key);
                if(!publicKey)
                    FAIL("Invalid RSA key", libcdoc::CRYPTO_ERROR);
                key_material = libcdoc::Crypto::encrypt(publicKey.get(), RSA_PKCS1_OAEP_PADDING, kek);

                LOG_TRACE_KEY("publicKeyDer: {}", rcpt.rcpt_key);
                LOG_TRACE_KEY("enc_kek: {}", key_material);
                LOG_TRACE_KEY("kek: {}", kek);
                LOG_TRACE_KEY("xor: {}", xor_key);
                if(rcpt.isKeyServer()) {
                    libcdoc::NetworkBackend::CapsuleInfo cinfo;
                    auto result = network->sendKey(cinfo, send_url, rcpt.rcpt_key, key_material, "rsa", rcpt.expiry_ts);
                    if (result < 0)
                        FAIL(network->getLastErrorStr(result), result);

                    LOG_DBG("Keyserver Id: {}", rcpt.server_id);
                    LOG_DBG("Transaction Id: {}", cinfo.transaction_id);

                    fb_rcpts.push_back(createRSAServerCapsule(builder, rcpt, cinfo.transaction_id, cinfo.expiry_time, xor_key));
                } else {
                    fb_rcpts.push_back(createRSACapsule(builder, rcpt, key_material, xor_key));
                }
            } else {
                auto publicKey = libcdoc::Crypto::fromECPublicKeyDer(rcpt.rcpt_key, NID_secp384r1);
                if(!publicKey)
                    FAIL("Invalid ECC key", libcdoc::CRYPTO_ERROR);
                auto ephKey = libcdoc::Crypto::genECKey(publicKey.get());
                std::vector<uint8_t> sharedSecret = libcdoc::Crypto::deriveSharedSecret(ephKey.get(), publicKey.get());
                key_material = libcdoc::Crypto::toPublicKeyDer(ephKey.get());
                std::vector<uint8_t> kekPm = libcdoc::Crypto::extract(sharedSecret, std::vector<uint8_t>(libcdoc::CDoc2::KEKPREMASTER.cbegin(), libcdoc::CDoc2::KEKPREMASTER.cend()));
                std::string info_str = libcdoc::CDoc2::getSaltForExpand(key_material, rcpt.rcpt_key);

                kek = libcdoc::Crypto::expand(kekPm, info_str, fmk.size());
                if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK)
                    FAIL("Internal error", libcdoc::CRYPTO_ERROR);

                LOG_DBG("info: {}", toHex(info_str));
                LOG_TRACE_KEY("publicKeyDer: {}", rcpt.rcpt_key);
                LOG_TRACE_KEY("ephPublicKeyDer: {}", key_material);
                LOG_TRACE_KEY("sharedSecret: {}", sharedSecret);
                LOG_TRACE_KEY("kekPm: {}", kekPm);
                LOG_TRACE_KEY("kek: {}", kek);
                LOG_TRACE_KEY("xor: {}", xor_key);
                if(rcpt.isKeyServer()) {
                    libcdoc::NetworkBackend::CapsuleInfo cinfo;
                    auto result = network->sendKey(cinfo, send_url, rcpt.rcpt_key, key_material, "ecc_secp384r1", rcpt.expiry_ts);
                    if (result < 0)
                        FAIL(network->getLastErrorStr(result), result);

                    LOG_DBG("Keyserver Id: {}", rcpt.server_id);
                    LOG_DBG("Transaction Id: {}", cinfo.transaction_id);

                    fb_rcpts.push_back(createECCServerCapsule(builder, rcpt, cinfo.transaction_id, cinfo.expiry_time, xor_key));
                } else {
                    fb_rcpts.push_back(createECCCapsule(builder, rcpt, key_material, xor_key));
                }
            }
        } else if (rcpt.isSymmetric()) {
            std::string info_str = libcdoc::CDoc2::getSaltForExpand(rcpt.getLabel({}));
            std::vector<uint8_t> kek_pm(libcdoc::CDoc2::KEY_LEN);
            std::vector<uint8_t> salt;
            int64_t result = crypto->random(salt, libcdoc::CDoc2::KEY_LEN);
            if (result < 0)
                FAIL(crypto->getLastErrorStr(result), result);
            std::vector<uint8_t> pw_salt;
            result = crypto->random(pw_salt, libcdoc::CDoc2::KEY_LEN);
            if (result < 0)
                FAIL(crypto->getLastErrorStr(result), result);
            result = crypto->extractHKDF(kek_pm, salt, pw_salt, rcpt.kdf_iter, rcpt_idx);
            if (result < 0)
                FAIL(crypto->getLastErrorStr(result), result);
            std::vector<uint8_t> kek = libcdoc::Crypto::expand(kek_pm, info_str, libcdoc::CDoc2::KEY_LEN);

            LOG_DBG("Label: {}", rcpt.label);
            LOG_DBG("KDF iter: {}", rcpt.kdf_iter);
            LOG_DBG("info: {}", toHex(info_str));
            LOG_TRACE_KEY("salt: {}", salt);
            LOG_TRACE_KEY("pw_salt: {}", pw_salt);
            LOG_TRACE_KEY("kek_pm: {}", kek_pm);
            LOG_TRACE_KEY("kek: {}", kek);

            if (kek.empty()) return libcdoc::CRYPTO_ERROR;
            if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK)
                FAIL("Internal error", libcdoc::CRYPTO_ERROR);
            if (rcpt.kdf_iter > 0) {
                fb_rcpts.push_back(createPasswordCapsule(builder, rcpt, salt, pw_salt, xor_key));
            } else {
                fb_rcpts.push_back(createSymmetricKeyCapsule(builder, rcpt, salt, xor_key));
            }
#ifdef HAS_KEYSHARES
        } else if (rcpt.isKeyShare()) {
            std::string url_list = conf->getValue(rcpt.server_id, libcdoc::Configuration::SHARE_SERVER_URLS);
            if (url_list.empty())
                FAIL("Missing server list for ID " + rcpt.server_id, libcdoc::CONFIGURATION_ERROR);
            LOG_DBG("Share servers: {}", url_list);
            std::vector<std::string> urls = libcdoc::JsonToStringArray(url_list);
            if (urls.size() < 1)
                FAIL("No server URLs in " + rcpt.server_id, libcdoc::CONFIGURATION_ERROR);
            int N_SHARES = urls.size();
            LOG_DBG("Number of shares: {}", N_SHARES);

            // identifier of the method, which is used to encrypt the plaintext FMK value:
            std::string FMKEncryptionMethod = "XOR";
            // Recipient identifier ("etsi/PNOEE-48010010101"):
            std::string RecipientInfo_i = "etsi/" + rcpt.id;
            LOG_DBG("Recipient info: {}", RecipientInfo_i);

            //# KEK_i computation:
            //KeyMaterialSalt_i = CSRNG(256)
            std::vector<uint8_t> key_material_salt;
            crypto->random(key_material_salt, libcdoc::CDoc2::KEY_LEN);

            //KeyMaterial_i = CSRNG(256)
            std::vector<uint8_t> key_material;
            crypto->random(key_material, libcdoc::CDoc2::KEY_LEN);

            //KEK_i_pm = HKDF_Extract(KeyMaterialSalt_i, KeyMaterial_i)
            std::vector<uint8_t> kek_pm = libcdoc::Crypto::extract(key_material_salt, key_material);

            // KEK_i = HKDF_Expand(KEK_i_pm, "CDOC2kek" + FMKEncryptionMethod + RecipientInfo_i, L)
            std::string info_str = std::string("CDOC2kek") + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) + RecipientInfo_i;
            LOG_DBG("Info: {}", info_str);
            std::vector<uint8_t> kek = libcdoc::Crypto::expand(kek_pm, info_str);
            LOG_TRACE_KEY("kek: {}", kek);
            if (kek.empty()) return libcdoc::CRYPTO_ERROR;
            if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK)
                FAIL("Internal error", libcdoc::CRYPTO_ERROR);

            // # Splitting KEK_i into shares
            // for j in (2, 3, ..., n):
            std::vector<std::vector<uint8_t>> kek_shares(N_SHARES);
            for (int i = 1; i < N_SHARES; i++) {
                // KEK_i_share_j = CSRNG(256)
                crypto->random(kek_shares[i], libcdoc::CDoc2::KEY_LEN);
            }
            // KEK_i_share_1 = XOR(KEK_i, KEK_i_share_2, KEK_i_share_3,..., KEK_i_share_n)
            kek_shares[0] = std::move(kek);
            for (int i = 1; i < N_SHARES; i++) {
                if (libcdoc::Crypto::xor_data(kek_shares[0], kek_shares[0], kek_shares[i]) != libcdoc::OK)
                    FAIL("Internal error", libcdoc::CRYPTO_ERROR);
            }
            //   # Client uploads all shares of KEK_i to CSS servers and
            //   # gets corresponding Capsule_i_Share_j_ID for each KEK_i_share_j
            //   RecipientInfo_i = "etsi/PNOEE-48010010101"
            //   DistributedKEKInfo_i = {CSS_ID, Capsule_i_Share_j_ID}
            std::vector<std::vector<uint8_t>> transaction_ids(N_SHARES);
            for (int i = 0; i < N_SHARES; i++) {
                std::string send_url = urls[i];
                LOG_DBG("Sending share: {} {} {}", i, send_url, libcdoc::toHex(kek_shares[i]));
                int result = network->sendShare(transaction_ids[i], send_url, RecipientInfo_i, kek_shares[i]);
                if (result < 0)
                    FAIL(network->getLastErrorStr(result), result);
                LOG_DBG("Share {} Transaction Id: {}", i, std::string((const char *) transaction_ids[i].data(), transaction_ids[i].size()));
            }
            std::vector<flatbuffers::Offset<cdoc20::recipients::KeyShare>> shares;
            for (int i = 0; i < N_SHARES; i++) {
                auto share = cdoc20::recipients::CreateKeyShare(builder, builder.CreateString(urls[i]), builder.CreateString((const char *)transaction_ids[i].data(), transaction_ids[i].size()));
                shares.push_back(share);
            }
            auto fb_shares = builder.CreateVector(shares);
            auto fb_capsule = cdoc20::recipients::CreateKeySharesCapsule(builder,
                                                                      fb_shares,
                                                                      builder.CreateVector(key_material_salt),
                                                                      cdoc20::recipients::KeyShareRecipientType::SID_MID,
                                                                      cdoc20::recipients::SharesScheme::N_OF_N,
                                                                      builder.CreateString(RecipientInfo_i));
            auto offset = cdoc20::header::CreateRecipientRecord(builder,
                                                         cdoc20::header::Capsule::recipients_KeySharesCapsule,
                                                         fb_capsule.Union(),
                                                         builder.CreateString(rcpt.label),
                                                         builder.CreateVector(xor_key),
                                                         cdoc20::header::FMKEncryptionMethod::XOR);
            fb_rcpts.push_back(offset);
#endif
        } else {
            FAIL("Invalid recipient type", libcdoc::UNSPECIFIED_ERROR);
        }
    }

    auto offset = cdoc20::header::CreateHeader(builder, builder.CreateVector(fb_rcpts),
                                               cdoc20::header::PayloadEncryptionMethod::CHACHA20POLY1305);
    builder.Finish(offset);

    header.assign(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
    return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::addRecipient(const libcdoc::Recipient& rcpt)
{
    if (finished)
        FAIL("Encryption finished", libcdoc::WORKFLOW_ERROR);
    if(tar)
        FAIL("Cannot add Recipient when files are added", libcdoc::WORKFLOW_ERROR);
    // Validate
    switch(rcpt.type) {
        case Recipient::SYMMETRIC_KEY:
            if (!crypto)
                FAIL("Symmetric key requires CryptoBackend", libcdoc::WORKFLOW_ERROR);
            if(!rcpt.validate())
                FAIL("Invalid recipient parameters", libcdoc::WRONG_ARGUMENTS);
            break;
        case Recipient::PUBLIC_KEY:
            if(!rcpt.server_id.empty() && !network)
                FAIL("Server capsule requires NetworkBackend", libcdoc::WORKFLOW_ERROR);
            if(!rcpt.validate())
                FAIL("Invalid recipient parameters", libcdoc::WRONG_ARGUMENTS);
            break;
        default:
            FAIL("Invalid recipient type", WRONG_ARGUMENTS);
    }
    recipients.push_back(rcpt);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::beginEncryption()
{
    if (finished)
        FAIL("Encryption finished", libcdoc::WORKFLOW_ERROR);
    last_error.clear();
    if(recipients.empty())
        FAIL("No recipients added", libcdoc::WORKFLOW_ERROR);
    if(tar)
        FAIL("Encryption already started", libcdoc::WORKFLOW_ERROR);
    if(auto rv = writeHeader(recipients); rv < 0)
        return rv;
    return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::addFile(const std::string& name, size_t size)
{
    if (finished)
        FAIL("Encryption finished", libcdoc::WORKFLOW_ERROR);
    if(!tar)
        FAIL("Encryption not started", libcdoc::WORKFLOW_ERROR);
    if (name.empty() || !libcdoc::isValidUtf8(name))
        FAIL("Invalid file name", libcdoc::DATA_FORMAT_ERROR);
    if (size > 8ULL * 1024 * 1024 * 1024)
        FAIL("Invalid file size", libcdoc::WRONG_ARGUMENTS);
    if(auto rv = tar->open(name, size); rv < 0)
        FAIL(tar->getLastErrorStr(rv), rv);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::writeData(const uint8_t *src, size_t size)
{
    if (finished)
        FAIL("Encryption finished", libcdoc::WORKFLOW_ERROR);
    if(!tar)
        FAIL("No file added", libcdoc::WORKFLOW_ERROR);
    if(auto rv = tar->write(src, size); rv != size)
        FAIL(tar->getLastErrorStr(rv), rv);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::finishEncryption()
{
    if (finished)
        FAIL("Encryption finished", libcdoc::WORKFLOW_ERROR);
    if(!tar)
        FAIL("No file added", libcdoc::WORKFLOW_ERROR);
    auto rv = tar->close();
    if(rv < 0)
        setLastError(tar->getLastErrorStr(rv));
    tar.reset();
    recipients.clear();
    if (owned) dst->close();
    finished = true;
    return rv;
}

libcdoc::result_t
CDoc2Writer::encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
    if (finished)
        FAIL("Encryption finished", libcdoc::WORKFLOW_ERROR);
    for (auto rcpt : keys) {
        if(auto rv = addRecipient(rcpt); rv != libcdoc::OK)
            return rv;
    }
    if(auto rv = beginEncryption(); rv < 0)
        return rv;
    std::string name;
    int64_t size;
    auto result = src.next(name, size);
    while(result == libcdoc::OK) {
        if (result = tar->open(name, size); result != libcdoc::OK)
            break;
        if (result = tar->writeAll(src); result < 0)
            break;
        result = src.next(name, size);
    }
    if (result != libcdoc::END_OF_STREAM) {
        tar.reset();
        return result;
    }
    return finishEncryption();
}

result_t
libcdoc::CDoc2Writer::fail(const std::string& message, result_t result)
{
    setLastError(message);
    LOG_ERROR("{}", message);
    return result;
}
