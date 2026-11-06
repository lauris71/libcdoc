// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "TLSKey.h"

#include "CryptoBackend.h"
#include "NetworkBackend.h"
#include "Utils.h"

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdlib>
#include <cstring>
#include <string_view>

using namespace std::literals::string_view_literals;

namespace {

constexpr const char *PROVIDER_PROPS = "provider=libcdoc-tls";
// Carries the NetworkBackend pointer from createTLSKey() to the key import
constexpr const char *NETWORK_PARAM = "libcdoc-network";
constexpr char RSA_NAME[] = "RSA";
constexpr char EC_NAME[] = "EC";
constexpr char ECDSA_NAME[] = "ECDSA";

// The provider lives in a library context of its own, so that its RSA and EC
// implementations are only ever used for the keys made here
OSSL_LIB_CTX *libctx = nullptr;

template <typename F>
OSSL_DISPATCH fn(int id, F f) { return {id, reinterpret_cast<void (*)()>(f)}; }

//
// Key management: the public key is kept as the default provider's key, the private
// key operations go to the network backend
//

struct Key {
    const char *type;
    EVP_PKEY *pub = nullptr;
    // nullptr for a key imported from elsewhere, e.g. a certificate's to compare with
    libcdoc::NetworkBackend *network = nullptr;
};

template <const char *Type>
void *keyNew(void *) { return new Key{Type}; }

void keyFree(void *vkey)
{
    if (auto *key = static_cast<Key *>(vkey)) {
        EVP_PKEY_free(key->pub);
        delete key;
    }
}

int keyHas(const void *vkey, int selection)
{
    const auto *key = static_cast<const Key *>(vkey);
    return key && key->pub && (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) || key->network);
}

int keyImport(void *vkey, int /*selection*/, const OSSL_PARAM params[])
{
    auto *key = static_cast<Key *>(vkey);
    if (!key || key->pub) return 0;
    if (const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, NETWORK_PARAM)) {
        const void *ptr = nullptr;
        size_t len = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &ptr, &len) || len != sizeof(key->network)) return 0;
        std::memcpy(&key->network, ptr, len);
    }
    // The default provider ignores NETWORK_PARAM
    auto ctx = libcdoc::make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new_from_name(libctx, key->type, "provider=default"));
    return ctx && EVP_PKEY_fromdata_init(ctx.get()) == 1 &&
        EVP_PKEY_fromdata(ctx.get(), &key->pub, EVP_PKEY_PUBLIC_KEY, const_cast<OSSL_PARAM *>(params)) == 1;
}

int keyExport(void *vkey, int selection, OSSL_CALLBACK *cb, void *cbarg)
{
    auto *key = static_cast<Key *>(vkey);
    // Signing first tries the key in whichever provider the name resolves to in the
    // caller's library context, exporting it there with everything selected. Only when
    // that export fails does it come back to this provider, so a key with a private half
    // must not leave. Comparing it with the certificate asks for the public part only.
    if (!key || !key->pub || ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && key->network)) return 0;
    OSSL_PARAM *params = nullptr;
    if (EVP_PKEY_todata(key->pub, EVP_PKEY_PUBLIC_KEY, &params) != 1) return 0;
    int ok = cb(params, cbarg);
    OSSL_PARAM_free(params);
    return ok;
}

int keyMatch(const void *vkey1, const void *vkey2, int /*selection*/)
{
    const auto *key1 = static_cast<const Key *>(vkey1);
    const auto *key2 = static_cast<const Key *>(vkey2);
    return key1 && key2 && key1->pub && key2->pub && EVP_PKEY_eq(key1->pub, key2->pub) == 1;
}

int keyGetParams(void *vkey, OSSL_PARAM params[])
{
    // Size, security bits, group and the like are those of the public key
    auto *key = static_cast<Key *>(vkey);
    return key && key->pub && EVP_PKEY_get_params(key->pub, params) == 1;
}

// OpenSSL accepts import, export and get_params only together with these descriptors
// (keymgmt_meth.c); neither key creation nor TLS consults them, so they are empty
const OSSL_PARAM *noTypes() { static const OSSL_PARAM end[] { OSSL_PARAM_END }; return end; }
const OSSL_PARAM *keyTypes(int /*selection*/) { return noTypes(); }
const OSSL_PARAM *keyGettableParams(void * /*provctx*/) { return noTypes(); }

template <const char *SignatureName>
const char *keyOperationName(int operation_id) { return operation_id == OSSL_OP_SIGNATURE ? SignatureName : nullptr; }

template <const char *Type, const char *SignatureName>
const OSSL_DISPATCH keymgmt[] {
    fn(OSSL_FUNC_KEYMGMT_NEW, keyNew<Type>),
    fn(OSSL_FUNC_KEYMGMT_FREE, keyFree),
    fn(OSSL_FUNC_KEYMGMT_HAS, keyHas),
    fn(OSSL_FUNC_KEYMGMT_MATCH, keyMatch),
    fn(OSSL_FUNC_KEYMGMT_IMPORT, keyImport),
    fn(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, keyTypes),
    fn(OSSL_FUNC_KEYMGMT_EXPORT, keyExport),
    fn(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, keyTypes),
    fn(OSSL_FUNC_KEYMGMT_GET_PARAMS, keyGetParams),
    fn(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, keyGettableParams),
    fn(OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, keyOperationName<SignatureName>),
    {0, nullptr}
};

//
// Signature: hash here, sign the digest with the network backend
//

struct SignCtx {
    Key *key = nullptr;
    libcdoc::unique_ptr_t<EVP_MD_free> md = libcdoc::make_unique_ptr<EVP_MD_free>(nullptr);
    libcdoc::unique_ptr_t<EVP_MD_free> mgf1 = libcdoc::make_unique_ptr<EVP_MD_free>(nullptr);
    libcdoc::unique_ptr_t<EVP_MD_CTX_free> mdctx = libcdoc::make_unique_ptr<EVP_MD_CTX_free>(EVP_MD_CTX_new());
    int padding = RSA_PKCS1_PADDING;
    int saltlen = RSA_PSS_SALTLEN_DIGEST;
};

bool fetchDigest(libcdoc::unique_ptr_t<EVP_MD_free> &md, const OSSL_PARAM *p)
{
    const char *name = nullptr;
    if (OSSL_PARAM_get_utf8_string_ptr(p, &name) != 1) return false;
    md.reset(EVP_MD_fetch(libctx, name, "provider=default"));
    return bool(md);
}

void *sigNew(void * /*provctx*/, const char * /*propq*/) { return new SignCtx; }
void sigFree(void *vctx) { delete static_cast<SignCtx *>(vctx); }

void *sigDup(void *vctx)
{
    const auto *ctx = static_cast<const SignCtx *>(vctx);
    auto copy = std::make_unique<SignCtx>();
    if (!ctx->mdctx || !copy->mdctx || EVP_MD_CTX_copy_ex(copy->mdctx.get(), ctx->mdctx.get()) != 1)
        return nullptr;
    if (ctx->md && EVP_MD_up_ref(ctx->md.get()) != 1)
        return nullptr;
    copy->md.reset(ctx->md.get());
    if (ctx->mgf1 && EVP_MD_up_ref(ctx->mgf1.get()) != 1)
        return nullptr;
    copy->mgf1.reset(ctx->mgf1.get());
    copy->key = ctx->key;
    copy->padding = ctx->padding;
    copy->saltlen = ctx->saltlen;
    return copy.release();
}

int sigSetParams(void *vctx, const OSSL_PARAM params[])
{
    auto *ctx = static_cast<SignCtx *>(vctx);
    // EVP_PKEY_CTX_set_rsa_padding() and _pss_saltlen() arrive as names, OSSL_PARAM users may pass numbers
    const char *str = nullptr;
    if (const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST); p && !fetchDigest(ctx->md, p))
        return 0;
    if (const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST); p && !fetchDigest(ctx->mgf1, p))
        return 0;
    if (const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE)) {
        if (OSSL_PARAM_get_utf8_string_ptr(p, &str) == 1)
            ctx->padding = str == OSSL_PKEY_RSA_PAD_MODE_PSS ""sv ? RSA_PKCS1_PSS_PADDING :
                str == OSSL_PKEY_RSA_PAD_MODE_PKCSV15 ""sv ? RSA_PKCS1_PADDING : -1;
        else if (OSSL_PARAM_get_int(p, &ctx->padding) != 1)
            return 0;
    }
    if (const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN)) {
        if (OSSL_PARAM_get_utf8_string_ptr(p, &str) == 1)
            ctx->saltlen = str == OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST ""sv ? RSA_PSS_SALTLEN_DIGEST : std::atoi(str);
        else if (OSSL_PARAM_get_int(p, &ctx->saltlen) != 1)
            return 0;
    }
    return 1;
}

const OSSL_PARAM *sigSettableParams(void * /*vctx*/, void * /*provctx*/)
{
    static const OSSL_PARAM types[] {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nullptr, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, nullptr, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, nullptr, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, nullptr, 0),
        OSSL_PARAM_END
    };
    return types;
}

int sigDigestSignInit(void *vctx, const char *mdname, void *vkey, const OSSL_PARAM params[])
{
    auto *ctx = static_cast<SignCtx *>(vctx);
    ctx->key = static_cast<Key *>(vkey);
    if (!ctx->key || !ctx->key->network || !sigSetParams(ctx, params)) return 0;
    if (mdname && *mdname)
        ctx->md.reset(EVP_MD_fetch(libctx, mdname, "provider=default"));
    return ctx->md && ctx->mdctx && EVP_DigestInit_ex2(ctx->mdctx.get(), ctx->md.get(), nullptr) == 1;
}

int sigDigestSignUpdate(void *vctx, const unsigned char *data, size_t datalen)
{
    return EVP_DigestUpdate(static_cast<SignCtx *>(vctx)->mdctx.get(), data, datalen);
}

int sigDigestSignFinal(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    auto *ctx = static_cast<SignCtx *>(vctx);
    if (!sig) {
        *siglen = size_t(EVP_PKEY_get_size(ctx->key->pub));
        return 1;
    }
    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx->mdctx.get(), digest.data(), &len) != 1) return 0;
    digest.resize(len);

    libcdoc::CryptoBackend::HashAlgorithm algo;
    switch (EVP_MD_get_type(ctx->md.get())) {
    case NID_sha224: algo = libcdoc::CryptoBackend::SHA_224; break;
    case NID_sha256: algo = libcdoc::CryptoBackend::SHA_256; break;
    case NID_sha384: algo = libcdoc::CryptoBackend::SHA_384; break;
    case NID_sha512: algo = libcdoc::CryptoBackend::SHA_512; break;
    default:
        LOG_ERROR("Unsupported TLS client signature digest {}", EVP_MD_get0_name(ctx->md.get()));
        return 0;
    }
    const bool isRSA = ctx->key->type == RSA_NAME;
    // What tokens implement and TLS 1.3 asks for: PSS salt as long as the hash, MGF1 with the same hash
    const bool supported = !isRSA || (ctx->padding == RSA_PKCS1_PSS_PADDING &&
        (!ctx->mgf1 || EVP_MD_get_type(ctx->mgf1.get()) == EVP_MD_get_type(ctx->md.get())) &&
        (ctx->saltlen == RSA_PSS_SALTLEN_DIGEST || ctx->saltlen == int(len)));
    if (!supported) {
        LOG_ERROR("Unsupported RSA padding {} for TLS client signature", ctx->padding);
        return 0;
    }

    std::vector<uint8_t> dst;
    if (ctx->key->network->signTLS(dst, algo, digest) != libcdoc::OK || dst.empty() || (!isRSA && dst.size() % 2))
        return 0;
    if (isRSA) {
        if (dst.size() > sigsize) return 0;
        std::memcpy(sig, dst.data(), dst.size());
        *siglen = dst.size();
        return 1;
    }
    // Tokens give ECDSA signatures as r || s, TLS wants them DER encoded
    auto ecsig = libcdoc::make_unique_ptr<ECDSA_SIG_free>(ECDSA_SIG_new());
    BIGNUM *r = BN_bin2bn(dst.data(), int(dst.size() / 2), nullptr);
    BIGNUM *s = BN_bin2bn(dst.data() + dst.size() / 2, int(dst.size() / 2), nullptr);
    if (!ecsig || !r || !s || ECDSA_SIG_set0(ecsig.get(), r, s) != 1) {
        BN_free(r);
        BN_free(s);
        return 0;
    }
    if (int derlen = i2d_ECDSA_SIG(ecsig.get(), nullptr); derlen <= 0 || size_t(derlen) > sigsize) return 0;
    *siglen = size_t(i2d_ECDSA_SIG(ecsig.get(), &sig));
    return 1;
}

const OSSL_DISPATCH signature[] {
    fn(OSSL_FUNC_SIGNATURE_NEWCTX, sigNew),
    fn(OSSL_FUNC_SIGNATURE_FREECTX, sigFree),
    fn(OSSL_FUNC_SIGNATURE_DUPCTX, sigDup),
    fn(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, sigDigestSignInit),
    fn(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, sigDigestSignUpdate),
    fn(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, sigDigestSignFinal),
    fn(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, sigSetParams),
    fn(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, sigSettableParams),
    {0, nullptr}
};

//
// Provider
//

const OSSL_ALGORITHM *providerQuery(void * /*provctx*/, int operation_id, int *no_cache)
{
    static const OSSL_ALGORITHM keymgmts[] {
        {"RSA:rsaEncryption:1.2.840.113549.1.1.1", PROVIDER_PROPS, keymgmt<RSA_NAME, RSA_NAME>, nullptr},
        {"EC:id-ecPublicKey:1.2.840.10045.2.1", PROVIDER_PROPS, keymgmt<EC_NAME, ECDSA_NAME>, nullptr},
        {nullptr, nullptr, nullptr, nullptr}
    };
    static const OSSL_ALGORITHM signatures[] {
        {"RSA:rsaEncryption:1.2.840.113549.1.1.1", PROVIDER_PROPS, signature, nullptr},
        {ECDSA_NAME, PROVIDER_PROPS, signature, nullptr},
        {nullptr, nullptr, nullptr, nullptr}
    };
    *no_cache = 0;
    return operation_id == OSSL_OP_KEYMGMT ? keymgmts : operation_id == OSSL_OP_SIGNATURE ? signatures : nullptr;
}

int providerInit(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH * /*in*/, const OSSL_DISPATCH **out, void **provctx)
{
    static const OSSL_DISPATCH dispatch[] {
        fn(OSSL_FUNC_PROVIDER_QUERY_OPERATION, providerQuery),
        {0, nullptr}
    };
    *out = dispatch;
    *provctx = const_cast<OSSL_CORE_HANDLE *>(handle);
    return 1;
}

} // namespace

libcdoc::unique_ptr_t<EVP_PKEY_free>
libcdoc::createTLSKey(NetworkBackend *network, X509 *cert)
{
    // Set up once and kept for the life of the process. Public keys and digests come
    // from the default provider, private key operations from ours.
    static OSSL_LIB_CTX *ctx = [] {
        libctx = OSSL_LIB_CTX_new();
        if (libctx && (!OSSL_PROVIDER_load(libctx, "default") ||
                !OSSL_PROVIDER_add_builtin(libctx, "libcdoc-tls", providerInit) ||
                !OSSL_PROVIDER_load(libctx, "libcdoc-tls"))) {
            LOG_ERROR("Failed to load the TLS client key provider");
            OSSL_LIB_CTX_free(libctx);
            libctx = nullptr;
        }
        return libctx;
    }();
    EVP_PKEY *pub = cert ? X509_get0_pubkey(cert) : nullptr;
    const char *type = !pub ? nullptr : EVP_PKEY_is_a(pub, RSA_NAME) ? RSA_NAME : EVP_PKEY_is_a(pub, EC_NAME) ? EC_NAME : nullptr;
    OSSL_PARAM *pubData = nullptr;
    if (!ctx || !network || !type || EVP_PKEY_todata(pub, EVP_PKEY_PUBLIC_KEY, &pubData) != 1) {
        LOG_ERROR("Unsupported TLS client key");
        return make_unique_ptr<EVP_PKEY_free>(nullptr);
    }
    auto pubParams = make_unique_ptr<OSSL_PARAM_free>(pubData);
    OSSL_PARAM networkParam[] {
        OSSL_PARAM_construct_octet_string(NETWORK_PARAM, &network, sizeof(network)),
        OSSL_PARAM_construct_end()
    };
    // The merged list points into pubParams, which must outlive it
    auto params = make_unique_ptr<OSSL_PARAM_free>(OSSL_PARAM_merge(pubParams.get(), networkParam));
    auto kctx = make_unique_ptr<EVP_PKEY_CTX_free>(EVP_PKEY_CTX_new_from_name(ctx, type, PROVIDER_PROPS));
    EVP_PKEY *key = nullptr;
    if (!params || !kctx || EVP_PKEY_fromdata_init(kctx.get()) != 1 ||
            EVP_PKEY_fromdata(kctx.get(), &key, EVP_PKEY_KEYPAIR, params.get()) != 1)
        LOG_ERROR("Failed to create the TLS client key");
    return make_unique_ptr<EVP_PKEY_free>(key);
}
