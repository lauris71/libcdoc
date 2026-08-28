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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

//
// Live integration tests for the keyshare (Smart-ID / Mobile-ID) flows.
//
// DISABLED BY DEFAULT: they require VPN connectivity to the RIA test
// environment and use the SK automated test identities (which approve
// requests automatically after a few seconds).
//
// Enable with:
//   LIBCDOC_LIVE_TESTS=1 ./build/.../test/unittests --run_test=LiveSidMid
//
// The RIA certificate-pinning infrastructure is still in development, so the
// tests currently require a build with LIBCDOC_ALLOW_INSECURE_TLS=ON (TLS
// certificate checks disabled); without it they are skipped.
//

#include <boost/test/unit_test.hpp>

#include <cdoc/CDocReader.h>
#include <cdoc/CDocWriter.h>
#include <cdoc/CryptoBackend.h>
#include <cdoc/Io.h>
#include <cdoc/Lock.h>
#include <cdoc/NetworkBackend.h>
#include <cdoc/Recipient.h>
#include <cdoc/ToolConf.h>
#include <cdoc/Utils.h>
#include <cdoc/utils/memory.h>

#include <cstdlib>
#include <memory>

using namespace std::string_literals;

namespace utf = boost::unit_test;

namespace {

// The RIA dev servers (default - the test environment's MID endpoint is
// currently broken). The test environment can be selected via environment
// variables, e.g.:
//   LIBCDOC_LIVE_SHARE_SERVERS="https://cdoc2-shares.test.riaint.ee,https://cdoc2-sharesexternal.test.riaint.ee" \
//   LIBCDOC_LIVE_AUTH_SERVER=https://cdoc2-auth.test.riaint.ee \
//   LIBCDOC_LIVE_RP_SERVER=https://cdoc2-rp.test.riaint.ee \
//   LIBCDOC_LIVE_TESTS=1 ./unittests --run_test=LiveSidMid
std::string
envOr(const char *name, const char *fallback)
{
    const char *v = std::getenv(name);
    return (v && *v) ? v : fallback;
}

const std::string SHARE_SERVERS = envOr("LIBCDOC_LIVE_SHARE_SERVERS",
    "https://cdoc2-shares.dev.riaint.ee,https://cdoc2-sharesexternal.dev.riaint.ee");
const std::string AUTH_SERVER = envOr("LIBCDOC_LIVE_AUTH_SERVER", "https://cdoc2-auth.dev.riaint.ee");
const std::string RP_SERVER = envOr("LIBCDOC_LIVE_RP_SERVER", "https://cdoc2-rp.dev.riaint.ee");

constexpr const char *SERVER_ID = "test-shares";

// SK automated test identities
constexpr const char *SID_PNO = "30303039903";    // Smart-ID test identity
constexpr const char *MID_PNO = "51307149560";    // Mobile-ID test identity
constexpr const char *MID_PHONE = "+37269930366"; // Mobile-ID test phone number

bool
liveTestsEnabled()
{
    std::string_view val = std::getenv("LIBCDOC_LIVE_TESTS") ? std::getenv("LIBCDOC_LIVE_TESTS") : "";
    return !val.empty() && val != "0";
}

// A network backend that does not pin peer certificates - relies on a
// LIBCDOC_ALLOW_INSECURE_TLS build until the RIA pinning infrastructure is
// ready.
struct LiveNetworkBackend : public libcdoc::NetworkBackend {
    libcdoc::result_t getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst, const std::string &url) override
    {
        dst.clear();
        return libcdoc::OK;
    }

    libcdoc::result_t showFeedback(SIDMIDFeedback& feedback) override
    {
        std::cout << "[LIVE] Verification code: " << feedback.code << std::endl;
        return libcdoc::OK;
    }
};

void
sidMidRoundtrip(const std::string& pno, const std::string& phone)
{
    if (!liveTestsEnabled()) {
        BOOST_TEST_MESSAGE("Live SID/MID tests are disabled (set LIBCDOC_LIVE_TESTS=1 to enable)");
        return;
    }
#ifndef LIBCDOC_ALLOW_INSECURE_TLS
    BOOST_TEST_MESSAGE("Live SID/MID tests require a LIBCDOC_ALLOW_INSECURE_TLS=ON build");
    BOOST_FAIL("LIBCDOC_ALLOW_INSECURE_TLS is not enabled in this build");
#endif

    const std::string payload_str = "Live keyshare roundtrip test payload\n";
    const std::vector<uint8_t> payload(payload_str.cbegin(), payload_str.cend());

    libcdoc::ToolConf conf;
    conf.servers.push_back({SERVER_ID, SHARE_SERVERS});
    conf.auth_server = AUTH_SERVER;
    conf.rp_server = RP_SERVER;
    conf.phone = phone; // ToolConf: empty phone -> SID, non-empty -> MID

    libcdoc::CryptoBackend crypto;
    LiveNetworkBackend network;

    //
    // Encrypt
    //
    std::vector<uint8_t> container;
    libcdoc::VectorConsumer consumer(container);
    std::unique_ptr<libcdoc::CDocWriter> wrt(
        libcdoc::CDocWriter::createWriter(2, &consumer, false, &conf, &crypto, &network));
    BOOST_REQUIRE(wrt != nullptr);

    libcdoc::Recipient rcpt = libcdoc::Recipient::makeShare("Live test", SERVER_ID, "PNOEE-" + pno);
    BOOST_REQUIRE(wrt->addRecipient(rcpt) == libcdoc::OK);
    BOOST_REQUIRE(wrt->beginEncryption() == libcdoc::OK);
    BOOST_REQUIRE(wrt->addFile("test.txt", payload.size()) == libcdoc::OK);
    BOOST_REQUIRE(wrt->writeData(payload.data(), payload.size()) == libcdoc::OK);
    BOOST_REQUIRE(wrt->finishEncryption() == libcdoc::OK);
    BOOST_REQUIRE(!container.empty());

    //
    // Decrypt
    //
    libcdoc::VectorSource src(container);
    std::unique_ptr<libcdoc::CDocReader> rdr(
        libcdoc::CDocReader::createReader(&src, false, &conf, &crypto, &network));
    BOOST_REQUIRE(rdr != nullptr);

    // Find the share server lock
    const std::vector<libcdoc::Lock>& locks = rdr->getLocks();
    unsigned int lock_idx = locks.size();
    for (size_t i = 0; i < locks.size(); i++) {
        if (locks[i].type == libcdoc::Lock::Type::SHARE_SERVER)
            lock_idx = i;
    }
    BOOST_REQUIRE(lock_idx < locks.size());

    // getFMK runs the full SID/MID flow (auth session, nonce, signing, shares)
    std::vector<uint8_t> fmk;
    BOOST_REQUIRE_EQUAL(rdr->getFMK(fmk, lock_idx), libcdoc::OK);
    libcdoc::Cleanser fmk_guard(fmk);

    BOOST_REQUIRE_EQUAL(rdr->beginDecryption(fmk), libcdoc::OK);

    libcdoc::FileInfo fi;
    BOOST_REQUIRE_EQUAL(rdr->nextFile(fi), libcdoc::OK);
    BOOST_CHECK_EQUAL(fi.name, "test.txt");

    std::vector<uint8_t> out;
    uint8_t buf[4096];
    libcdoc::result_t n;
    while ((n = rdr->readData(buf, sizeof(buf))) > 0)
        out.insert(out.end(), buf, buf + n);
    BOOST_REQUIRE_EQUAL(n, 0);

    BOOST_CHECK(out == payload);
}

} // namespace

BOOST_AUTO_TEST_SUITE(LiveSidMid)

BOOST_AUTO_TEST_CASE(SID)
{
    sidMidRoundtrip(SID_PNO, {});
}

BOOST_AUTO_TEST_CASE(MID)
{
    sidMidRoundtrip(MID_PNO, MID_PHONE);
}

BOOST_AUTO_TEST_SUITE_END()
