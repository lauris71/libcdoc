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

#include <openssl/x509v3.h>

#include "Crypto.h"
#include "Certificate.h"

namespace libcdoc {

static std::string
getName(const std::vector<uint8_t>& cert, int NID)
{
	X509 *peerCert = Crypto::toX509(cert);
	if(!peerCert) return {};
	std::string cn = [&]{
		std::string cn;
		X509_NAME *name = X509_get_subject_name(peerCert);
		if(!name)
			return cn;
        int pos = X509_NAME_get_index_by_NID(name, NID, -1);
		if(pos == -1)
			return cn;
		X509_NAME_ENTRY *e = X509_NAME_get_entry(name, pos);
		if(!e)
			return cn;
		char *data = nullptr;
		int size = ASN1_STRING_to_UTF8((uint8_t**)&data, X509_NAME_ENTRY_get_data(e));

		cn.assign(data, size_t(size));
		OPENSSL_free(data);
		return cn;
	}();
	X509_free(peerCert);
	return cn;
}

std::string
Certificate::getCommonName() const
{
	return getName(cert, NID_commonName);
}

std::string
Certificate::getGivenName() const
{
	return getName(cert, NID_givenName);
}

std::string
Certificate::getSurname() const
{
	return getName(cert, NID_surname);
}

std::string
Certificate::getSerialNumber() const
{
	return getName(cert, NID_serialNumber);
}

static void *
extension(X509 *x509, int nid )
{
	return X509_get_ext_d2i(x509, nid, nullptr, nullptr);
}


std::vector<std::string>
Certificate::policies() const
{
    constexpr int PolicyBufferLen = 50;

	X509 *peerCert = Crypto::toX509(cert);
	if(!peerCert) return {};

	stack_st_POLICYINFO *cp = (stack_st_POLICYINFO *) extension(peerCert, NID_certificate_policies);
	if(!cp) {
		X509_free(peerCert);
		return {};
	}

	std::vector<std::string> list;
	for(int i = 0; i < sk_POLICYINFO_num(cp); i++) {
		POLICYINFO *pi = sk_POLICYINFO_value(cp, i);
        char buf[PolicyBufferLen + 1]{};
        int len = OBJ_obj2txt(buf, PolicyBufferLen, pi->policyid, 1);
		if(len != NID_undef) {
			list.push_back(std::string(buf));
		}
	}

	CERTIFICATEPOLICIES_free((CERTIFICATEPOLICIES *) cp);
	X509_free(peerCert);

	return list;
}

std::vector<uint8_t>
Certificate::getPublicKey() const
{
	X509 *x509 = Crypto::toX509(cert);
	if(!x509) return {};

	EVP_PKEY *pkey = X509_get0_pubkey(x509);
	int plen = i2d_PublicKey(pkey, nullptr);
	std::vector<uint8_t> pdata(plen);
	uint8_t *pptr = pdata.data();
	i2d_PublicKey(pkey, &pptr);

	X509_free(x509);

	return pdata;
}

Certificate::Algorithm
Certificate::getAlgorithm() const
{
	X509 *x509 = Crypto::toX509(cert);
	if(!x509) return {};

	EVP_PKEY *pkey = X509_get0_pubkey(x509);
	int alg = EVP_PKEY_get_base_id(pkey);

	X509_free(x509);

	return (alg == EVP_PKEY_RSA) ? Algorithm::RSA : Algorithm::ECC;
}

std::vector<uint8_t> Certificate::getDigest()
{
    X509* x509 = Crypto::toX509(cert);
    if(!x509)
        return {};

    const EVP_MD* digest_type = EVP_get_digestbyname("sha1");

    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;

    if (X509_digest(x509, digest_type, digest.data(), &digest_len))
    {
        digest.resize(digest_len);
    }
    else
    {
        digest.clear();
    }

    X509_free(x509);

    return digest;
}

} // namespace libcdoc
