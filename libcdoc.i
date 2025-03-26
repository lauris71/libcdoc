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

%module(directors="1") CDoc

%{
#include "CDoc.h"
#include "Io.h"
#include "Configuration.h"
#include "CDocWriter.h"
#include "CDocReader.h"
#include "Lock.h"
#include "NetworkBackend.h"
#include "PKCS11Backend.h"
#include "Recipient.h"
#include "Utils.h"
#include "Wrapper.h"
#include <iostream>
%}

// Handle standard C++ types
%include "std_string.i"
%include "std_vector.i"
//%include "std_map.i"

%include "typemaps.i"

%ignore libcdoc::MultiDataSource;
%ignore libcdoc::MultiDataConsumer;
%ignore libcdoc::ChainedConsumer;
%ignore libcdoc::ChainedSource;
%ignore libcdoc::IStreamSource;
%ignore libcdoc::OStreamConsumer;
%ignore libcdoc::VectorConsumer;
%ignore libcdoc::VectorSource;
%ignore libcdoc::FileListConsumer;
%ignore libcdoc::FileListSource;

%ignore libcdoc::CDocWriter::createWriter(int version, DataConsumer *dst, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
%ignore libcdoc::CDocWriter::createWriter(int version, std::ostream& ofs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
%ignore libcdoc::CDocWriter::encrypt(MultiDataSource& src, const std::vector<libcdoc::Recipient>& recipients);

%ignore libcdoc::CDocReader::getFMK(std::vector<uint8_t>& fmk, const libcdoc::Lock& lock);
%ignore libcdoc::CDocReader::nextFile(std::string& name, int64_t& size);
%ignore libcdoc::CDocReader::getLockForCert(Lock& lock, const std::vector<uint8_t>& cert);
%ignore libcdoc::CDocReader::decrypt(const std::vector<uint8_t>& fmk, MultiDataConsumer *consumer);
%ignore libcdoc::CDocReader::createReader(std::istream& ifs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);

%ignore libcdoc::Configuration::KEYSERVER_SEND_URL;
%ignore libcdoc::Configuration::KEYSERVER_FETCH_URL;
%ignore libcdoc::Configuration::SHARE_SERVER_URLS;
%ignore libcdoc::Configuration::SHARE_SIGNER;
%ignore libcdoc::Configuration::SID_DOMAIN;
%ignore libcdoc::Configuration::MID_DOMAIN;
%ignore libcdoc::Configuration::BASE_URL;
%ignore libcdoc::Configuration::RP_UUID;
%ignore libcdoc::Configuration::RP_NAME;
%ignore libcdoc::Configuration::PHONE_NUMBER;

%ignore libcdoc::PKCS11Backend::Handle;
%ignore libcdoc::PKCS11Backend::findCertificates(const std::string& label);
%ignore libcdoc::PKCS11Backend::findSecretKeys(const std::string& label);
%ignore libcdoc::PKCS11Backend::findCertificates(const std::vector<uint8_t>& public_key);
%ignore libcdoc::PKCS11Backend::getCertificate(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);
%ignore libcdoc::PKCS11Backend::getPublicKey(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);

#ifdef SWIGJAVA
%include "arrays_java.i"
%include "enums.swg"
%javaconst(1);

%apply long long { libcdoc::result_t }
%apply long long { int64_t }
%apply long long { uint64_t }
%apply int { int32_t }
%apply int { unsigned int }

%typemap(javaout, throws="CDocException") libcdoc::result_t %{
{
    long result = $jnicall;
    if (result < CDoc.END_OF_STREAM) throw new CDocException((int) result, this.getLastErrorStr((int) result));
    return result;
}
%}

%typemap(javadirectorout, throws="CDocException") libcdoc::result_t "$javacall"

//
// const uint8_t *src <- byte[]
//

%typemap(in, throws="CDocException") (const uint8_t *src) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
%}
%typemap(javain) const uint8_t *src "$javainput"
%typemap(jni) const uint8_t *src "jbyteArray"
%typemap(jtype) const uint8_t *src "byte[]"
%typemap(jstype) const uint8_t *src "byte[]"

//
// const uint8_t *src, size_t len <- byte[]
//

%typemap(in, throws="CDocException") (const uint8_t *src, size_t size) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
    $2 = jenv->GetArrayLength($input);
%}
%typemap(javain) (const uint8_t *src, size_t size) "$javainput"
%typemap(jni) (const uint8_t *src, size_t size) "jbyteArray"
%typemap(jtype) (const uint8_t *src, size_t size) "byte[]"
%typemap(jstype) (const uint8_t *src, size_t size) "byte[]"

//
// uint8_t *dst, size_t size <- byte[]
//

%typemap(in, throws="CDocException") (uint8_t *dst, size_t size) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
    $2 = jenv->GetArrayLength($input);
%}
%typemap(freearg) (uint8_t *dst, size_t size) %{
    jenv->ReleaseByteArrayElements($input, (jbyte *) $1, 0);
%}
%typemap(javain) (uint8_t *dst, size_t size) "$javainput"
%typemap(jni) (uint8_t *dst, size_t size) "jbyteArray"
%typemap(jtype) (uint8_t *dst, size_t size) "byte[]"
%typemap(jstype) (uint8_t *dst, size_t size) "byte[]"
%typemap(directorin,descriptor="[B") (uint8_t *dst, size_t size) %{
    // (uint8_t *dst, size_t size) directorin

    // Use scope guard to read back after Java call
    auto del = [&] (jbyteArray *ba) {
        // std::cerr << "deleting Byte array\n";
        uint8_t *data = (uint8_t *) jenv->GetByteArrayElements(*ba, NULL);
        memcpy($1, data, $2);
        jenv->ReleaseByteArrayElements(*ba, (jbyte *) data, 0);
    };
    std::unique_ptr<jbyteArray, decltype(del)> $1_ba(new jbyteArray, del);
    *$1_ba = jenv->NewByteArray($2);
    $input = *$1_ba;
%}
%typemap(javadirectorin) (uint8_t *dst, size_t size) "$jniinput"

//
// std::vector<uint8_t> <-> byte[]
//

%fragment("SWIG_VectorUnsignedCharToJavaArray", "header") {
static jbyteArray SWIG_VectorUnsignedCharToJavaArray(JNIEnv *jenv, const std::vector<unsigned char> &data) {
    jbyteArray jresult = jenv->NewByteArray(data.size());
    if(jresult)
        jenv->SetByteArrayRegion(jresult, 0, data.size(), (const jbyte*)data.data());
    return jresult;
}}
%fragment("SWIG_JavaArrayToVectorUnsignedChar", "header") {
static std::vector<unsigned char> SWIG_JavaArrayToVectorUnsignedChar(JNIEnv *jenv, jbyteArray data) {
    std::vector<unsigned char> result(jenv->GetArrayLength(data));
    jenv->GetByteArrayRegion(data, 0, result.size(), (jbyte*)result.data());
    return result;
}}
%typemap(out, fragment="SWIG_VectorUnsignedCharToJavaArray") std::vector<uint8_t>
%{ jresult = SWIG_VectorUnsignedCharToJavaArray(jenv, result); // std::vector<uint8_t> out %}
%typemap(out, fragment="SWIG_VectorUnsignedCharToJavaArray") std::vector<uint8_t>&
%{ jresult = SWIG_VectorUnsignedCharToJavaArray(jenv, *result); // std::vector<uint8_t>& out %}
%typemap(in, fragment="SWIG_JavaArrayToVectorUnsignedChar") std::vector<uint8_t>
%{ $1 = SWIG_JavaArrayToVectorUnsignedChar(jenv, $input); // std::vector<uint8_t> in %}
%typemap(in) std::vector<uint8_t>& %{
    std::vector<uint8_t> $1_vec = SWIG_JavaArrayToVectorUnsignedChar(jenv, $input); //  std::vector<uint8_t>& in
    $1 = &$1_vec;
%}
%typemap(jtype) std::vector<uint8_t>, std::vector<uint8_t>& "byte[]"
%typemap(jstype) std::vector<uint8_t>, std::vector<uint8_t>& "byte[]"
%typemap(jni) std::vector<uint8_t>, std::vector<uint8_t>& "jbyteArray"
%typemap(javaout) std::vector<uint8_t>, std::vector<uint8_t>& {
    return $jnicall;
}
%typemap(freearg) std::vector<uint8_t>, std::vector<uint8_t>&
%{ // std::vector<uint8_t>, std::vector<uint8_t>& freearg %}
%typemap(javain) std::vector<uint8_t>, std::vector<uint8_t>& "$javainput"
%typemap(directorin,descriptor="[B") std::vector<uint8_t>, std::vector<uint8_t>& %{
    $input = jenv->NewByteArray($1.size());
    jenv->SetByteArrayRegion($input, 0, $1.size(), (const jbyte*)$1.data());
%}
%typemap(javadirectorin) std::vector<uint8_t>, std::vector<uint8_t>& "$jniinput"
%apply std::vector<uint8_t>& { const std::vector<uint8_t>& }

//
// std::vector<uint8_t>& dst <-> DataBuffer
//

%typemap(out) std::vector<uint8_t>& dst %{
    // DataBuffer out
%}
%typemap(freearg) std::vector<uint8_t>& dst %{
    // DataBuffer freearg
%}
%typemap(in) std::vector<uint8_t>& dst %{
    // DataBuffer in
    jclass $1_class = jenv->FindClass("ee/ria/cdoc/DataBuffer");
    jmethodID $1_mid = jenv->GetStaticMethodID($1_class, "getCPtr", "(Lee/ria/cdoc/DataBuffer;)J");
    jlong $1_cptr = jenv->CallStaticLongMethod($1_class, $1_mid, $input);
    libcdoc::DataBuffer *$1_db = (libcdoc::DataBuffer *) $1_cptr;
    $1 = $1_db->data;
%}
%typemap(jtype) std::vector<uint8_t>& dst "DataBuffer"
%typemap(jstype) std::vector<uint8_t>& dst "DataBuffer"
%typemap(jni) std::vector<uint8_t>& dst "jobject"
%typemap(javaout) std::vector<uint8_t>& dst "$jnicall"
%typemap(javain) std::vector<uint8_t>& dst "$javainput"
%typemap(directorin,descriptor="Lee/ria/cdoc/DataBuffer;") std::vector<uint8_t>& dst %{
    // DataBuffer directorin

    // Use scope guard to reset DataBuffer after Java call
    auto del = [&] (libcdoc::DataBuffer *db) {
        // std::cerr << "deleting DataBuffer\n";
        db->reset();
    };
    std::unique_ptr<libcdoc::DataBuffer, decltype(del)> $1_db(new libcdoc::DataBuffer(&$1), del);

    jclass buf_class = jenv->FindClass("ee/ria/cdoc/DataBuffer");
    jmethodID mid = jenv->GetMethodID(buf_class, "<init>", "(JZ)V");
    jobject obj = jenv->NewObject(buf_class, mid, (jlong) $1_db.get(), JNI_FALSE);
    $input = obj;
%}
%typemap(directorout) std::vector<uint8_t>& dst %{
    // DataBuffer directorout
%}
%typemap(javadirectorin) std::vector<uint8_t>& dst "$jniinput"
%typemap(javadirectorout) std::vector<uint8_t>& dst %{
    // DataBuffer javadirectorout
    $javacall
%}

//
// std::vector<std::string>& <- String[]
//

%typemap(in) std::vector<std::string>& %{
    // std::vector<std::string>& in
    jsize $input_size = jenv->GetArrayLength($input);
    std::vector<std::string> $1_vec;
    for (jsize i = 0; i < $input_size; i++) {
        jstring jstr = (jstring) jenv->GetObjectArrayElement($input, i);
        const char *chars = jenv->GetStringUTFChars(jstr, nullptr);
        $1_vec.push_back(chars);
        jenv->ReleaseStringUTFChars(jstr, chars);
    }
    $1 = &$1_vec;
%}
%typemap(jtype) std::vector<std::string>& "String[]"
%typemap(jstype) std::vector<std::string>& "String[]"
%typemap(jni) std::vector<std::string>& "jobjectArray"
%typemap(javain) std::vector<std::string>& "$javainput"

//
// std::map<std::string, std::string> -> java.util.Map<String,String>
//

%typemap(out) std::map<std::string, std::string> %{
    jclass map_class = jenv->FindClass("java/util/Hashtable");
    std::cerr << "Map class:" << (void *) map_class << std::endl;
    jmethodID mid_new = jenv->GetMethodID(map_class, "<init>", "()V");
    std::cerr << "Mid_new:" << mid_new << std::endl;
    jmethodID mid_put = jenv->GetMethodID(map_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    std::cerr << "Mid_put:" << mid_put << std::endl;
    jobject map = jenv->NewObject(map_class, mid_new);
    std::cerr << "Map:" << (void *) map << std::endl;
    for(auto pair : *(&result)) {
        jstring key = jenv->NewStringUTF(pair.first.c_str());
        jstring val = jenv->NewStringUTF(pair.second.c_str());
        jenv->CallObjectMethod(map, mid_put, key, val);
    }
    jresult = map;
%}
%typemap(jtype) std::map<std::string, std::string> "java.util.Map<String,String>"
%typemap(jstype) std::map<std::string, std::string> "java.util.Map<String,String>"
%typemap(jni) std::map<std::string, std::string> "jobject"
%typemap(javaout) std::map<std::string, std::string> {
    return $jnicall;
}

//
// std::vector<std::vector<uint8_t>> <- CertificateList
//

%typemap(in) std::vector<std::vector<uint8_t>>& %{
    // CertificateList in
    std::cerr << "%typemap(in) std::vector<std::vector<uint8_t>>&" << std::endl;
    jclass $1_class = jenv->FindClass("ee/ria/cdoc/CertificateList");
    jmethodID $1_mid = jenv->GetStaticMethodID($1_class, "getCPtr", "(Lee/ria/cdoc/CertificateList;)J");
    jlong $1_cptr = jenv->CallStaticLongMethod($1_class, $1_mid, $input);
    libcdoc::CertificateList *$1_db = (libcdoc::CertificateList *) $1_cptr;
    $1 = $1_db->data;
%}
%typemap(freearg) std::vector<std::vector<uint8_t>>& %{
    // std::vector<std::vector<uint8_t>>& freearg
%}
%typemap(jtype) std::vector<std::vector<uint8_t>>& "CertificateList"
%typemap(jstype) std::vector<std::vector<uint8_t>>& "CertificateList"
%typemap(jni) std::vector<std::vector<uint8_t>>& "jobject"
%typemap(javain) std::vector<std::vector<uint8_t>>& "$javainput"

%typemap(directorin,descriptor="Lee/ria/cdoc/CertificateList;") std::vector<std::vector<uint8_t>>& %{
    // CertificateList directorin

    // Use scope guard to reset CertificateList after Java call
    auto del = [&] (libcdoc::CertificateList *db) {
        // std::cerr << "deleting CertificateList\n";
        db->reset();
    };
    std::unique_ptr<libcdoc::CertificateList, decltype(del)> $1_db(new libcdoc::CertificateList(&$1), del);

    jclass buf_class = jenv->FindClass("ee/ria/cdoc/CertificateList");
    jmethodID mid = jenv->GetMethodID(buf_class, "<init>", "(JZ)V");
    jobject obj = jenv->NewObject(buf_class, mid, (jlong) $1_db.get(), JNI_FALSE);
    $input = obj;
%}
%typemap(directorout) std::vector<std::vector<uint8_t>>& %{
    std::cerr << "%typemap(directorout) std::vector<std::vector<uint8_t>>&" << std::endl;
    // std::vector<std::vector<uint8_t>>& directorout
%}
%typemap(javadirectorin) std::vector<std::vector<uint8_t>>& "$jniinput"
%typemap(javadirectorout) std::vector<std::vector<uint8_t>>& %{
    // std::vector<std::vector<uint8_t>>& javadirectorout
    $javacall
%}

//
// std::string_view -> String
//

%typemap(in) std::string_view %{
    const char *$1_utf8 = jenv->GetStringUTFChars($input, nullptr);
    $1 = $1_utf8;
%}
%typemap(freearg) std::string_view %{
    jenv->ReleaseStringUTFChars($input, $1_utf8);
%}
//%typemap(out) std::string_view %{
//    std::string $1_str(*(&result));
//    jresult = jenv->NewStringUtf($1_str.c_str());
//%}
%typemap(jtype) std::string_view "String"
%typemap(jstype) std::string_view "String"
%typemap(jni) std::string_view "jstring"
%typemap(javain) std::string_view "$javainput"
//%typemap(javaout) std::string_view %{
//    return $jnicall;
//%}
%typemap(directorin,descriptor="Ljava/lang/String;") std::string_view %{
    std::string $1_str($1);
    $input = jenv->NewStringUTF($1_str.c_str());
%}
// No return of std::string_view so no directorout
%typemap(javadirectorin) std::string_view "$jniinput"
// No return of std::string_view so no javadirectorout

//
// CDocWriter
//

%extend libcdoc::CDocWriter {
    int64_t writeData(const uint8_t *src, size_t pos, size_t size) {
        return $self->writeData(src + pos, size);
    }
};

//
// CDocReader
//

// Use LockVector object to encapsulate the vector of locks
%template(LockVector) std::vector<libcdoc::Lock>;

// Custom wrapper do away with const qualifiers
%extend libcdoc::CDocReader {
    std::vector<libcdoc::Lock> getLocks() {
        static const std::vector<libcdoc::Lock> locks = $self->getLocks();
        std::vector<libcdoc::Lock> p(locks.cbegin(), locks.cend());
        return std::move(p);
    }
    std::vector<uint8_t> getFMK(unsigned int lock_idx) {
        std::vector<uint8_t> fmk;
        $self->getFMK(fmk, lock_idx);
        return fmk;
    }
};
%ignore libcdoc::CDocReader::getLocks();

%typemap(javacode) libcdoc::CDocReader %{
    public void readFile(java.io.OutputStream ofs) throws CDocException, java.io.IOException {
        byte[] buf = new byte[1024];
        long result = readData(buf);
        while(result > 0) {
            ofs.write(buf, 0, (int) result);
            result = readData(buf);
        }
    }
%}

//
// DataBuffer
//

%ignore libcdoc::DataBuffer::data;
%ignore libcdoc::DataBuffer::DataBuffer(std::vector<uint8_t> *_data);
%ignore libcdoc::DataBuffer::reset();

//
// DataConsumer
//

%ignore libcdoc::DataConsumer::write(const std::vector<uint8_t>& src);

//
// CertificateList
//

%ignore libcdoc::CertificateList::data;
%ignore libcdoc::CertificateList::CertificateList(std::vector<std::vector<uint8_t>> *_data);
%ignore libcdoc::CertificateList::reset();
%ignore libcdoc::CertificateList::setData(const std::vector<std::vector<uint8_t>>& _data);
%ignore libcdoc::CertificateList::getData();

//
// Recipient
//

%ignore libcdoc::Recipient::rcpt_key;
%ignore libcdoc::Recipient::cert;
%ignore libcdoc::Recipient::buildLabel(std::vector<std::pair<std::string_view, std::string_view>> components);
%extend libcdoc::Recipient {
    std::vector<uint8_t> getRcptKey() {
        return $self->rcpt_key;
    }
    void setRcptKey(const std::vector<uint8_t>& key) {
        $self->rcpt_key = key;
    }
    std::vector<uint8_t> getCert() {
        return $self->cert;
    }
    void setCert(const std::vector<uint8_t>& value) {
        $self->cert = value;
    }
    static std::string buildLabel(const std::vector<std::string>& values) {
        std::vector<std::pair<std::string_view, std::string_view>> vec;
        for (size_t i = 0; (i + 1) < values.size(); i += 2) {
            vec.push_back({values[i], values[i + 1]});
        }
        return libcdoc::Recipient::buildLabel(vec);
    }
};

//
// Lock
//

%ignore libcdoc::Lock::Lock;
%ignore libcdoc::Lock::type;
%ignore libcdoc::Lock::pk_type;
%ignore libcdoc::Lock::label;
%ignore libcdoc::Lock::encrypted_fmk;
%ignore libcdoc::Lock::setBytes;
%ignore libcdoc::Lock::setString;
%ignore libcdoc::Lock::setInt;
%ignore libcdoc::Lock::setCertificate;
%extend libcdoc::Lock {
    Type getType() {
        return $self->type;
    }
    PKType getPKType() {
        return $self->pk_type;
    }
    std::string getLabel() {
        return $self->label;
    }
    std::vector<uint8_t> getEncryptedFMK() {
        return $self->encrypted_fmk;
    }
}

//
// Configuration
//

%ignore libcdoc::JSONConfiguration::JSONConfiguration(std::istream& ifs);
%ignore libcdoc::JSONConfiguration::parse(std::istream& ifs);

%typemap(javacode) libcdoc::Configuration %{
    public static final String KEYSERVER_SEND_URL = "KEYSERVER_SEND_URL";
    public static final String KEYSERVER_FETCH_URL = "KEYSERVER_FETCH_URL";
    public static final String SHARE_SERVER_URLS = "SHARE_SERVER_URLS";
    public static final String SHARE_SIGNER = "SHARE_SIGNER";
    public static final String SID_DOMAIN = "SMART_ID";
    public static final String MID_DOMAIN = "MOBILE_ID";
    public static final String BASE_URL = "BASE_URL";
    public static final String RP_UUID = "RP_UUID";
    public static final String RP_NAME = "RP_NAME";
    public static final String PHONE_NUMBER = "PHONE_NUMBER";
%}

//
// CryptoBackend
//

//
// NetworkBackend
//

%ignore libcdoc::NetworkBackend::ShareInfo::share;
%extend libcdoc::NetworkBackend::ShareInfo {
    std::vector<uint8_t> getShare() {
        return $self->share;
    }
    void setShare(const std::vector<uint8_t>& share) {
        $self->share = share;
    }
};

%typemap(javaimports) ArrayList<byte[]> %{
    import java.util.ArrayList;
%}

%typemap(javaimports) std::vector<std::vector<uint8_t>>& %{
    import java.util.ArrayList;
%}
%typemap(javaimports) libcdoc::NetworkBackend %{
    import java.util.ArrayList;
%}

%feature("director") libcdoc::DataSource;
%feature("director") libcdoc::CryptoBackend;
%feature("director") libcdoc::PKCS11Backend;
%feature("director") libcdoc::NetworkBackend;
%feature("director") libcdoc::Configuration;
#endif

// Swig does not like visibility/declspec attributes
#define CDOC_EXPORT
// fixme: Remove this in production
#define LIBCDOC_TESTING 1
#define CDOC_DISABLE_MOVE(X)

%include "CDoc.h"
%include "Wrapper.h"
%include "Io.h"
%include "Recipient.h"
%include "Lock.h"
%include "Configuration.h"
%include "CryptoBackend.h"
%include "NetworkBackend.h"
%include "PKCS11Backend.h"

#ifdef SWIGJAVA
%typemap(javaout, throws="CDocException") libcdoc::result_t %{
                                                            {
                                                             long result = $jnicall;
if (result < CDoc.END_OF_STREAM) throw new CDocException((int) result, this.getLastErrorStr());
return result;
}
%}

#endif

%include "CDocReader.h"
%include "CDocWriter.h"

#ifdef SWIGJAVA
#endif
