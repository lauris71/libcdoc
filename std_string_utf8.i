/* -----------------------------------------------------------------------------
 * std_string_utf8.i
 *
 * Typemaps for std::string and const std::string& that transport standard
 * UTF-8 (as used by libcdoc) instead of JNI's modified UTF-8 (CESU-8).
 *
 * JNI's GetStringUTFChars/NewStringUTF use modified UTF-8: NUL is encoded
 * as a 2-byte sequence and supplementary characters (above U+FFFF) as two
 * 3-byte surrogate encodings. libcdoc stores labels and file names as
 * standard UTF-8, so such strings were corrupted (or crashed the JVM).
 *
 * These typemaps convert in two steps:
 *   C++ std::string <-> Java byte[]   (raw bytes over the JNI boundary)
 *   Java byte[] <-> Java String       (java.lang.String with
 *                                      StandardCharsets.UTF_8)
 *
 * This file also defines the SWIG_JavaUtf8* helper functions used by
 * std_string_view.i and std_map_string_view.i - include it before them.
 * ----------------------------------------------------------------------------- */

%{
#include <string>

/* std::string/byte[] <-> jstring conversions using java.lang.String methods,
 * which handle standard UTF-8 (unlike NewStringUTF/GetStringUTFChars). */
static jstring SWIG_JavaUtf8ToJstring(JNIEnv *jenv, const char *data, size_t size) {
    jclass charset_class = jenv->FindClass("java/nio/charset/StandardCharsets");
    jfieldID fid_utf8 = jenv->GetStaticFieldID(charset_class, "UTF_8", "Ljava/nio/charset/Charset;");
    jobject charset = jenv->GetStaticObjectField(charset_class, fid_utf8);
    jbyteArray bytes = jenv->NewByteArray((jsize) size);
    if (!bytes) return nullptr;
    jenv->SetByteArrayRegion(bytes, 0, (jsize) size, (const jbyte *) data);
    jclass str_class = jenv->FindClass("java/lang/String");
    jmethodID mid_new = jenv->GetMethodID(str_class, "<init>", "([BLjava/nio/charset/Charset;)V");
    jstring result = (jstring) jenv->NewObject(str_class, mid_new, bytes, charset);
    jenv->DeleteLocalRef(bytes);
    jenv->DeleteLocalRef(charset);
    return result;
}

static jstring SWIG_JavaUtf8ToJstring(JNIEnv *jenv, const std::string &str) {
    return SWIG_JavaUtf8ToJstring(jenv, str.data(), str.size());
}

static std::string SWIG_JavaJstringToUtf8(JNIEnv *jenv, jstring jstr) {
    jclass charset_class = jenv->FindClass("java/nio/charset/StandardCharsets");
    jfieldID fid_utf8 = jenv->GetStaticFieldID(charset_class, "UTF_8", "Ljava/nio/charset/Charset;");
    jobject charset = jenv->GetStaticObjectField(charset_class, fid_utf8);
    jclass str_class = jenv->FindClass("java/lang/String");
    jmethodID mid_getBytes = jenv->GetMethodID(str_class, "getBytes", "(Ljava/nio/charset/Charset;)[B");
    jbyteArray bytes = (jbyteArray) jenv->CallObjectMethod(jstr, mid_getBytes, charset);
    if (!bytes) return {};
    jsize len = jenv->GetArrayLength(bytes);
    jbyte *buf = jenv->GetByteArrayElements(bytes, nullptr);
    std::string result;
    if (buf) {
        result.assign((const char *) buf, len);
        jenv->ReleaseByteArrayElements(bytes, buf, JNI_ABORT);
    }
    jenv->DeleteLocalRef(bytes);
    jenv->DeleteLocalRef(charset);
    return result;
}
%}

// std::string
%typemap(jni) std::string "jbyteArray"
%typemap(jtype) std::string "byte[]"
%typemap(jstype) std::string "String"
%typemap(javadirectorin) std::string "$jniinput == null ? null : new String($jniinput, java.nio.charset.StandardCharsets.UTF_8)"
%typemap(javadirectorout) std::string "$javacall == null ? null : $javacall.getBytes(java.nio.charset.StandardCharsets.UTF_8)"

%typemap(in) std::string
%{ if (!$input) {
     SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
     return $null;
   }
   jsize $1_len = jenv->GetArrayLength($input);
   jbyte *$1_buf = jenv->GetByteArrayElements($input, nullptr);
   if (!$1_buf) return $null;
   $1.assign((const char *) $1_buf, $1_len);
   jenv->ReleaseByteArrayElements($input, $1_buf, JNI_ABORT); %}

%typemap(directorout) std::string
%{ if ($input) {
     jsize $1_len = jenv->GetArrayLength($input);
     jbyte *$1_buf = jenv->GetByteArrayElements($input, nullptr);
     if (!$1_buf) return $null;
     $result.assign((const char *) $1_buf, $1_len);
     jenv->ReleaseByteArrayElements($input, $1_buf, JNI_ABORT);
   } %}

%typemap(directorin,descriptor="[B") std::string
%{ $input = jenv->NewByteArray((jsize) $1.size());
   if ($input) {
     jenv->SetByteArrayRegion($input, 0, (jsize) $1.size(), (const jbyte *) $1.data());
     Swig::LocalRefGuard $1_refguard(jenv, $input);
   } %}

%typemap(out) std::string
%{ $result = jenv->NewByteArray((jsize) $1.size());
   if ($result) jenv->SetByteArrayRegion($result, 0, (jsize) $1.size(), (const jbyte *) $1.data()); %}

%typemap(javain) std::string "$javainput == null ? null : $javainput.getBytes(java.nio.charset.StandardCharsets.UTF_8)"

%typemap(javaout) std::string {
    byte[] b = $jnicall;
    return b == null ? null : new String(b, java.nio.charset.StandardCharsets.UTF_8);
  }

%typecheck(SWIG_TYPECHECK_INT8_ARRAY) std::string ""

%typemap(throws) std::string
%{ SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, $1.c_str());
   return $null; %}

// const std::string &
%typemap(jni) const std::string & "jbyteArray"
%typemap(jtype) const std::string & "byte[]"
%typemap(jstype) const std::string & "String"
%typemap(javadirectorin) const std::string & "$jniinput == null ? null : new String($jniinput, java.nio.charset.StandardCharsets.UTF_8)"
%typemap(javadirectorout) const std::string & "$javacall == null ? null : $javacall.getBytes(java.nio.charset.StandardCharsets.UTF_8)"

%typemap(in) const std::string &
%{ if (!$input) {
     SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
     return $null;
   }
   jsize $1_len = jenv->GetArrayLength($input);
   jbyte *$1_buf = jenv->GetByteArrayElements($input, nullptr);
   if (!$1_buf) return $null;
   $*1_ltype $1_str((const char *) $1_buf, $1_len);
   $1 = &$1_str;
   jenv->ReleaseByteArrayElements($input, $1_buf, JNI_ABORT); %}

%typemap(directorout) const std::string &
%{ if ($input) {
     jsize $1_len = jenv->GetArrayLength($input);
     jbyte *$1_buf = jenv->GetByteArrayElements($input, nullptr);
     if (!$1_buf) return $null;
     /* possible thread/reentrant code problem */
     thread_local $*1_ltype $1_str;
     $1_str.assign((const char *) $1_buf, $1_len);
     $result = &$1_str;
     jenv->ReleaseByteArrayElements($input, $1_buf, JNI_ABORT);
   } %}

%typemap(directorin,descriptor="[B") const std::string &
%{ $input = jenv->NewByteArray((jsize) $1.size());
   if ($input) {
     jenv->SetByteArrayRegion($input, 0, (jsize) $1.size(), (const jbyte *) $1.data());
     Swig::LocalRefGuard $1_refguard(jenv, $input);
   } %}

%typemap(out) const std::string &
%{ $result = jenv->NewByteArray((jsize) $1->size());
   if ($result) jenv->SetByteArrayRegion($result, 0, (jsize) $1->size(), (const jbyte *) $1->data()); %}

%typemap(javain) const std::string & "$javainput == null ? null : $javainput.getBytes(java.nio.charset.StandardCharsets.UTF_8)"

%typemap(javaout) const std::string & {
    byte[] b = $jnicall;
    return b == null ? null : new String(b, java.nio.charset.StandardCharsets.UTF_8);
  }

%typecheck(SWIG_TYPECHECK_INT8_ARRAY) const std::string & ""

%typemap(throws) const std::string &
%{ SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, $1.c_str());
   return $null; %}
