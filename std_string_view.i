/* -----------------------------------------------------------------------------
 * std_string_view.i
 *
 * Typemaps for std::string_view and const std::string_view&
 * These are mapped to a Java String and are passed around by value.
 *
 * This is a project-local variant of the SWIG library file (kept because
 * older SWIG versions, e.g. on Ubuntu 22, did not ship it). Unlike the
 * upstream version, strings cross the JNI boundary as byte[] and are
 * converted with java.lang.String/StandardCharsets.UTF_8, so standard
 * UTF-8 content (embedded NUL, supplementary characters) survives intact.
 *
 * To use non-const std::string_view references use the following %apply.  Note
 * that they are passed by value.
 * %apply const std::string_view & {std::string_view &};
 *
 * Requires std_string_utf8.i to be included first (helper functions).
 * ----------------------------------------------------------------------------- */

%{
#include <string_view>
#include <string>
%}

namespace std {

%naturalvar string_view;

class string_view;

// string_view
%typemap(jni) string_view "jbyteArray"
%typemap(jtype) string_view "byte[]"
%typemap(jstype) string_view "String"
%typemap(javadirectorin) string_view "$jniinput == null ? null : new String($jniinput, java.nio.charset.StandardCharsets.UTF_8)"
%typemap(javadirectorout) string_view "$javacall == null ? null : $javacall.getBytes(java.nio.charset.StandardCharsets.UTF_8)"

%typemap(in) string_view
%{ if (!$input) {
     SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
     return $null;
   }
   jsize $1_len = jenv->GetArrayLength($input);
   jbyte *$1_buf = jenv->GetByteArrayElements($input, nullptr);
   if (!$1_buf) return $null;
   $1 = std::string_view((const char *) $1_buf, $1_len); %}

/* std::string_view requires the string data to remain valid while the
 * string_view is in use. The byte array elements are released after the
 * wrapped call. */
%typemap(freearg) string_view
%{ jenv->ReleaseByteArrayElements($input, $1_buf, JNI_ABORT); %}

%typemap(directorout,warning=SWIGWARN_TYPEMAP_THREAD_UNSAFE_MSG) string_view
%{ if ($input) {
     jsize $1_len = jenv->GetArrayLength($input);
     jbyte *$1_buf = jenv->GetByteArrayElements($input, nullptr);
     if (!$1_buf) return $null;
     /* possible thread/reentrant code problem */
     thread_local std::string $1_str;
     $1_str.assign((const char *) $1_buf, $1_len);
     $result = std::string_view($1_str);
     jenv->ReleaseByteArrayElements($input, $1_buf, JNI_ABORT);
   } %}

%typemap(directorin,descriptor="[B") string_view
%{ $input = jenv->NewByteArray((jsize) $1.size());
   if ($input) {
     jenv->SetByteArrayRegion($input, 0, (jsize) $1.size(), (const jbyte *) $1.data());
     Swig::LocalRefGuard $1_refguard(jenv, $input);
   } %}

%typemap(out) string_view
%{ $result = jenv->NewByteArray((jsize) $1.size());
   if ($result) jenv->SetByteArrayRegion($result, 0, (jsize) $1.size(), (const jbyte *) $1.data()); %}

%typemap(javain) string_view "$javainput == null ? null : $javainput.getBytes(java.nio.charset.StandardCharsets.UTF_8)"

%typemap(javaout) string_view {
    byte[] b = $jnicall;
    return b == null ? null : new String(b, java.nio.charset.StandardCharsets.UTF_8);
  }

%typecheck(SWIG_TYPECHECK_INT8_ARRAY) string_view ""

%typemap(throws) string_view
%{ SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, std::string($1).c_str());
   return $null; %}

// const string_view &
%typemap(jni) const string_view & "jbyteArray"
%typemap(jtype) const string_view & "byte[]"
%typemap(jstype) const string_view & "String"
%typemap(javadirectorin) const string_view & "$jniinput == null ? null : new String($jniinput, java.nio.charset.StandardCharsets.UTF_8)"
%typemap(javadirectorout) const string_view & "$javacall == null ? null : $javacall.getBytes(java.nio.charset.StandardCharsets.UTF_8)"

%typemap(in) const string_view &
%{ if (!$input) {
     SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
     return $null;
   }
   jsize $1_len = jenv->GetArrayLength($input);
   jbyte *$1_buf = jenv->GetByteArrayElements($input, nullptr);
   if (!$1_buf) return $null;
   $*1_ltype $1_strview((const char *) $1_buf, $1_len);
   $1 = &$1_strview; %}

/* std::string_view requires the string data to remain valid while the
 * string_view is in use. */
%typemap(freearg) const string_view &
%{ jenv->ReleaseByteArrayElements($input, $1_buf, JNI_ABORT); %}

%typemap(directorout,warning=SWIGWARN_TYPEMAP_THREAD_UNSAFE_MSG) const string_view &
%{ if ($input) {
     jsize $1_len = jenv->GetArrayLength($input);
     jbyte *$1_buf = jenv->GetByteArrayElements($input, nullptr);
     if (!$1_buf) return $null;
     /* possible thread/reentrant code problem */
     thread_local std::string $1_str;
     $1_str.assign((const char *) $1_buf, $1_len);
     thread_local $*1_ltype $1_strview;
     $1_strview = $1_str;
     $result = &$1_strview;
     jenv->ReleaseByteArrayElements($input, $1_buf, JNI_ABORT);
   } %}

%typemap(directorin,descriptor="[B") const string_view &
%{ $input = jenv->NewByteArray((jsize) $1.size());
   if ($input) {
     jenv->SetByteArrayRegion($input, 0, (jsize) $1.size(), (const jbyte *) $1.data());
     Swig::LocalRefGuard $1_refguard(jenv, $input);
   } %}

%typemap(out) const string_view &
%{ $result = jenv->NewByteArray((jsize) $1->size());
   if ($result) jenv->SetByteArrayRegion($result, 0, (jsize) $1->size(), (const jbyte *) $1->data()); %}

%typemap(javain) const string_view & "$javainput == null ? null : $javainput.getBytes(java.nio.charset.StandardCharsets.UTF_8)"

%typemap(javaout) const string_view & {
    byte[] b = $jnicall;
    return b == null ? null : new String(b, java.nio.charset.StandardCharsets.UTF_8);
  }

%typecheck(SWIG_TYPECHECK_INT8_ARRAY) const string_view & ""

%typemap(throws) const string_view &
%{ SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, std::string($1).c_str());
   return $null; %}

}
