// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

/* -----------------------------------------------------------------------------
 * std_map_string_view.i
 *
 * Typemaps for std::map<std::string_view, std::string_view>
 * These are mapped to a Java Map<String,String> and are passed by value.
 *
 * Because std::string_view does not own its character data, the "in" typemap
 * first copies the Java strings into a temporary std::map<std::string,
 * std::string> (whose nodes have stable addresses) and then builds the
 * string_view map referencing that storage. The temporary lives until the
 * end of the wrapper call, which is sufficient for by-value parameters.
 *
 * Strings are converted via java.lang.String getBytes/new String with
 * StandardCharsets.UTF_8 (SWIG_JavaJstringToUtf8/SWIG_JavaUtf8ToJstring
 * from std_string_utf8.i), so standard UTF-8 content (embedded NUL,
 * supplementary characters) survives intact. Include std_string_utf8.i
 * before this file.
 * ----------------------------------------------------------------------------- */

%{
#include <map>
#include <string>
#include <string_view>
%}

%typemap(jni) std::map<std::string_view, std::string_view> "jobject"
%typemap(jtype) std::map<std::string_view, std::string_view> "java.util.Map<String,String>"
%typemap(jstype) std::map<std::string_view, std::string_view> "java.util.Map<String,String>"

// Java Map -> C++ std::map<std::string_view, std::string_view>
//
// Note: $1 must be assigned as a whole (not populated through &$1) because
// SWIG passes class-type by-value parameters through SwigValueWrapper, which
// allocates the underlying object on assignment.
//
// The temporaries are declared inside the typemap body (not in the
// parenthesized declaration list after the typemap name) because some SWIG
// versions only emit the first variable from a multi-variable declaration,
// causing "not declared in this scope" errors.
%typemap(in) std::map<std::string_view, std::string_view> %{
    std::map<std::string, std::string> arg_store;
    std::map<std::string_view, std::string_view> arg_view;
    if (!$input) {
        SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null map");
        return $null;
    }
    {
        jclass map_class = jenv->FindClass("java/util/Map");
        jmethodID mid_entrySet = jenv->GetMethodID(map_class, "entrySet", "()Ljava/util/Set;");
        jobject entry_set = jenv->CallObjectMethod($input, mid_entrySet);
        jclass set_class = jenv->FindClass("java/util/Set");
        jmethodID mid_iterator = jenv->GetMethodID(set_class, "iterator", "()Ljava/util/Iterator;");
        jobject iterator = jenv->CallObjectMethod(entry_set, mid_iterator);
        jclass iter_class = jenv->FindClass("java/util/Iterator");
        jmethodID mid_hasNext = jenv->GetMethodID(iter_class, "hasNext", "()Z");
        jmethodID mid_next = jenv->GetMethodID(iter_class, "next", "()Ljava/lang/Object;");
        jclass entry_class = jenv->FindClass("java/util/Map$Entry");
        jmethodID mid_getKey = jenv->GetMethodID(entry_class, "getKey", "()Ljava/lang/Object;");
        jmethodID mid_getValue = jenv->GetMethodID(entry_class, "getValue", "()Ljava/lang/Object;");
        while (jenv->CallBooleanMethod(iterator, mid_hasNext)) {
            jobject entry = jenv->CallObjectMethod(iterator, mid_next);
            jstring jkey = (jstring) jenv->CallObjectMethod(entry, mid_getKey);
            jstring jval = (jstring) jenv->CallObjectMethod(entry, mid_getValue);
            arg_store.emplace(SWIG_JavaJstringToUtf8(jenv, jkey), SWIG_JavaJstringToUtf8(jenv, jval));
            jenv->DeleteLocalRef(jkey);
            jenv->DeleteLocalRef(jval);
            jenv->DeleteLocalRef(entry);
        }
        if (jenv->ExceptionCheck()) return $null;
    }
    // std::map nodes are stable, so string_views into arg_store stay valid
    // for the duration of the wrapped call.
    for (const auto& [key, value] : arg_store) {
        arg_view.emplace(key, value);
    }
    $1 = arg_view;
%}

// C++ std::map<std::string_view, std::string_view> -> Java Map
%typemap(out) std::map<std::string_view, std::string_view> %{
    jclass map_class = jenv->FindClass("java/util/HashMap");
    jmethodID mid_new = jenv->GetMethodID(map_class, "<init>", "()V");
    jmethodID mid_put = jenv->GetMethodID(map_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject map = jenv->NewObject(map_class, mid_new);
    for (const auto& [key, value] : result) {
        jstring jkey = SWIG_JavaUtf8ToJstring(jenv, key.data(), key.size());
        jstring jval = SWIG_JavaUtf8ToJstring(jenv, value.data(), value.size());
        jenv->CallObjectMethod(map, mid_put, jkey, jval);
        jenv->DeleteLocalRef(jkey);
        jenv->DeleteLocalRef(jval);
    }
    jresult = map;
%}

%typemap(javain) std::map<std::string_view, std::string_view> "$javainput"

%typemap(javaout) std::map<std::string_view, std::string_view> {
    return $jnicall;
}

%typemap(typecheck) std::map<std::string_view, std::string_view> %{
    /* Accept any java.util.Map */
    {
        jclass map_class = jenv->FindClass("java/util/Map");
        $1 = jenv->IsInstanceOf($input, map_class) ? 1 : 0;
    }
%}
