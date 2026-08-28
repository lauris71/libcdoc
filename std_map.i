/* -----------------------------------------------------------------------------
 * std_map.i
 *
 * Typemaps for std::map<std::string, std::string>
 * These are mapped to a Java Map<String,String> and are passed by value.
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
%}

%typemap(jni) std::map<std::string, std::string> "jobject"
%typemap(jtype) std::map<std::string, std::string> "java.util.Map<String,String>"
%typemap(jstype) std::map<std::string, std::string> "java.util.Map<String,String>"

// Java Map -> C++ std::map<std::string, std::string>
//
// Note: $1 must be assigned as a whole (not populated through &$1) because
// SWIG passes class-type by-value parameters through SwigValueWrapper, which
// allocates the underlying object on assignment.
%typemap(in) std::map<std::string, std::string> (
        std::map<std::string, std::string> $1_view) %{
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
            $1_view.emplace(SWIG_JavaJstringToUtf8(jenv, jkey), SWIG_JavaJstringToUtf8(jenv, jval));
            jenv->DeleteLocalRef(jkey);
            jenv->DeleteLocalRef(jval);
            jenv->DeleteLocalRef(entry);
        }
        if (jenv->ExceptionCheck()) return $null;
    }
    $1 = $1_view;
%}

// C++ std::map<std::string, std::string> -> Java Map
%typemap(out) std::map<std::string, std::string> %{
    jclass map_class = jenv->FindClass("java/util/HashMap");
    jmethodID mid_new = jenv->GetMethodID(map_class, "<init>", "()V");
    jmethodID mid_put = jenv->GetMethodID(map_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject map = jenv->NewObject(map_class, mid_new);
    for (const auto& [key, value] : *(&result)) {
        jstring jkey = SWIG_JavaUtf8ToJstring(jenv, key);
        jstring jval = SWIG_JavaUtf8ToJstring(jenv, value);
        jenv->CallObjectMethod(map, mid_put, jkey, jval);
        jenv->DeleteLocalRef(jkey);
        jenv->DeleteLocalRef(jval);
    }
    jresult = map;
%}

%typemap(javain) std::map<std::string, std::string> "$javainput"

%typemap(javaout) std::map<std::string, std::string> {
    return $jnicall;
}

%typemap(typecheck) std::map<std::string, std::string> %{
    /* Accept any java.util.Map */
    {
        jclass map_class = jenv->FindClass("java/util/Map");
        $1 = jenv->IsInstanceOf($input, map_class) ? 1 : 0;
    }
%}
