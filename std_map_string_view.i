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
%typemap(in) std::map<std::string_view, std::string_view> (
        std::map<std::string, std::string> $1_store,
        std::map<std::string_view, std::string_view> $1_view) %{
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
            const char *key_chars = jenv->GetStringUTFChars(jkey, nullptr);
            std::string key(key_chars);
            jenv->ReleaseStringUTFChars(jkey, key_chars);
            const char *val_chars = jenv->GetStringUTFChars(jval, nullptr);
            std::string val(val_chars);
            jenv->ReleaseStringUTFChars(jval, val_chars);
            $1_store.emplace(std::move(key), std::move(val));
        }
        if (jenv->ExceptionCheck()) return $null;
    }
    // std::map nodes are stable, so string_views into $1_store stay valid
    // for the duration of the wrapped call.
    for (const auto& [key, value] : $1_store) {
        $1_view.emplace(key, value);
    }
    $1 = $1_view;
%}

// C++ std::map<std::string_view, std::string_view> -> Java Map
%typemap(out) std::map<std::string_view, std::string_view> %{
    jclass map_class = jenv->FindClass("java/util/HashMap");
    jmethodID mid_new = jenv->GetMethodID(map_class, "<init>", "()V");
    jmethodID mid_put = jenv->GetMethodID(map_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject map = jenv->NewObject(map_class, mid_new);
    for (const auto& [key, value] : result) {
        jstring jkey = jenv->NewStringUTF(std::string(key).c_str());
        jstring jval = jenv->NewStringUTF(std::string(value).c_str());
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
