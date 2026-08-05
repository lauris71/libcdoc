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

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/crypto.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace libcdoc {

template<typename T>
void cleanse(std::vector<T>& v) noexcept
{
	if (!v.empty()) {
        OPENSSL_cleanse(v.data(), v.size() * sizeof(T));
	}
}

template<typename T, size_t N>
void cleanse(std::array<T, N>& a) noexcept
{
	if (!a.empty()) {
        OPENSSL_cleanse(a.data(), a.size() * sizeof(T));
	}
}

class SecureBytes {
    std::vector<uint8_t> data_;
    bool locked_ = false;

    void lock() noexcept {
        if (!data_.empty() && !locked_) {
#ifdef _WIN32
            locked_ = VirtualLock(data_.data(), data_.size());
#else
            locked_ = (mlock(data_.data(), data_.size()) == 0);
#endif
        }
    }

    void unlock() noexcept {
        if (!data_.empty() && locked_) {
#ifdef _WIN32
            VirtualUnlock(data_.data(), data_.size());
#else
            munlock(data_.data(), data_.size());
#endif
            locked_ = false;
        }
    }

public:
    using iterator = std::vector<uint8_t>::iterator;
    using const_iterator = std::vector<uint8_t>::const_iterator;

    SecureBytes() noexcept = default;

    ~SecureBytes() {
        cleanse();
        unlock();
    }

    SecureBytes(const SecureBytes& other) : data_(other.data_) {
        lock();
    }

    SecureBytes(SecureBytes&& other) noexcept : data_(std::move(other.data_)), locked_(other.locked_) {
        other.locked_ = false;
    }

    SecureBytes& operator=(const SecureBytes& other) {
        if (this != &other) {
            cleanse();
            unlock();
            data_ = other.data_;
            lock();
        }
        return *this;
    }

    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            cleanse();
            unlock();
            data_ = std::move(other.data_);
            locked_ = other.locked_;
            other.locked_ = false;
        }
        return *this;
    }

    SecureBytes& operator=(std::vector<uint8_t> v) {
        cleanse();
        unlock();
        data_ = std::move(v);
        lock();
        return *this;
    }

    SecureBytes(std::vector<uint8_t> v) noexcept : data_(std::move(v)) {
        lock();
    }

    SecureBytes(const std::string& s) : data_(s.cbegin(), s.cend()) {
        lock();
    }

    template<typename InputIt>
    SecureBytes(InputIt first, InputIt last) : data_(first, last) {
        lock();
    }

    explicit SecureBytes(size_t size) : data_(size) {
        lock();
    }

    template<typename InputIt>
    void assign(InputIt first, InputIt last) {
        cleanse();
        unlock();
        data_.assign(first, last);
        lock();
    }

    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return data_.data(); }
    [[nodiscard]] uint8_t* data() noexcept { return data_.data(); }
    [[nodiscard]] const uint8_t& operator[](size_t i) const noexcept { return data_[i]; }
    [[nodiscard]] uint8_t& operator[](size_t i) noexcept { return data_[i]; }

    [[nodiscard]] const_iterator cbegin() const noexcept { return data_.cbegin(); }
    [[nodiscard]] const_iterator cend() const noexcept { return data_.cend(); }
    [[nodiscard]] iterator begin() noexcept { return data_.begin(); }
    [[nodiscard]] iterator end() noexcept { return data_.end(); }
    [[nodiscard]] const_iterator begin() const noexcept { return data_.begin(); }
    [[nodiscard]] const_iterator end() const noexcept { return data_.end(); }

    void resize(size_t n) {
        unlock();
        data_.resize(n);
        lock();
    }

    void clear() {
        cleanse();
        unlock();
        data_.clear();
    }

    void cleanse() noexcept {
        ::libcdoc::cleanse(data_);
    }

    [[nodiscard]] operator const std::vector<uint8_t>&() const noexcept { return data_; }

    [[nodiscard]] bool operator==(const SecureBytes& other) const noexcept {
        if (data_.size() != other.data_.size()) return false;
        return CRYPTO_memcmp(data_.data(), other.data_.data(), data_.size()) == 0;
    }

    [[nodiscard]] bool operator!=(const SecureBytes& other) const noexcept {
        return !(*this == other);
    }
};

//
// A self-cleaning writable container for temporary secrets.
//
// We allow getting a reference to the actual content vector to be used in library calls, but
// all existing contents will be cleansed first in that case.
//

class SecureTarget {
    std::vector<uint8_t> data_;
public:
    using iterator = std::vector<uint8_t>::iterator;
    using const_iterator = std::vector<uint8_t>::const_iterator;

    SecureTarget() noexcept = default;

    ~SecureTarget() {
        cleanse();
    }

    SecureTarget(const SecureTarget& other) = delete;
    SecureTarget(SecureTarget&& other) = delete;
    SecureTarget& operator=(const SecureTarget& other) = delete;
    SecureTarget& operator=(SecureTarget&& other) = delete;
    // Need a plain constructor for declaration-initialisation case
    SecureTarget(std::vector<uint8_t> v) noexcept : data_(std::move(v)) {}
    // Assignment should first cleanse and then copy/move
    SecureTarget& operator=(const std::vector<uint8_t>& v) {
        cleanse();
        data_ = v;
        return *this;
    }
    SecureTarget& operator=(std::vector<uint8_t>&& v) {
        cleanse();
        data_ = std::move(v);
        return *this;
    }

    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return data_.data(); }
    [[nodiscard]] const_iterator cbegin() const noexcept { return data_.cbegin(); }
    [[nodiscard]] const_iterator cend() const noexcept { return data_.cend(); }
    [[nodiscard]] const_iterator begin() const noexcept { return data_.begin(); }
    [[nodiscard]] const_iterator end() const noexcept { return data_.end(); }

    [[nodiscard]] operator const std::vector<uint8_t>&() const noexcept { return data_; }

    // Get writable vector
    // Any secret, if present, is cleansed first to avoid leaking previous contents
    std::vector<uint8_t>& getTarget() {
        cleanse();
        return data_;
    }
    std::vector<uint8_t>& getTarget(size_t size) {
        cleanse(size);
        return data_;
    }

    void cleanse(size_t size = 0) noexcept {
        ::libcdoc::cleanse(data_);
        data_.resize(size);
    }
};

/**
 * @brief Scope guard that wipes a contiguous secret on destruction.
 *
 * Wraps a reference to a @c std::vector<uint8_t> (or @c std::array<uint8_t,N>)
 * and calls @ref libcdoc::cleanse on it from the destructor, including the
 * exceptional and early-return paths. Intended for the short-lived KEK / FMK
 * pre-master / shared-secret buffers in CDoc2Reader / CDoc2Writer where every
 * function has multiple early-return branches and remembering to cleanse at
 * each one is fragile.
 *
 * Note: this only wipes the *currently-allocated* storage. It does NOT wipe
 * earlier allocations that @c std::vector may have freed during a resize.
 * For long-lived secrets that get assigned over multiple times, use
 * @ref SecureBytes (which serialises through cleanse/unlock on each resize)
 * or a fixed-size container.
 *
 * Usage:
 * @code
 *   std::vector<uint8_t> kek;
 *   Cleanser kek_guard(kek);     // wipes `kek` on every exit from this scope
 *   ...
 *   if (failure) return ERROR;   // kek is wiped before unwind
 *   ...
 * @endcode
 */
template<typename Container>
class Cleanser {
public:
    explicit Cleanser(Container& c) noexcept : c_(c) {}
    ~Cleanser() noexcept { libcdoc::cleanse(c_); }

    Cleanser(const Cleanser&) = delete;
    Cleanser& operator=(const Cleanser&) = delete;
    Cleanser(Cleanser&&) = delete;
    Cleanser& operator=(Cleanser&&) = delete;
private:
    Container& c_;
};

// Class template argument deduction: `Cleanser g(vec);` infers the type.
template<typename Container>
Cleanser(Container&) -> Cleanser<Container>;

inline bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) noexcept
{
	if (a.size() != b.size()) return false;
	return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

template<auto D>
struct free_deleter
{
    template<class T>
    void operator()(T *p) const noexcept
    {
        D(p);
    }
};

template<typename> struct free_argument;
template<class T, class R>
struct free_argument<R (*)(T *)>
{
    using type = T;
};

template<auto D>
using free_argument_t = typename free_argument<decltype(D)>::type;

template <class T>
using unique_free_t = std::unique_ptr<T, void(*)(T*)>;

template <auto D>
using unique_ptr_t = std::unique_ptr<free_argument_t<D>, free_deleter<D>>;

template<class T, typename D>
[[nodiscard]]
constexpr std::unique_ptr<T, D> make_unique_ptr(T *p, D d) noexcept
{
    return {p, std::forward<D>(d)};
}

template<auto D, class T>
[[nodiscard]]
constexpr auto make_unique_ptr(T *p) noexcept
{
    return std::unique_ptr<T, free_deleter<D>>(p);
}

template<auto D>
[[nodiscard]]
constexpr auto make_unique_ptr(nullptr_t) noexcept
{
    return unique_ptr_t<D>(nullptr);
}

template<auto D, class P>
[[nodiscard]]
constexpr auto make_unique_cast(P *p) noexcept
{
    using T = typename free_argument<decltype(D)>::type;
    return make_unique_ptr<D>(static_cast<T*>(p));
}

template<auto F, auto Free, typename... Args>
[[nodiscard]]
constexpr auto d2i(const std::vector<uint8_t> &data, Args&&... args) noexcept
{
    if(data.empty())
        return std::unique_ptr<free_argument_t<Free>, decltype(Free)>(nullptr, Free);
    const auto *p = data.data();
    return make_unique_ptr(F(std::forward<Args>(args)..., &p, long(data.size())), Free);
}

}
