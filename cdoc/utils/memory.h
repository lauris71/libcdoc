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

#include <memory>
#include <vector>

namespace libcdoc {

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