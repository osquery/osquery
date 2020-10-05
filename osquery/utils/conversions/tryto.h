/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <type_traits>

#include <osquery/utils/expected/expected.h>

namespace osquery {

enum class ConversionError {
  InvalidArgument,
  OutOfRange,
  Unknown,
};

template <typename ToType, typename FromType>
inline typename std::enable_if<
    std::is_same<ToType,
                 typename std::remove_cv<typename std::remove_reference<
                     FromType>::type>::type>::value,
    Expected<ToType, ConversionError>>::type
tryTo(FromType&& from) {
  return std::forward<FromType>(from);
}

namespace impl {

template <typename Type>
struct IsStlString {
  static constexpr bool value = std::is_same<Type, std::string>::value ||
                                std::is_same<Type, std::wstring>::value;
};

template <typename Type>
struct IsInteger {
  static constexpr bool value =
      std::is_integral<Type>::value && !std::is_same<Type, bool>::value;
};

template <typename FromType,
          typename ToType,
          typename IntType,
          typename =
              typename std::enable_if<std::is_same<ToType, IntType>::value &&
                                          IsStlString<FromType>::value,
                                      IntType>::type>
struct IsConversionFromStringToIntEnabledFor {
  using type = IntType;
};

template <typename ToType, typename FromType>
inline
    typename IsConversionFromStringToIntEnabledFor<FromType, ToType, int>::type
    throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoi(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      long int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stol(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      long long int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoll(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      unsigned int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoul(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      unsigned long int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoul(from, &pos, base);
}

template <typename ToType, typename FromType>
inline
    typename IsConversionFromStringToIntEnabledFor<FromType,
                                                   ToType,
                                                   unsigned long long int>::type
    throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoull(from, &pos, base);
}

Expected<bool, ConversionError> stringToBool(std::string from);

} // namespace impl

/**
 * Template tryTo for [w]string to integer conversion
 */
template <typename ToType, typename FromType>
inline typename std::enable_if<impl::IsInteger<ToType>::value &&
                                   impl::IsStlString<FromType>::value,
                               Expected<ToType, ConversionError>>::type
tryTo(const FromType& from, const int base = 10) noexcept {
  try {
    return impl::throwingStringToInt<ToType>(from, base);
  } catch (const std::invalid_argument& ia) {
    return createError(ConversionError::InvalidArgument)
           << "If no conversion could be performed. " << ia.what();
  } catch (const std::out_of_range& oor) {
    return createError(ConversionError::OutOfRange)
           << "Value read is out of the range of representable values by an "
              "int. "
           << oor.what();
  } catch (...) {
    return createError(ConversionError::Unknown)
           << "Unknown error during conversion "
           << boost::core::demangle(typeid(FromType).name()) << " to "
           << boost::core::demangle(typeid(ToType).name()) << " base " << base;
  }
}

/**
 * Parsing general representation of boolean value in string.
 *     "1" : true
 *     "0" : false
 *     "y" : true
 *   "yes" : true
 *     "n" : false
 *    "no" : false
 *   ... and so on
 *   For the full list of possible valid values @see stringToBool definition
 */
template <typename ToType>
inline typename std::enable_if<std::is_same<ToType, bool>::value,
                               Expected<ToType, ConversionError>>::type
tryTo(std::string from) {
  return impl::stringToBool(std::move(from));
}

inline uint64_t operator"" _sz(unsigned long long int x) {
  return x;
}

} // namespace osquery
