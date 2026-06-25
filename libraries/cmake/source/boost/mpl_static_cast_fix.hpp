// Workaround for Clang 16+ constant expression issues with Boost MPL 1.77.
// (Fixed in Boost 1.82.)
//
// Root cause (two interlocking problems):
//
// 1) BOOST_MPL_AUX_STATIC_CAST(T, expr) expands to static_cast<T>(expr) or
//    (T)(expr). When T is an enum type and expr is int, this is an explicit
//    int-to-enum conversion. C++17 [temp.arg.nontype] only permits IMPLICIT
//    conversions ("converted constant expression") in non-type template
//    arguments, so the explicit cast is rejected.
//
//    Fix: Replace the macro with a constexpr function template that returns
//    type T. Because the return type is already T, no conversion is needed
//    at the call site. The explicit cast happens inside the constexpr function
//    body where explicit conversions are fully allowed.
//
// 2) The boost::numeric::*_mixture_enum enums (udt_builtin_mixture_enum,
//    sign_mixture_enum, int_float_mixture_enum) have values 0-3 with no
//    fixed underlying type. C++17 [dcl.enum] gives them a valid range of
//    [0,3] (2-bit unsigned). When integral_c<T,0>::prior or
//    integral_c<T,3>::next is instantiated the compiler computes T(-1) or
//    T(4), both out-of-range, which is undefined behaviour and therefore not
//    a constant expression — rejected by Clang 16+.
//
//    Fix: Pre-empt those three enum headers and redeclare the enums with a
//    fixed ": int" underlying type so that every int value is in-range and
//    the computed prior/next values are valid constant expressions.
//
// ── Part 1: fix the boost::numeric enum valid ranges ─────────────────────────

// Pre-empt udt_builtin_mixture_enum.hpp
#define BOOST_NUMERIC_CONVERSION_UDT_BUILTIN_MIXTURE_ENUM_FLC_12NOV2002_HPP
namespace boost { namespace numeric {
  enum udt_builtin_mixture_enum : int {
     builtin_to_builtin
    ,builtin_to_udt
    ,udt_to_builtin
    ,udt_to_udt
  };
} }

// Pre-empt sign_mixture_enum.hpp
#define BOOST_NUMERIC_CONVERSION_SIGN_MIXTURE_ENUM_FLC_12NOV2002_HPP
namespace boost { namespace numeric {
  enum sign_mixture_enum : int {
     unsigned_to_unsigned
    ,signed_to_signed
    ,signed_to_unsigned
    ,unsigned_to_signed
  };
} }

// Pre-empt int_float_mixture_enum.hpp
#define BOOST_NUMERIC_CONVERSION_INT_FLOAT_MIXTURE_ENUM_FLC_12NOV2002_HPP
namespace boost { namespace numeric {
  enum int_float_mixture_enum : int {
     integral_to_integral
    ,integral_to_float
    ,float_to_integral
    ,float_to_float
  };
} }

// ── Part 2: fix BOOST_MPL_AUX_STATIC_CAST ────────────────────────────────────

// Constexpr function returning T directly so the call-site expression has type
// T and no implicit int→enum conversion is required at the template-argument
// position. The static_cast happens inside the function body where explicit
// conversions are allowed, and with the fixed-int underlying type above the
// cast is always well-defined.
template<typename T, typename U>
constexpr T boost_mpl_static_cast_workaround(U x) {
    return static_cast<T>(x);
}

// Pre-empt static_cast.hpp (its include guard is BOOST_MPL_AUX_STATIC_CAST_HPP_INCLUDED)
// so our definition below is not overridden.
#define BOOST_MPL_AUX_STATIC_CAST_HPP_INCLUDED
#define BOOST_MPL_AUX_STATIC_CAST(T, expr) (::boost_mpl_static_cast_workaround<T>(expr))
