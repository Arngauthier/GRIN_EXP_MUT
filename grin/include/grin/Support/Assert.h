#ifndef GRIN_ASSERT_H
#define GRIN_ASSERT_H

//
// This file is distributed under the MIT License. See LICENSE.md for details.
//

#ifdef __cplusplus
extern "C" {
#endif

// Standard includes
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#if !__has_builtin(__builtin_assume)
#define __builtin_assume(x)
#endif

#if !__has_builtin(__builtin_unreachable) && !defined(__GNUC__)
#define __builtin_unreachable(x)
#endif

#if defined(__clang__)

// clang-format off
#define SILENCE_ASSUME_HEADER                                          \
  _Pragma("clang diagnostic push")                                     \
  _Pragma("clang diagnostic ignored \"-Wassume\"")
// clang-format on
#define SILENCE_ASSUME_FOOTER _Pragma("clang diagnostic pop")

#else

#define SILENCE_ASSUME_HEADER
#define SILENCE_ASSUME_FOOTER

#endif

/// \brief Same as __builtin_assume but (temporarily) suppresses warnings about
///        ignored side-effects
#define silent_assume(what)                    \
  do {                                         \
    SILENCE_ASSUME_HEADER                      \
    __builtin_assume(static_cast<bool>(what)); \
    SILENCE_ASSUME_FOOTER                      \
  } while (0)

// We support C++11, C99 (with GNU attributes) or C11
#ifdef __cplusplus

#define boolcast(what) static_cast<bool>(what)
#define noret [[noreturn]]

#else

#define boolcast(what) (bool) (what)

#if __STDC_VERSION__ >= 201112L
#include <stdnoreturn.h>
#define noret noreturn
#elif __has_attribute(noreturn) || defined(__GNUC__)
#define noret __attribute__((noreturn))
#else
#warning "Can't mark functions as noreturn"
#endif

#endif

noret void grin_assert_fail(const char *AssertionBody,
                             const char *Message,
                             const char *File,
                             unsigned Line);
noret void grin_check_fail(const char *CheckBody,
                            const char *Message,
                            const char *File,
                            unsigned Line);
noret void grin_do_abort(const char *Message, const char *File, unsigned Line);

#undef noret

/// \brief Aborts program execution with a message, in release mode too.
///
/// Use this macro to ensure program termination in case of an unexpected
/// situation.
#define grin_abort_impl(message)                \
  do {                                           \
    grin_do_abort(message, __FILE__, __LINE__); \
  } while (0)

/// \brief Asserts \a what or aborts with \a message, in release mode too.
///
/// Use this macro to ensure program termination in case of an unexpected
/// situation.
#define grin_check_impl(what, message)                     \
  do {                                                      \
    bool Condition = boolcast(what);                        \
    if (!Condition) {                                       \
      grin_check_fail(#what, message, __FILE__, __LINE__); \
    }                                                       \
    silent_assume(Condition);                               \
  } while (0)

#ifndef NDEBUG

/// \brief Marks a program path as unreachable. In debug mode, aborts with \a
///        message.
///
/// Use this macro to catch bugs during development an tell the compiler that a
/// certain situation will never happen at run-time, which might open up to new
/// optimization opportunities.
#define grin_unreachable_impl(message) grin_abort(message)

/// \brief Asserts \a what or, in debug mode, aborts with \a message.
///
/// Use this macro to catch bugs during development an tell the compiler that a
/// certain situation will never happen at run-time, which might open up to new
/// optimization opportunities.
#define grin_assert_impl(what, message)                     \
  do {                                                       \
    bool Condition = boolcast(what);                         \
    if (!Condition) {                                        \
      grin_assert_fail(#what, message, __FILE__, __LINE__); \
    }                                                        \
    silent_assume(Condition);                                \
  } while (0)

#else

#define grin_unreachable_impl(message) __builtin_unreachable()

#define grin_assert_impl(what, message) \
  do {                                   \
    (void) sizeof((what));               \
    silent_assume(what);                 \
  } while (0)

#endif

#define COMMA_IF_INVOKED(...) ,
#define CONCAT_TOKENS(a, b) a##b
#define CONCAT2(a, b) CONCAT_TOKENS(a, b)
#define CONCAT3(a, b, c) CONCAT2(CONCAT2(a, b), c)
#define CONCAT4(a, b, c, d) CONCAT2(CONCAT3(a, b, c), d)
#define CONCAT5(a, b, c, d, e) CONCAT2(CONCAT4(a, b, c, d), e)
#define GET_10TH(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, ...) _10

/// \brief Check if the argument list contains a comma
#define HAS_COMMA(...) GET_10TH(__VA_ARGS__, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0)

/// Check if the argument list is empty
///
/// This is a workaround to avoid using ##__VA_ARGS__ (which eats the previous
/// comma if empty), since it's a GNU extension, and to void using default
/// arguments, since we want this header to be functioncal in C files too.
#define IS_EMPTY(...)                                        \
  HAS_COMMA(CONCAT5(IS_EMPTY_,                               \
                    HAS_COMMA(__VA_ARGS__),                  \
                    HAS_COMMA(COMMA_IF_INVOKED __VA_ARGS__), \
                    HAS_COMMA(__VA_ARGS__()),                \
                    HAS_COMMA(COMMA_IF_INVOKED __VA_ARGS__())))
// It's empty if the first three conditions are false and the last is true
#define IS_EMPTY_0001 ,

#define GRIN_ABORT_0(...) grin_abort_impl(__VA_ARGS__)
#define GRIN_ABORT_1(...) grin_abort_impl(NULL)
#define grin_abort(...) \
  CONCAT2(GRIN_ABORT_, IS_EMPTY(__VA_ARGS__))(__VA_ARGS__)

#define GRIN_UNREACHABLE_0(...) grin_unreachable_impl(__VA_ARGS__)
#define GRIN_UNREACHABLE_1(...) grin_unreachable_impl(NULL)
#define grin_unreachable(...) \
  CONCAT2(GRIN_UNREACHABLE_, IS_EMPTY(__VA_ARGS__))(__VA_ARGS__)

#define MACRO_OVERLOAD_1_OR_2(_1, _2, NAME, ...) NAME

#define grin_assert_impl_nomsg(what) grin_assert_impl(what, NULL)
#define grin_assert(...)                        \
  MACRO_OVERLOAD_1_OR_2(__VA_ARGS__,             \
                        grin_assert_impl,       \
                        grin_assert_impl_nomsg) \
  (__VA_ARGS__)

#define grin_check_impl_nomsg(what) grin_check_impl(what, NULL)
#define grin_check(...)                                                       \
  MACRO_OVERLOAD_1_OR_2(__VA_ARGS__, grin_check_impl, grin_check_impl_nomsg) \
  (__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // GRIN_ASSERT_H
