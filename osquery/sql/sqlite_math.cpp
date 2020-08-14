/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifdef WIN32
#define _USE_MATH_DEFINES
#endif
// Include cmath here to ensure it is included after the define.
#include <cmath>

#include <osquery/utils/system/errno.h>

#include <assert.h>
#include <errno.h>

#include <string.h>

#include <functional>

#include <sqlite3.h>

namespace osquery {

using DoubleDoubleFunction = std::function<double(double)>;

/**
 * Force use of the double(double) math functions without these lambda
 * functions, MSVC will error because it fails to select an overload compatible
 * with DoubleDoubleFunction.
 */
// clang-format off
#define SIN_FUNC    [](double a)->double { return sin(a);    }
#define COS_FUNC    [](double a)->double { return cos(a);    }
#define TAN_FUNC    [](double a)->double { return tanl(a);   }
#define ASIN_FUNC   [](double a)->double { return asin(a);   }
#define ACOS_FUNC   [](double a)->double { return acos(a);   }
#define ATAN_FUNC   [](double a)->double { return atan(a);   }
#define LOG_FUNC    [](double a)->double { return log(a);    }
#define LOG10_FUNC  [](double a)->double { return log10(a);  }
#define SQRT_FUNC   [](double a)->double { return sqrt(a);   }
#define EXP_FUNC    [](double a)->double { return expl(a);   }
#define CEIL_FUNC   [](double a)->double { return ceil(a);   }
#define FLOOR_FUNC  [](double a)->double { return floor(a);  }
// clang-format on

/**
 * @brief Call a math function that takes a double and returns a double.
 */
static void callDoubleFunc(sqlite3_context* context,
                           int argc,
                           sqlite3_value** argv,
                           DoubleDoubleFunction f) {
  double rVal = 0.0, val;
  assert(argc == 1);
  switch (sqlite3_value_type(argv[0])) {
  case SQLITE_NULL:
    sqlite3_result_null(context);
    break;
  default:
    rVal = sqlite3_value_double(argv[0]);
    errno = 0;
    val = f(rVal);
    if (errno == 0) {
      sqlite3_result_double(context, val);
    } else {
      sqlite3_result_error(context, platformStrerr(errno).c_str(), -1);
    }
    break;
  }
}

static void sinFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, SIN_FUNC);
}

static void cosFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, COS_FUNC);
}

static void tanFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, TAN_FUNC);
}

static void asinFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, ASIN_FUNC);
}

static void acosFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, ACOS_FUNC);
}

static void atanFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, ATAN_FUNC);
}

static double cot(double x) {
  return 1.0 / tan(x);
}

static void cotFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, cot);
}

static void logFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, LOG_FUNC);
}

static void log10Func(sqlite3_context* context,
                      int argc,
                      sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, LOG10_FUNC);
}

static void sqrtFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, SQRT_FUNC);
}

static void expFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, EXP_FUNC);
}

static void powerFunc(sqlite3_context* context,
                      int argc,
                      sqlite3_value** argv) {
  assert(argc == 2);

  if (sqlite3_value_type(argv[0]) == SQLITE_NULL ||
      sqlite3_value_type(argv[1]) == SQLITE_NULL) {
    sqlite3_result_null(context);
  } else {
    double r1 = sqlite3_value_double(argv[0]);
    double r2 = sqlite3_value_double(argv[1]);
    errno = 0;
    double val = pow(r1, r2);
    if (errno == 0) {
      sqlite3_result_double(context, val);
    } else {
      sqlite3_result_error(context, platformStrerr(errno).c_str(), -1);
    }
  }
}

static void callCastedDoubleFunc(sqlite3_context* context,
                                 int argc,
                                 sqlite3_value** argv,
                                 DoubleDoubleFunction f) {
  double rVal = 0.0;
  assert(argc == 1);
  switch (sqlite3_value_type(argv[0])) {
  case SQLITE_INTEGER: {
    int64_t iVal = sqlite3_value_int64(argv[0]);
    sqlite3_result_int64(context, iVal);
    break;
  }
  case SQLITE_NULL:
    sqlite3_result_null(context);
    break;
  default:
    rVal = sqlite3_value_double(argv[0]);
    sqlite3_result_int64(context, (int64_t)f(rVal));
    break;
  }
}

static void ceilFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  callCastedDoubleFunc(context, argc, argv, CEIL_FUNC);
}

static void floorFunc(sqlite3_context* context,
                      int argc,
                      sqlite3_value** argv) {
  callCastedDoubleFunc(context, argc, argv, FLOOR_FUNC);
}

/** Convert Degrees into Radians */
static double deg2rad(double x) {
  return x * M_PI / 180.0;
}

/** Convert Radians into Degrees */
static double rad2deg(double x) {
  return 180.0 * x / M_PI;
}

static void rad2degFunc(sqlite3_context* context,
                        int argc,
                        sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, rad2deg);
}

static void deg2radFunc(sqlite3_context* context,
                        int argc,
                        sqlite3_value** argv) {
  callDoubleFunc(context, argc, argv, deg2rad);
}

static void piFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {
  sqlite3_result_double(context, M_PI);
}

struct FuncDef {
  const char* zFunctionName;
  int nArg;
  void (*xFunc)(sqlite3_context*, int, sqlite3_value**);
};

void registerMathExtensions(sqlite3* db) {
  // This approach to adding non-standard Math functions was inspired by the
  // somewhat deprecated/legacy work by Liam Healy from 2010 in the extension
  // functions contribution.
  static const struct FuncDef aFuncs[] = {
      {"sqrt", 1, sqrtFunc},
      {"acos", 1, acosFunc},
      {"asin", 1, asinFunc},
      {"atan", 1, atanFunc},
      {"cos", 1, cosFunc},
      {"sin", 1, sinFunc},
      {"tan", 1, tanFunc},
      {"cot", 1, cotFunc},
      {"exp", 1, expFunc},
      {"log", 1, logFunc},
      {"log10", 1, log10Func},
      {"power", 2, powerFunc},
      {"ceil", 1, ceilFunc},
      {"floor", 1, floorFunc},
      {"degrees", 1, rad2degFunc},
      {"radians", 1, deg2radFunc},
      {"pi", 0, piFunc},
  };

  for (size_t i = 0; i < sizeof(aFuncs) / sizeof(struct FuncDef); i++) {
    sqlite3_create_function(db,
                            aFuncs[i].zFunctionName,
                            aFuncs[i].nArg,
                            SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                            nullptr,
                            aFuncs[i].xFunc,
                            nullptr,
                            nullptr);
  }
}
} // namespace osquery
