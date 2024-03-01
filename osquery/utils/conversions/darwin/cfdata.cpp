/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "cfdata.h"

#include <iomanip>
#include <sstream>

namespace osquery {

std::string stringFromCFData(const CFDataRef& cf_data) {
    const std::string kHexDigitsLowercase = "0123456789abcdef";
    const uint8_t * src = cf_dataGetBytePtr(cf_data);
    const auto len = cf_dataGetLength(cf_data);
    const uint8_t * end = src + len;
    auto lenOfCharacters = len * 2;
    std::string output;
    while( src < end && lenOfCharacters >= 2)
    {
        uint8_t b = *src;
        ++src;
        output.push_back(kHexDigitsLowercase.at(b >> 4));
        output.push_back(kHexDigitsLowercase.at(b & 0xF));
        lenOfCharacters = lenOfCharacters - 2;
    }
    return output;
}

}
