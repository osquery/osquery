# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

importSourceSubmodule(
  NAME "boost"

  NO_RECURSIVE

  SUBMODULES
    "src"

  SHALLOW_SUBMODULES
    "src/libs/fusion"
    "src/libs/logic"
    "src/libs/conversion"
    "src/libs/xpressive"
    "src/libs/proto"
    "src/libs/beast"
    "src/libs/mp11"
    "src/libs/unordered"
    "src/libs/function_types"
    "src/libs/tti"
    "src/libs/uuid"
    "src/libs/asio"
    "src/libs/any"
    "src/libs/foreach"
    "src/libs/multi_index"
    "src/libs/property_tree"
    "src/libs/spirit"
    "src/libs/algorithm"
    "src/libs/variant"
    "src/libs/format"
    "src/libs/optional"
    "src/libs/type_index"
    "src/libs/coroutine2"
    "src/libs/function"
    "src/libs/ratio"
    "src/libs/multiprecision"
    "src/libs/tokenizer"
    "src/libs/intrusive"
    "src/libs/array"
    "src/libs/range"
    "src/libs/concept_check"
    "src/libs/utility"
    "src/libs/throw_exception"
    "src/libs/move"
    "src/libs/container_hash"
    "src/libs/io"
    "src/libs/detail"
    "src/libs/mpl"
    "src/libs/static_assert"
    "src/libs/core"
    "src/libs/type_traits"
    "src/libs/preprocessor"
    "src/libs/bind"
    "src/libs/smart_ptr"
    "src/libs/assert"
    "src/libs/iterator"
    "src/libs/predef"
    "src/libs/integer"
    "src/libs/lexical_cast"
    "src/libs/system"
    "src/libs/tuple"
    "src/libs/locale"
    "src/libs/context"
    "src/libs/coroutine"
    "src/libs/filesystem"
    "src/libs/regex"
    "src/libs/thread"
    "src/libs/atomic"
    "src/libs/date_time"
    "src/libs/numeric/conversion"
    "src/libs/container"
    "src/libs/math"
    "src/libs/chrono"
    "src/libs/exception"
    "src/libs/serialization"
    "src/libs/random"
    "src/libs/config"
    "src/libs/process"
    "src/libs/circular_buffer"
    "src/libs/winapi"
    "src/libs/iostreams"
    "src/libs/scope_exit"
    "src/libs/typeof"
    "src/libs/endian"

  PATCH
    "src/libs/process"
)
