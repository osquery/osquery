/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Precompiled header for the AWS SDK third-party targets.
//
// These headers were identified as the most expensive in ClangBuildAnalyzer:
//   AWSString.h            ~503 s total (1984 inclusions, 274 ms avg)
//   AWSMemory.h            ~344 s total (1984 inclusions, 173 ms avg)
//   AmazonWebServiceRequest.h       ~340 s total (527 inclusions, 646 ms avg)
//   AmazonSerializableWebServiceRequest.h  ~340 s total (524 inclusions, 649 ms
//   avg)
//
// Applied to thirdparty_aws-cpp-sdk-core and reused by all other SDK targets.
// All include paths below are available via the INTERFACE include directories
// exported by thirdparty_aws-cpp-sdk-core.

#pragma once

#include <aws/core/AmazonSerializableWebServiceRequest.h>
#include <aws/core/AmazonWebServiceRequest.h>
#include <aws/core/utils/memory/AWSMemory.h>
#include <aws/core/utils/memory/stl/AWSString.h>
