/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
namespace osquery {

Status verifySignature(const std::string& b64Pub,
                       const std::string& b64Sig,
                       const std::string& message);

Status verifyStrictSignature(const std::string& b64Sig,
                             const std::string& message);

Status verifyQuerySignature(const std::string& b64Sig,
                            const std::string& query);

bool doesQueryRequireSignature(const std::string& query);
}