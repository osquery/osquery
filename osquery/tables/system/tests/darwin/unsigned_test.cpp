/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

/**
 * This is a test program that will not have any code signature, which is
 * used in the SignatureTest.test_get_unsigned unit test. The cmake post build
 * will remove any ad hoc signature applied on M1 systems.
 */

#include <stdio.h>

int main(int argc, char** argv) {
  printf("Hello world!\n");
  return 0;
}
