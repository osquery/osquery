<#
  Copyright (c) 2014-present, Facebook, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
#>

# It does not seem that they have HTTPS: https://github.com/StrawberryPerl/strawberryperl.com/issues/11
Invoke-WebRequest "http://strawberryperl.com/download/5.30.0.1/strawberry-perl-5.30.0.1-64bit.zip" -OutFile "$env:TEMP\strawberry_perl.zip"
Expand-Archive "$env:TEMP\strawberry_perl.zip" -DestinationPath "C:\Strawberry" -Force
