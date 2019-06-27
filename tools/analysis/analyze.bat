@echo off
REM Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
"C:\Program Files\Cppcheck\cppcheck.exe" --quiet -i .\build\ .
"C:\Program Files\Cppcheck\cppcheck.exe" --quiet --project=.\build\windows10\OSQUERY.sln
