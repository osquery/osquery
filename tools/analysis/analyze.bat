@echo off
"C:\Program Files\Cppcheck\cppcheck.exe" --quiet -i .\third-party\ -i .\build\ .
"C:\Program Files\Cppcheck\cppcheck.exe" --quiet --project=.\build\windows10\OSQUERY.sln
