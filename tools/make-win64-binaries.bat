call "%VS140COMNTOOLS%vcvarsqueryregistry.bat" 64bit
call "%VCINSTALLDIR%vcvarsall.bat" amd64

mkdir .\build\windows10
cd .\build\windows10
cmake ..\.. -G "Visual Studio 14 2015 Win64"

cmake --build . --target shell --config Release
cmake --build . --target daemon --config Release
cmake --build . --target osquery_tests --config Release
cmake --build . --target osquery_additional_tests --config Release
