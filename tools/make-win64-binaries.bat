call "%VS140COMNTOOLS%vcvarsqueryregistry.bat" 64bit
call "%VCINSTALLDIR%vcvarsall.bat" amd64

mkdir .\build\windows10
cd .\build\windows10
cmake ..\.. -G "Visual Studio 14 2015 Win64"

for %%t in (shell,daemon,osquery_tests,osquery_additional_tests,osquery_tables_tests) do (
  cmake --build . --target %%t --config Release
  if errorlevel 1 goto end
)

:end
