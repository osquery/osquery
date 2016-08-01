mkdir .\build\windows10
cd .\build\windows10
cmake ..\.. -G "Visual Studio 14 2015 Win64"

"C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe" .\osquery\shell.vcxproj /t:Build /p:Configuration=Release

copy "C:\ProgramData\chocolatey\lib\linenoise-ng\local\bin\linenoise.dll" .\osquery\Release\linenoise.dll
copy "C:\ProgramData\chocolatey\lib\glog\local\bin\glog.dll" .\osquery\Release\glog.dll
copy "C:\ProgramData\chocolatey\lib\openssl\local\bin\libeay32.dll" .\osquery\Release\libeay32.dll

