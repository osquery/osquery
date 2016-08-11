mkdir .\build\windows10
cd .\build\windows10
cmake ..\.. -G "Visual Studio 14 2015 Win64"

cmake --build . --target shell --config Release

