@echo off & setlocal
REM command chcp returns string: "Active code page: ..."
for /F "tokens=*"  %%i in ('chcp') do SET t=%%i

REM Get the last substring (codepage) from "t" and assign it to "CodePage" 
:loop
for /f "tokens=1*" %%a in ("%t%") do (
    set CodePage=%%a
    set t=%%b
   )
if defined t goto :loop

REM Changing the active code page to US code
chcp 437>nul

%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass .\tools\build.ps1
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%
%ALLUSERSPROFILE%\chocolatey\bin\refreshenv.cmd

REM Restore the original code page
chcp %CodePage%>nul
