@echo off

@powershell -NoProfile -ExecutionPolicy Bypass .\tools\provision.ps1
%ALLUSERSPROFILE%\chocolatey\bin\refreshenv.cmd
