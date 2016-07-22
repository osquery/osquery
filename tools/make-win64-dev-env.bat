@echo off

@powershell -NoProfile -ExecutionPolicy Bypass .\provision.ps1
%ALLUSERSPROFILE%\chocolatey\bin\refreshenv.cmd
