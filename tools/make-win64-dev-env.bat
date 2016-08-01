@echo off
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass .\tools\provision.ps1
%ALLUSERSPROFILE%\chocolatey\bin\refreshenv.cmd

