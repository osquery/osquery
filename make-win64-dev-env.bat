@echo off

@powershell -NoProfile -ExecutionPolicy Bypass .\tools\provision.ps1
refreshenv.cmd
