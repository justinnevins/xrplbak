@echo off
rem Double-click this file to copy and check the xrplbak backup files.
rem Settings are at the top of Pull-XrplbakBackup.ps1.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Pull-XrplbakBackup.ps1" %*
