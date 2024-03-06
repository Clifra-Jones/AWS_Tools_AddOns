@echo off
REM Credential process file for Windows.
pwsh -NoLogo -NoProfile -command  "Get-Secret -Name %1 -AsPlainText"