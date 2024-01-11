REM Credential process file for Windows.
pwsh -NoLogo -NoProfile -NonInteractive -command  "Get-Secret -Vault AWS -Name %1 -AsPlainText"