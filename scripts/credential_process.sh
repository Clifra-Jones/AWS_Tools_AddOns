#!/bin/bash
pwsh -NoLogo -NoProfile -NonInteractive -command  "Get-Secret -Vault AWS -Name $1 -AsPlainText"
