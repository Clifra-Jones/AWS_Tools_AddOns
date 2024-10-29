#!/bin/bash
pwsh -NoLogo -NoProfile -command  "Get-Secret -Name $1 -AsPlainText" 
