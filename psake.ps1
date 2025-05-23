Properties {
    $ModuleName = (Get-Item $PSScriptRoot\*.psd1)[0].BaseName

    $Exclude = @(
        'psake.ps1',
        '.git',
        '.gitignore'
        'publish',
        '.vscode'
        '_config.yml'
    )
    $TempDir = "$home/tmp" 
    $PublishDir = "$PSScriptRoot/publish/$ModuleName"
}


Task default -depends Build

Task Publish -depends Build {
    # Write-Host "test publish = $testpublish"
    if ($testpublish -eq "yes") {
        $whatIf = $true
    } else {
        $whatIf = $false
    }
    # Write-Host "whatif = $whatIf"
    $NugetKey = (Get-Secret -Name NuGetKey -AsPlainText | ConvertFrom-Json).NuGetKey
    Publish-PSResource -Path $PublishDir -ApiKey $NugetKey -WhatIf:$WhatIf -Verbose
}

Task Build -depends Clean {
    # Generate updated reference page
    # . $PSScriptRoot/docs/makeDocs.ps1

    Copy-Item "$PSScriptRoot\*" -Destination $PublishDir -Exclude $Exclude -Recurse 
}

Task Clean -depends Init {    
    Remove-Item "$PublishDir\*" -Recurse -Force
}

Task Init {
    if (-not (Test-Path $TempDir)) {
        New-Item -ItemType Directory $TempDir
    }
    if (-not (Test-Path $PublishDir)) {
        New-Item -ItemType Directory $PublishDir
    }    
}

