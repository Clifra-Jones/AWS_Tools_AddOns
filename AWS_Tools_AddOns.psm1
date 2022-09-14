function Get-S3Folder () {
    Param(
        [Parameter(Mandatory = $true )]
        [String]$BucketName,
        [String]$Prefix,
        [switch]$Files,
        [switch]$Folders,
        [Int]$MaxServiceCallHistory=50
    )

    If ($MaxServiceCallHistory) {
        Set-AWSHistoryConfiguration -MaxServiceCallHistory $MaxServiceCallHistory
    }

    $result = [System.Collections.Generic.List[PSObject]]::New()

    $Prefix += ($Prefix.EndsWith("/")) ? "" : "/"
    $s3Files = Get-S3Object -BucketName $BucketName -Prefix $Prefix -Delimiter '/'
    $s3Folders = ($AWSHistory.LastCommand.Responses.History).CommonPrefixes
    if ($Files) {
        foreach ($s3File in $s3Files) {
            $result.add(
                [PSCustomObject]@{
                    Key = $S3File.Key
                }
            )
        }
    } elseif ($Folders) {
        foreach ($s3Folder in $s3Folders) {
            $result.Add(
                [PSCustomObject]@{
                    Key = $S3Folder
                }
            )
        }
    } else {
        foreach ($s3File in $s3Files) {
            $result.add(
                [PSCustomObject]@{
                    Key = $S3File.Key
                }                
            )
        }
        foreach ($s3Folder in $s3Folders) {
            $result.Add(
                [PSCustomObject]@{
                    Key = $S3Folder
                }
            )
        }
    }
    return $result.ToArray() | Sort-Object -Property Key
    <#
    .SYNOPSIS
    List S3 Folders
    .DESCRIPTION
    This function emulates working with folders "Common prefixes" in S3. It will list the files and top level keys for a given bucket and prefix.
    .PARAMETER BucketName
    The name of the bucket
    .PARAMETER Prefix
    The prefix to list.
    .PARAMETER Files
    Only return the files in the top level prefix.
    .PARAMETER Folders
    Only return the folders in the top level prefix
    .PARAMETER MaxServiceCallHistory
    To get the common prefixes we call the $AWSHistory.LastCommand. By default that only returns the last 10 commands.
    So we set this to 50 as our default. This is usually fine for most uses unless you have a prefix with lot of sub-prefixes and files.
    .OUTPUTS
    An array of prefixes and/or files.
    #>
}

function Restore-S3Folder () {
    Param(
        [Parameter(Mandatory)]
        [string]$BucketName,
        [Parameter(Mandatory)]
        [string]$Prefix,
        [Parameter(Mandatory)]
        [int]$CopyLifetime,
        [Parameter(Mandatory)]
        [ValidateSet("Standard", "Expedited","Bulk")]
        [string]$Tier
    )
    #Validate the bucket exists
    $Bucket = Get-S3Bucket -BucketName $BucketName
    If (-not $Bucket) {
        Write-Host "Bucket not found!" -ForegroundColor Red
        exit
    }
    $Prefix += ($Prefix.EndsWith("/")) ? "" : "/"

    $s3Keys = Get-S3Object -BucketName $BucketName -Prefix $Prefix
    if ($s3Keys) {
        $s3Keys | Restore-S3Object -CopyLifetimeInDays $CopyLifetime -Tier $Tier | Out-Null
    }
    <#
    .SYNOPSIS
    Restore an S3 folder, i.e. "common prefix", from Glacier.
    .DESCRIPTION
    AWS Powershell Tools for S3 only has the ability to restore a single s3 object from glacier. This function allows you to restore
    all object with a common prefix.
    .PARAMETER BucketName
    The bucket name.
    .PARAMETER Prefix
    The Prefix to restore.
    .PARAMETER CopyLifetime
    The Number of days to keep the restored objects before returning them to glacier.
    .PARAMETER Tier
    The storage tier to restore the objects to. Valid entries are Standard, Expedited, Bulk
    .OUTPUTS
    Response indicating success or failure.
    #>
} 

Function Get-S3RestoreProgress() {
    Param(
        [Parameter(Mandatory)]
        [String]$BucketName,
        [Parameter(ParameterSetName='prefix')]
        [string]$Prefix,
        [Parameter(ParameterSetName='key')]
        [string]$Key
    )
    #valudate buckey name
    $Bucket = Get-S3Bucket -BucketName $BucketName
    If (-not $Bucket) {
        Write-Host"Bucket not found" -ForegroundColor Red
        exit
    }
    if ($Key) {
        Get-S3ObjectMetadata -BucketName $BucketName -Key $key | Select-Object @{Name="Key";Expression={$Key}},RestoreInProgress, RestoreExpiration
    } else {
        $Prefix += ($Prefix.EndsWith("/")) ? "" : "/"

        $s3Keys = Get-S3Object -BucketName $BucketName -Prefix $Prefix

        $S3Keys |Foreach-Object {$Key = $_.Key; $_ | Get-S3ObjectMetadata | Select-Object @{Name="Key";Expression={$Key}},RestoreInProgress, RestoreExpiration}
    }
    <#
    .SYNOPSIS
    Display the progress of a Glacier Restore.
    .PARAMETER BucketName
    The bucket name.
    .PARAMETER Prefix
    The prefix to check the restore progress. Required if Key is omitted.
    .PARAMETER Key
    The full key of an object to check. Required if Prefix is omitted.
    #>
}