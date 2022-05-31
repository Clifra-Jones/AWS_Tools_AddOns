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
} 

Function Get-S3RestoreProgress() {
    Param(
        [Parameter(Mandatory)]
        [String]$BucketName,
        [Parameter(Mandatory)]
        [string]$Prefix
    )
    #valudate buckey name
    $Bucket = Get-S3Bucket -BucketName $BucketName
    If (-not $Bucket) {
        Write-Host"Bucket not found" -ForegroundColor Red
        exit
    }
    $Prefix += ($Prefix.EndsWith("/")) ? "" : "/"

    $s3Keys = Get-S3Object -BucketName $BucketName -Prefix $Prefix

    $S3Keys |Foreach-Object {$Key = $_.Key; $_ | Get-S3ObjectMetadata | Select-Object @{Name="Key";Expression={$Key}},RestoreInProgress, RestoreExpiration}
}
