function Get-S3Folder () {
    Param(
        [Parameter(Mandatory = $true )]
        [String]$BucketName,
        [String]$Prefix,
        [switch]$Files,
        [switch]$Folders,
        [Int]$MaxServiceCallHistory
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