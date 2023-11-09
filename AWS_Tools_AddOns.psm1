using namespace System.Collections.Generic
using namespace System.Web

#Requires -Modules @{ModuleName = 'AWS.Tools.Common'; ModuleVersion = '4.1.279'}
#Requires -Modules @{ModuleName = 'Aws.Tools.S3'; ModuleVersion = '4.1.279'}
#Requires -Modules @{ModuleName = 'AWS.Tools.EC2'; ModuleVersion = '4.1.279'}
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
    This function emulates working with folders "Common prefixes" in S3. It will list the files and top level prefixes for a given bucket and prefix.
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
        foreach ($S3Key in $s3Keys) {
            $msg = "Restoring object {0} to {1} for {2} days" -f $s3Key.Key, $Tier, $CopyLifetime
            Write-Host $msg -ForegroundColor Yellow
            $S3Key | Restore-S3Object -CopyLifetimeInDays $CopyLifetime -Tier $Tier -ErrorAction SilentlyContinue | Out-Null
        }
    }
    <#
    .SYNOPSIS
    Restore an S3 folder, i.e. "common prefix", from Glacier.
    .DESCRIPTION
    AWS Powershell Tools for S3 only has the ability to restore a single s3 object from glacier. 
    This function allows you to restore all object with a common prefix.
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
    #validate bucket name
    $Bucket = Get-S3Bucket -BucketName $BucketName
    If (-not $Bucket) {
        Throw "Bucket not found"
    }
    if ($Key) {
        Get-S3ObjectMetadata -BucketName $BucketName -Key $key | Select-Object @{Name="Key";Expression={$Key}},RestoreInProgress, RestoreExpiration
    } else {
        $Prefix += ($Prefix.EndsWith("/")) ? "" : "/"

        $s3Keys = Get-S3Object -BucketName $BucketName -Prefix $Prefix

        
        $S3Keys |Foreach-Object {
            # Remove any by-directional unicode characters the stupid users may have entered into the file path & name
            $Key = $_.Key -replace '\P{IsBasicLatin}'

            $Key | Get-S3ObjectMetadata | Select-Object @{Name="Key";Expression={$Key}},RestoreInProgress, RestoreExpiration}
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
    .OUTPUTS
    An array of AWS S3 Metadata objects. Check the RestoreInProgress property. A value of false indicates the restore has completed.
    #>
}

function Get-IamUserPermissions() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$Username
    )

    $GroupList = [List[psObject]]::New()
    #$InlinePolicyList = [List[psObject]]:New()
    #$PolicyList = [List[psObject]]::New()

    # Get the IAM User
    $IamUser = Get-IAMUser -UserName $Username

    # Create a Hash Table for the User Permissions
    $UserPermissions = @{
        Arn = $IamUser.Arn
        CreateDate = $IamUser.CreateDate
        PasswordLastUsed = $IamUser.PasswordLastUsed
        UserId = $IamUser.UserId
        UserName = $IamUser.UserName
    }

    #Get any inline policies assigned to the user.
    $UserInlinePolicies = Get-IamUserPolicyList -UserName $IamUser.Username
    $UserInlinePolicyList = [List[psObject]]::New()
    foreach ($UserInlinePolicy in $UserInlinePolicies) {
        $UserPolicy = Get-IAMUserPolicy -PolicyName $UserInlinePolicies.PolicyName -UserName $IamUser.UserName
        $PolicyDocument = [HttpUtility]::UrlDecode($UserPolicy.PolicyDocument)
        $UserInlinePolicyList.Add(
            [PSCustomObject]@{
                PolicyName = UserPolict.PolicyName
                PolicyDocument = $PolicyDocument
            }
        )        
    }
    $UserPermission.Add("InLinePolicies", $UserInlinePolicyList.ToArray())
    

    # Retrieve the Users Group Membership
    $Groups = Get-IAMGroupForUser -UserName $IamUser.Username
    foreach ($Group in $Groups) {   
        $GroupPermission = @{
            GroupName = $Group.GroupName
            GroupId = $Group.GroupId
        } 

        # Get any inline policies
        $GroupInlinePolicyList = [List[psObject]]::New()
        $GroupInlinePolicies = Get-IAMGroupPolicyList -GroupName $Group.Name
        if ($GroupInlinePolicies) {
            $GroupInlinePolicyList = [List[psObject]]::New()
            foreach ($GroupInlinePolicy in $GroupInLinePolicies) {
                $InlinePolicyDocument = [HttpUtility]::UrlDecode((Get-IAMGroupPolicy -GroupName $Group.Name -PolicyName $GroupInlinePolicy.PolicyName).PolicyDocument)
                $InlinePolicyList.Add(
                    [PSCustomObject]@{
                        PolicyName = $GroupInlinePolicy.PolicyName
                        PolicyDocument = $InlinePolicyDocument
                    }
                )
            }
            $GroupPermission.Add("InlinePermission",$InlinePolicyList.ToArray())
        }

        # Get any Managed Policies.
    }

}

function Get-EC2InstanceList() {
    [CmdletBinding()]
    Param(
        [string]$ProfileName,
        [switch]$IncludeAccountId
    )

    If ($ProfileName) {
        try {
            Set-AWSCredential -ProfileName $ProfileName
        } catch {
            throw $_
        }
    }

    $EC2InstanceList = [List[psObject]]::New()

    $EC2Instances = (Get-EC2instance).Instances
    foreach ($EC2Instance in $EC2INstances) {
        $Tags = $EC2Instance.Tags
        $Name = $Tags[$Tags.Key.IndexOf("Name")].Value
        $State = $EC2Instance.State.Name
        $AvailabilityZone = (Get-EC2InstanceStatus -InstanceId $EC2Instance.InstanceId -IncludeAllInstance $true).AvailabilityZone
        $SecurityGroup = $EC2INstance.SecurityGroups.GroupName -join ","
        $SubnetTags = (Get-EC2Subnet -SubnetId $EC2Instance.SubnetId).Tags 
        if ($SubnetTags) {
            $SubnetName = $SubnetTags[$SubnetTags.Key.IndexOf("Name")].Value
        } else {
            $SubnetName = $null
        }

        $Instance = [PSCustomObject]@{
            Name = $Name
            InstanceId = $EC2Instance.InstanceId
            InstanceState = $State
            InstanceType = $EC2Instance.InstanceType
            AvailabilityZone = $AvailabilityZone
            SecurityGroup = $SecurityGroup
            KeyName = $EC2Instance.KeyName
            PrivateIpAddress = $EC2Instance.PrivateIpAddress
            PrivateDnsName = $EC2Instance.PrivateDnsName
            SubnetId = $EC2Instance.SubnetId
            Subnet = $SubnetName
            LaunchTime = $EC2Instance.LaunchTime
            Platform = $EC2Instance.PlatformDetails
        }

        If ($IncludeAccountId) {
            $AccountId = (Get-STSCallerIdentity).Account
            $Instance | Add-Member -MemberType NoteProperty -Name "AccountId" -Value $AccountId
        }
        $EC2InstanceList.Add($Instance)
    }
    return $EC2InstanceList.ToArray()
}

function Get-DiskMappings() {
    function Convert-SCSITargetIdToDeviceName {
        param([int]$SCSITargetId)
        If ($SCSITargetId -eq 0) {
          return "sda1"
        }
        $deviceName = "xvd"
        If ($SCSITargetId -gt 25) {
          $deviceName += [char](0x60 + [int]($SCSITargetId / 26))
        }
        $deviceName += [char](0x61 + $SCSITargetId % 26)
        return $deviceName
      }
      
      [string[]]$array1 = @()
      [string[]]$array2 = @()
      [string[]]$array3 = @()
      [string[]]$array4 = @()
      
      Get-CimInstance -ClassName Win32_Volume | Select-Object Name, DeviceID | ForEach-Object {
        $array1 += $_.Name
        $array2 += $_.DeviceID
      }
      
      $i = 0
      While ($i -ne ($array2.Count)) {
        $array3 += ((Get-Volume -Path $array2[$i] | Get-Partition | Get-Disk).SerialNumber) -replace "_[^ ]*$" -replace "vol", "vol-"
        $array4 += ((Get-Volume -Path $array2[$i] | Get-Partition | Get-Disk).FriendlyName)
        $i ++
      }
      
      [array[]]$array = $array1, $array2, $array3, $array4
      
      Try {
        $InstanceId = Get-EC2InstanceMetadata -Category "InstanceId"
        $Region = Get-EC2InstanceMetadata -Category "Region" | Select-Object -ExpandProperty SystemName
      }
      Catch {
        Write-Host "Could not access the instance Metadata using AWS Get-EC2InstanceMetadata CMDLet.
      Verify you have AWSPowershell SDK version '3.1.73.0' or greater installed and Metadata is enabled for this instance." -ForegroundColor Yellow
      }
      Try {
        $BlockDeviceMappings = (Get-EC2Instance -Region $Region -Instance $InstanceId).Instances.BlockDeviceMappings
        $VirtualDeviceMap = (Get-EC2InstanceMetadata -Category "BlockDeviceMapping").GetEnumerator() | Where-Object { $_.Key -ne "ami" }
      }
      Catch {
        Write-Host "Could not access the AWS API, therefore, VolumeId is not available.
      Verify that you provided your access keys or assigned an IAM role with adequate permissions." -ForegroundColor Yellow
      }
      
      Get-disk | ForEach-Object {
        $DriveLetter = $null
        $VolumeName = $null
        $VirtualDevice = $null
        $DeviceName = $_.FriendlyName
      
        $DiskDrive = $_
        $Disk = $_.Number
        $Partitions = $_.NumberOfPartitions
        $EbsVolumeID = $_.SerialNumber -replace "_[^ ]*$" -replace "vol", "vol-"
        if ($Partitions -ge 1) {
          $PartitionsData = Get-Partition -DiskId $_.Path
          $DriveLetter = $PartitionsData.DriveLetter | Where-object { $_ -notin @("", $null) }
          $VolumeName = (Get-PSDrive | Where-Object { $_.Name -in @($DriveLetter) }).Description | Where-object { $_ -notin @("", $null) }
        }
        If ($DiskDrive.path -like "*PROD_PVDISK*") {
          $BlockDeviceName = Convert-SCSITargetIdToDeviceName((Get-WmiObject -Class Win32_Diskdrive | Where-Object { $_.DeviceID -eq ("\\.\PHYSICALDRIVE" + $DiskDrive.Number) }).SCSITargetId)
          $BlockDeviceName = "/dev/" + $BlockDeviceName
          $BlockDevice = $BlockDeviceMappings | Where-Object { $BlockDeviceName -like "*" + $_.DeviceName + "*" }
          $EbsVolumeID = $BlockDevice.Ebs.VolumeId
          $VirtualDevice = ($VirtualDeviceMap.GetEnumerator() | Where-Object { $_.Value -eq $BlockDeviceName }).Key | Select-Object -First 1
        }
        ElseIf ($DiskDrive.path -like "*PROD_AMAZON_EC2_NVME*") {
          $BlockDeviceName = (Get-EC2InstanceMetadata -Category "BlockDeviceMapping").ephemeral((Get-WmiObject -Class Win32_Diskdrive | Where-Object { $_.DeviceID -eq ("\\.\PHYSICALDRIVE" + $DiskDrive.Number) }).SCSIPort - 2)
          $BlockDevice = $null
          $VirtualDevice = ($VirtualDeviceMap.GetEnumerator() | Where-Object { $_.Value -eq $BlockDeviceName }).Key | Select-Object -First 1
        }
        ElseIf ($DiskDrive.path -like "*PROD_AMAZON*") {
          if ($DriveLetter -match '[^a-zA-Z0-9]') {
            $i = 0
            While ($i -ne ($array3.Count)) {
              if ($array[2][$i] -eq $EbsVolumeID) {
                $DriveLetter = $array[0][$i]
                $DeviceName = $array[3][$i]
              }
              $i ++
            }
          }
          $BlockDevice = ""
          $BlockDeviceName = ($BlockDeviceMappings | Where-Object { $_.ebs.VolumeId -eq $EbsVolumeID }).DeviceName
        }
        ElseIf ($DiskDrive.path -like "*NETAPP*") {
          if ($DriveLetter -match '[^a-zA-Z0-9]') {
            $i = 0
            While ($i -ne ($array3.Count)) {
              if ($array[2][$i] -eq $EbsVolumeID) {
                $DriveLetter = $array[0][$i]
                $DeviceName = $array[3][$i]
              }
              $i ++
            }
          }
          $EbsVolumeID = "FSxN Volume"
          $BlockDevice = ""
          $BlockDeviceName = ($BlockDeviceMappings | Where-Object { $_.ebs.VolumeId -eq $EbsVolumeID }).DeviceName
        }
        Else {
          $BlockDeviceName = $null
          $BlockDevice = $null
        }
        New-Object PSObject -Property @{
          Disk          = $Disk;
          Partitions    = $Partitions;
          DriveLetter   = If ($DriveLetter -eq $null) { "N/A" } Else { $DriveLetter };
          EbsVolumeId   = If ($EbsVolumeID -eq $null) { "N/A" } Else { $EbsVolumeID };
          Device        = If ($BlockDeviceName -eq $null) { "N/A" } Else { $BlockDeviceName };
          VirtualDevice = If ($VirtualDevice -eq $null) { "N/A" } Else { $VirtualDevice };
          VolumeName    = If ($VolumeName -eq $null) { "N/A" } Else { $VolumeName };
          DeviceName    = If ($DeviceName -eq $null) { "N/A" } Else { $DeviceName };
        }
      } | Sort-Object Disk | Format-Table -AutoSize -Property Disk, Partitions, DriveLetter, EbsVolumeId, Device, VirtualDevice, DeviceName, VolumeName      
}