
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

function Get-IAMGroupPermissions() {
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$GroupName
    )

    $IamGroup = (Get-IAMGroup -GroupName $GroupName).Group 


    $Group = [PsCustomObject]@{
        Arn = $IamGroup.Arn
        GroupName = $IamGroup.GroupName
        GroupId = $IamGroup.GroupId
        CreateDate = $IamGroup.CreateDate
        Policies = [List[PsObject]]::New()
    }
    
    # Get any inline policies

    $GroupInlinePolicies = Get-IAMGroupPolicyList -GroupName $GroupName
    if ($GroupInlinePolicies) {            
        foreach ($GroupInlinePolicy in $GroupInLinePolicies) {
            $iamPolicy = Get-IAMGroupPolicy -PolicyName $GroupInlinePolicy -GroupName $GroupName
            $PolicyDocument = [HttpUtility]::UrlDecode($IamPolicy.PolicyDocument)

            $Policy = [PsCustomObject]@{
                PolicyName = $IamPolicy.PolicyName
                Arn = "N/A"
                PolicyDocument = $PolicyDocument
                PolicyType = 'Inline'
            }
            $Group.Policies.Add($Policy)
        }
    }

    # Get any Group Attached Policies.
    $GroupAttachedPolicies = Get-IAMAttachedGroupPolicyList -GroupName $GroupName
    if ($GroupAttachedPolicies) {
        foreach($GroupAttachedPolicy in $GroupAttachedPolicies) {
            $IamPolicy = Get-IamPolicy -PolicyArn $GroupAttachedPolicy.PolicyArn
            if ($IamPolicy.arn -like "*aws:policy*") {
                $PolicyTYpe = 'AWS Managed'
            } else {
                $PolicyType = 'Customer Managed'
            }
            # Get the default version Id
            $VersionId = (Get-IAMPolicyVersions -PolicyArn $IamPolicy.Arn | Where-Object {$_.IsDefaultVersion -eq $True}).VersionId
            $PolicyDocument = [HttpUtility]::UrlDecode((Get-IAMPolicyVersion -PolicyArn $IamPolicy.Arn -VersionId $VersionId).Document)
            $Policy = [PsCustomObject]@{
                PolicyName = $IamPolicy.Name
                Arn = $IamPolicy.Arn
                PolicyDocument = $PolicyDocument.ToString()
                PolicyType = $PolicyType
            }
            $Group.Policies.Add($Policy)
        }
    }

    return $Group

    <#
    .SYNOPSIS
    Returns the permissions assigned to this group.
    .DESCRIPTION
    Returns an object containing the permissions and policies assigned to a group.
    .PARAMETER GroupName
    The name of the group.
    .OUTPUTS
    An object with the following properties.
    .NOTES
    The Group Object contains the following properties.

    Name            Type
    --------------- -------------
    Arn             String
    GroupName       String
    GroupId         String
    CreateData      DateTime
    Policies        Collection

    The Policies property contains a collection of Policy objects with the following properties.

    Name            Type
    --------------- ----------------------
    PolicyName      String
    Arn             String (Applicable for managed policies only)
    PolicyDocument  JSON
    PolicyType      String (either 'inline', 'AWSManaged', or 'Customer Managed')
    #>
}

function Get-IAMUserPermissions() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$Username
    )

    # Get the IAM User
    $IamUser = Get-IAMUser -UserName $Username

    # Create a PSObject for the User Permissions
    $UserPermissions = [psCustomObject]@{
        Arn = $IamUser.Arn
        CreateDate = $IamUser.CreateDate
        PasswordLastUsed = $IamUser.PasswordLastUsed
        UserId = $IamUser.UserId
        UserName = $IamUser.UserName
        Policies = [List[PsObject]]::New()
        Groups = [List[PsObject]]::New()
    }

    #Get any inline policies assigned to the user.
    $UserInlinePolicies = Get-IamUserPolicyList -UserName $IamUser.Username
    foreach ($UserInlinePolicy in $UserInlinePolicies) {
        $UserPolicy = Get-IAMUserPolicy -PolicyName $UserInlinePolicies.PolicyName -UserName $IamUser.UserName
        $PolicyDocument = [HttpUtility]::UrlDecode($UserPolicy.PolicyDocument)
        $Policy = [PsCustomObject]@{
                PolicyName = $IamPolicy.Name
                Arn = "N/A"
                PolicyDocument = $PolicyDocument
                PolicyType = 'Inline'
            }
        $UserPermissions.InlinePolicies.Add($Policy)
    }

    # Get an attached pPolicies for this user.
    $UserAttachedPolicies = Get-IAMAttachedUserPolicies -UserName $Username
    foreach ($UserAttachedPolicy in $UserAttachedPolicies) {
        $IamPolicy = Get-IAMPolicy -PolicyArn $UserAttachedPolicy.PolicyArn
        if ($IamPolicy.Arn -like "*aws:policy") {
            $PolicyType | Add-Member -MemberType NoteProperty -Name "PolicyType" -Value "AWS Managed"
        } else {
            $PolicyType | Add-Member -MemberType NoteProperty -Name "MemberType" -Value "Customer Managed"
        }
        $PolicyDocument = [HttpUtility]::UrlDecode($IamPolicy.PolicyDocument)
        $Policy = [PsCustomObject]@{
                PolicyName = $IamPolicy.Name
                Arn = $IamPolicy.Arn
                PolicyDocument = $PolicyDocument.ToString()
                PolicyType = $PolicyType
            }
        UserPermissions.Policies.Add($Policy)
    }
    
    # Group
    $UserGroups = Get-IAMGroupForUser -UserName $IamUser.Username
    foreach ($UserGroup in $UserGroups) {   
        $Group = Get-IAMGroupPermissions -GroupName $UserGroup.GroupName
        $UserPermissions.Groups.Add($Group)
    }

    return $UserPermissions

    <#
    .SYNOPSIS
    Returns permissions assigned to a user.
    .DESCRIPTION
    Returns an object containing user information and the permissions and policies assigned to a user. 
    Also contains a collection of group objects the User is a member of (See Get-IAMGroupPermissions).
    .PARAMETER Username
    The Name of the user.
    .OUTPUTS
    An object containing user information and policies assigned to the user.
    .NOTES
    The User Object contains the following properties.

    Name                Type
    ------------------- ----------------------
    Arn                 String
    Username            String
    UserId              String
    CreateDate          DateTime
    PasswordLastUsed    DateTime
    Policies            Collection of Policies assigned to the group.
    Groups              Groups the user is a member of (Group Objects, see Get-IAMGroupPermissions)

    The Policy objects in the Policies collection have the following properties.

    Name                Type
    ------------------- ---------------------
    PolicyName          String
    Arn                 String (Applicable for managed policies only)
    PolicyDocument      JSON
    PolicyType          String (either 'inline', 'AWSManaged', or 'Customer Managed')
    #>
}

function Get-IAMRolePermissions() {
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$RoleName
    )

    $IamRole = Get-IAMRole -RoleName $RoleName

    $AssumeRolePolicyDocument = [HttpUtility]::UrlDecode($IamRole.AssumeRolePolicyDocument)


    $Role = [PSCustomObject]@{
        Arn = $IamRole.Arn
        RoleName = $IamRole.RoleName
        RoleId = $IamRole.RoleId
        RoleLastUsed = $IamRole.RoleLastUsed
        CreateDate = $IamRole.CreateDate
        MaxSessionDuration = $IamRole.MaxSessionDuration
        AssumeRolePolicyDocument = $AssumeRolePolicyDocument
        Policies = [List[PsObject]]::New()
    }

    # Get inline policies

    $RoleInlinePolicies = Get-IAMRolePolicies -RoleName $RoleName
    If ($RoleInlinePolicies) {
        foreach ($RoleInlinePolicy in $RoleInlinePolicies) {
            $IamPolicy = Get-IAMRolePolicy -PolicyName $RoleInlinePolicy -RoleName $RoleName
            $PolicyDocument = [HttpUtility]::UrlDecode($IamPolicy.PolicyDocument)

            $Policy = [PSCustomObject]@{
                PolicyName = $IamPolicy.PolicyName
                Arn = "N/A"
                PolicyDocument = $PolicyDocument
                PolicyType = 'InLine'
            }
            $Role.Policies.Add($Policy)
        }
    }
    
    # Get any attached Policies
    $RoleAttachedPolicies = Get-IAMAttachedRolePolicies -RoleName $RoleName
    if ($RoleAttachedPolicies) {
        foreach ($RoleAttachedPolicy in $RoleAttachedPolicies) {
            $IamPolicy = Get-IamPolicy -PolicyArn $RoleAttachedPolicy.PolicyArn
            if ($IamPolicy.arn -like "*aws:policy") {
                $PolicyType = 'AWS Managed'
            } else {
                $PolicyType = 'Customer Managed'
            }
            $VersionId = (Get-IAMPolicyVersions -PolicyArn $IamPolicy.PolicyArn | Where-Object {$_.IsDefault -eq $True}).VersionId
            $PolicyDocument = [HttpUtility]::UrlDecode((Get-IAMPolicyVersion -PolicyArn $IamPolicy.Arn -VersionId $VersionId).Document)
            $Policy = [PSCustomObject]@{
                PolicyName = $IamPolicy.Name
                Arn = $IamPolicy.Arn
                PolicyDocument = $PolicyDocument
                $PolicyType = $PolicyType
            }
            $Role.Policies.Add($Policy)
        }
    }

    return $Role

    <#
    .SYNOPSIS
    Returns the permissions assigned to a role.
    .DESCRIPTION
    Returns an object containing the permissions and policies assigned to a role.
    .PARAMETER RoleName
    The name of the role.
    .OUTPUTS
    An object with the following properties.
    .NOTES
    The Role object has the following properties.

    Name                        Type
    --------------------------- ----------------
    Arn                         String
    RoleName                    String
    RoleId                      String
    CreateDate                  DateTime
    MaxSessionDuration          Integer
    AssumeRolePolicyDocument    JSON
    Policies                    Collection og Policies assigned to the role.

    The Policy objects in the Policies collection have the following properties.

    Name                Type
    ------------------- -------------------
    PolicyName          String
    Arn                 String (Applicable for managed policies only)
    PolicyDocument      JSON
    PolicyType          String (either 'inline', 'AWSManaged', or 'Customer Managed')
    #>
}

function Get-EC2InstanceList() {
    [CmdletBinding()]
    Param(
        [string]$ProfileName,
        [switch]$IncludeAccountId,
        [switch]$NoProgress
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
        if (-not $NoProgress) {
            Write-Progress -Activity "Getting EC2 INstances" -Status $Name -PercentComplete (($EC2Instances.IndexOf($EC2Instance) / $EC2Instances.Count) * 100)
        }
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
            PublicIPAddress = $EC2Instance.PublicIpAddress
            PublicDNSName = $EC2Instance.PublicDnsName
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
    <#
    .SYNOPSIS
    Returns a list of EC2 Instances
    .DESCRIPTION 
    REturns a list of EC2 INstances with relevant properties.
    .PARAMETER ProfileName
    The saved EC2 profile to used to retrieve the data.
    .PARAMETER IncludeAccountId
    Include the account ID the EC2 INstance is in.
    .OUTPUTS
    A collection of custom EC2 Instances.
    .NOTES
    Each EC2 instance object has the following properties.

    Name                Type        Description
    ------------------- ---------   -------------------------
    Name                String      Name of the Instance.
    InstanceId          String      Instance identifier.
    InstanceState       String      The state of the instance (Stopped or Running).
    InstanceType        String      The Instance type.
    AvailabilityZone    String      The availability zone the instance is in.
    SecurityGroup       String      The Security Groups assigned to the Instance.
    KeyName             String      The KMS Key assigned to the Instance.
    PrivateIpAddress    String      The Private IP address assigned to the Instance.
    PrivateDNSName      String      The Private DNS Name assigned to the instance.
    PublicIPAddress     String      The Public IP address assigned tot he instance.
    PublicDNSName       String      The Public DNS name assigned to the instance.
    SubnetId            String      The Subnet Assigned to the instance.
    Subnet              String      The Subnet Name.
    Platform            String      The Instance Platform i.e Windows Linux
    #>
}

function Get-DiskMappings() {
    
    function Convert-SCSITargetIdToDeviceName {
        param(
            [int]$SCSITargetId
        )

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
      
    # [string[]]$array1 = @()
    # [string[]]$array2 = @()
    # [string[]]$array3 = @()
    # [string[]]$array4 = @()
    
    $Win32_Volumes = Get-CimInstance -ClassName Win32_Volume

    $VolNames = $Win32_Volumes.Name
    $VolIDs = $Win32_Volumes.DeviceID

    #   Get-CimInstance -ClassName Win32_Volume | Select-Object Name, DeviceID | ForEach-Object {
    #     $array1 += $_.Name
    #     $array2 += $_.DeviceID
    #   }
    
    $Serials = [List[PsObject]]::New()
    $FriendlyNames = [List[PsObject]]::New()

    foreach ($VolID in $VolIDs) {
        Write-Host "Getting disk information for volume $VolId" -ForegroundColor Green
        $disk = Get-Volume -Path $VolID | Get-Partition | Get-Disk
        $Serials.Add(($Disk.SerialNumber -replace "_[^ ]*$" -replace "vol", "vol-"))
        $FriendlyNames.Add($Disk.FriendlyName)
    }
    # $i = 0
    # While ($i -ne ($array2.Count)) {
    # $array3 += ((Get-Volume -Path $array2[$i] | Get-Partition | Get-Disk).SerialNumber) -replace "_[^ ]*$" -replace "vol", "vol-"
    # $array4 += ((Get-Volume -Path $array2[$i] | Get-Partition | Get-Disk).FriendlyName)
    # $i ++
    # }

    $DiskInfo = @{}
    foreach ($VolName in $VolNames) {
        $i = $VolNames.IndexOf($VolName)
        $Drive = [PSCustomObject]@{
            DriveLetter = ($VolName.replace(':\\', ''))
            VolumeId = $VolIDs[$i]
            Serial = $Serials[$i]
            FriendlyName = $FriendlyNames[$i]
        }
        $DiskInfo.Add($VolName.replace(':\',''), $Drive)
    }
    
    # [array[]]$array = $VolNames, $VolIds, $Serials, $FriendlyNames
    
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
        [array]$VirtualDeviceMap = (Get-EC2InstanceMetadata -Category "BlockDeviceMapping").GetEnumerator() | ForEach-Object {$_}
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
          $BlockDeviceName = Convert-SCSITargetIdToDeviceName((Get-CIMInstance -ClassName Win32_Diskdrive | Where-Object { $_.DeviceID -eq ("\\.\PHYSICALDRIVE" + $DiskDrive.Number) }).SCSITargetId)
          $BlockDeviceName = "/dev/" + $BlockDeviceName
          $BlockDevice = $BlockDeviceMappings | Where-Object { $BlockDeviceName -like "*" + $_.DeviceName + "*" }
          $EbsVolumeID = $BlockDevice.Ebs.VolumeId
          # $VirtualDevice = ($VirtualDeviceMap.GetEnumerator() | Where-Object { $_.Value -eq $BlockDeviceName }).Key | Select-Object -First 1
          $VirtualDevice = $VirtualDeviceMap.Where({$_.Value -eq $BlockDeviceName}).Key | Select-Object -First 1
        }
        ElseIf ($DiskDrive.path -like "*PROD_AMAZON_EC2_NVME*") {
          $BlockDeviceName = Convert-SCSITargetIdToDeviceName((Get-CIMInstance -ClassName Win32_Diskdrive | Where-Object { $_.DeviceID -eq ("\\.\PHYSICALDRIVE" + $DiskDrive.Number) }).SCSITargetId)
          $BlockDevice = $null
          #$VirtualDevice = ($VirtualDeviceMap.GetEnumerator() | Where-Object { $_.Value -eq $BlockDeviceName }).Key | Select-Object -First 1
          $VirtualDevice = $VirtualDeviceMap.Where({$_.Value -eq $BlockDeviceName}).Key | Select-Object -First 1
        }
        ElseIf ($DiskDrive.path -like "*PROD_AMAZON*") {
          if ($DriveLetter -match '^[a-zA-Z0-9]') {
            $DeviceName = $DiskInfo["$DriveLetter"].FriendlyName
            # $i = 0
            # While ($i -ne ($array3.Count)) {
            #   if ($array[2][$i] -eq $EbsVolumeID) {
            #     $DriveLetter = $array[0][$i]
            #     $DeviceName = $array[3][$i]
            #   }
            #   $i ++
            # }
          }
          $BlockDevice = ""         
          $BlockDeviceName = ($BlockDeviceMappings | Where-Object { $_.ebs.VolumeId -eq $EbsVolumeID }).DeviceName
          $VirtualDevice = $VirtualDeviceMap.Where({$_.Value -eq $BlockDeviceName}).Key | Select-Object -First 1
        }
        ElseIf ($DiskDrive.path -like "*NETAPP*") {
          if ($DriveLetter -match '^[a-zA-Z0-9]') {
            $DeviceName = $DiskInfo["$DriveLetter"].FriendlyName
            # $i = 0
            # While ($i -ne ($array3.Count)) {
            #   if ($array[2][$i] -eq $EbsVolumeID) {
            #     $DriveLetter = $array[0][$i]
            #     $DeviceName = $array[3][$i]
            #   }
            #   $i ++
            # }
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
          DriveLetter   = If ($null -eq $DriveLetter) { "N/A" } Else { $DriveLetter };
          EbsVolumeId   = If ($null -eq $EbsVolumeID) { "N/A" } Else { $EbsVolumeID };
          Device        = If ($null -eq $BlockDeviceName) { "N/A" } Else { $BlockDeviceName };
          VirtualDevice = If ($null -eq $VirtualDevice) { "N/A" } Else { $VirtualDevice };
          VolumeName    = If ($null -eq $VolumeName) { "N/A" } Else { $VolumeName };
          DeviceName    = If ($null -eq $DeviceName) { "N/A" } Else { $DeviceName };
        }
    } | Sort-Object Disk | Select-Object Disk, Partitions, DriveLetter, EbsVolumeId, Device, VirtualDevice, DeviceName, VolumeName 

    <#
    .SYNOPSIS 
    LIst disk mappings on an EC2 Instance.
    .DESCRIPTION
    List the disk mappings on an EC2 instance to reference the volume ID with the Windows volume and drive letter.
    This function must be run on an EC2 Windows instance.
    .OUTPUTS
    An array of disk objects.
    #>
}

function Set-SecretVault() {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$VaultName,
        [ValidateSet('Password','None')]
        [string]$Authentication,
        [ValidateSet('Prompt','None')]
        [string]$Interaction
    )

    $Config = Get-SecretStoreConfiguration | Where-Object {$_.Scope -eq "CurrentUser"}

    $Params = @{}

    If ($Authentication) {
        if ($Authentication -ne $Config.Authentication) {
            $Params.Add("Authentication", $Authentication)
        }
    }

    if ($Interaction) {
        if ($Interaction -ne $Config.Interaction) {
            $Params.Add("Interaction", $Interaction)
        }
    }

    If ($Params.Count -gt 0) {
        Set-SecretStoreConfiguration -Scope CurrentUser @Params
    }

    Register-SecretVault -Name $VaultName -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault -AllowClobber

    Write-Host "Vault $VaultName Created"
    <#
    .DESCRIPTION
    Creates a Secrets vault and sets the option configuration parameters.
    Note: If you plan to use this vault for automation purposes you must set Authentication and Interaction to 'None'.
    .PARAMETER VaultName
    The Name of the vault.
    .PARAMETER Authentication
    The type of Authentication, Either 'Password' or 'None'
    .PARAMETER Interaction
    Allow or suppress user interaction. Either 'Prompt' or 'None'. If set to none and the vault requires a password an error will occur.    
    #>
}

function Set-SecureAWSCredentials() {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [String]$ProfileName,
        [Parameter(Mandatory)]
        [string]$AccessKeyId,
        [Parameter(Mandatory)]
        [string]$SecretAccessKey,
        [string]$AccessToken,
        [Parameter(Mandatory)]
        [String]$Region,
        [datetime]$Expiration,
        [string]$VaultName
    )

    $Cred = Get-AWSCredential -ProfileName $ProfileName
    if ($Cred) {
        Remove-AWSCredentialProfile -ProfileName $ProfileName -Force
    }

    $secretIn = @{
    Version=1;
    AccessKeyId= $AccessKeyId;
    SecretAccessKey=$SecretAccessKey;
    SessionToken= $null; #"the AWS session token for temporary credentials";
    #Expiration="ISO8601 timestamp when the credentials expire";
    } 

    if ($Expiration) {
        $ExpDate = $Expiration.ToString("yyyy-MM-dd HH:mm:ss")
        $SecretIn.Add("Expiration", $ExpDate)
    }

    $secret = $secretIn | ConvertTo-Json

    $Params = @{
        Name = $ProfileName
        Secret = $secret
    }
    
    if ($VaultName) {
        $Params.Add("Vault", $VaultName)
    }
    

    Set-Secret @Params

    $CredFile ="{0}/.aws/credentials" -f $home

    # Add-Content -Path $CredFile -Value "[$ProfileName]"
    if ($IsWindows) {
        $content = @"
[$ProfileName]
credential_process = credential_process.cmd = $ProfileName
region = $Region
"@
        Add-Content -Path $CredFile -Value $content
    } else {
        $content = @"
[$ProfileName]
credential_process = credential_process.sh = $ProfileName
region = $Region
"@
        Add-Content -Path $CredFile -Value $content
    }

    <#
    .SYNOPSIS
    Creates a secure entry in the aws credentials file.
    .DESCRIPTION
    Creates a secure entry in the AWS Credentials file. The AWS Keys are stored in a Secret vault created by Set-SecretVault.
    This credential entry uses a credential process. This process calls a script based on the Operation system.
    For Windows: credential_process.cmd
    For Linux/Mac: credential_process.sh
    Copy the appropriate file into a directory that is in the path.
    For Linux the best place is ~/.local/bin
    For Windows any directory that is a in the path. For optimal security create a folder under the user profile and add that path to the User section of the Path Environment variable configuration.
    .PARAMETER ProfileName
    The name of the profile. To set a default profile you must name the profile default.
    .PARAMETER AccessKeyId
    The AWS Access Key ID.
    .PARAMETER SecretAccessKey
    The AWS Secret Access key.
    .PARAMETER Region
    The default AWS Region for this profile.
    .PARAMETER Expiration
    An option expiration date, the stored secret will expire after this date/time.
    .PARAMETER VaultName
    An optional vault name. If omitted, the secret will be created in the default vault. 

    #>
}