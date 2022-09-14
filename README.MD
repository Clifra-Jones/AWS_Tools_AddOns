# AWS_Tools_AddOns Module

Additional tools for working with AWS.Tools for Powershell

Author: Cliff Williams

ModuleVersion: 1.0.0

CompanyName: Balfour Beatty US

Copyright: (c) Balfour Beatty US. All rights reserved.

## Helper function for working with AWS in Powershell.

## Get-S3Folder

### Synopsis

List S3 Folders

### Description

This function emulates working with folders "Common prefixes" in S3. It will list the files and top level keys for a given bucket and prefix.

### Syntax

```powershell
Get-S3Folder [-BucketName] <String> [[-Prefix] <String>] [-Files] [-Folders] [[-MaxServiceCallHistory] <Int32>] [<CommonParameters>]
```

### Parameters

| Name  | Alias  | Type  | Description | Required? | Pipeline Input | Default Value |
| - | - | - | - | - | - | - |
| <nobr>BucketName</nobr> |  | String | The name of the bucket | true | false |  |
| <nobr>Prefix</nobr> |  | String | The prefix to list. | false | false |  |
| <nobr>Files</nobr> |  | SwitchParameter | Only return the files in the top level prefix. | false | false | False |
| <nobr>Folders</nobr> |  | SwitchParameter | Only return the folders in the top level prefix | false | false | False |
| <nobr>MaxServiceCallHistory</nobr> |  | Int32 | To get the common prefixes we call the $AWSHistory.LastCommand. By default that only returns the last 10 commands. So we set this to 50 as our default. This is usually fine for most uses unless you have a prefix with lot of sub-prefixes and files. | false | false | 50 |

### Outputs

- An array of prefixes and/or files.

## Get-S3RestoreProgress

### Synopsis

Display the progress of a Glacier Restore.

### Description

### Syntax

```powershell
Get-S3RestoreProgress -BucketName <String> [-Prefix <String>] [<CommonParameters>]

Get-S3RestoreProgress -BucketName <String> [-Key <String>] [<CommonParameters>]
```

### Parameters

| Name  | Alias  | Type  | Description | Required? | Pipeline Input | Default Value |
| - | - | - | - | - | - | - |
| <nobr>BucketName</nobr> |  | String | The bucket name. | true | false |  |
| <nobr>Prefix</nobr> |  | String | The prefix to check the restore progress. Required if Key is omitted. | false | false |  |
| <nobr>Key</nobr> |  | String | The full key of an object to check. Required if Prefix is omitted. | false | false |  |

## Restore-S3Folder

### Synopsis

Restore an S3 folder, i.e. "common prefix", from Glacier.

### Description

AWS Powershell Tools for S3 only has the ability to restore a single s3 object from glacier. This function allows you to restore<br>all object with a common prefix.

### Syntax

```powershell
Restore-S3Folder [-BucketName] <String> [-Prefix] <String> [-CopyLifetime] <Int32> [-Tier] <String> [<CommonParameters>]
```

### Parameters

| Name  | Alias  | Type  | Description | Required? | Pipeline Input | Default Value |
| - | - | - | - | - | - | - |
| <nobr>BucketName</nobr> |  | String | The bucket name. | true | false |  |
| <nobr>Prefix</nobr> |  | String | The Prefix to restore. | true | false |  |
| <nobr>CopyLifetime</nobr> |  | Int32 | The Number of days to keep the restored objects before returning them to glacier. | true | false | 0 |
| <nobr>Tier</nobr> |  | String | The storage tier to restore the objects to. Valid entries are Standard, Expedited, Bulk | true | false |  |

### Outputs

- Response indicating success or failure.
