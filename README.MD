# AWS_Tools_AddOns Module

Additional tools for working with AWS.Tools for Powershell

Author: Cliff Williams

ModuleVersion: 1.0.0

Company Name: Balfour Beatty US

Copyright: (c) Balfour Beatty US. All rights reserved.

License: [Microsoft Public License](https://opensource.org/licenses/MS-PL)

## Helper functions for working with AWS in Powershell

These functions were created for working with AWS S3 in PowerShell.

AWS S3 does not have the concept of folders. While browsing S3 buckets in the AWS console it appears the show folder you can drill down into, these are not actually folders in the Windows Explorer sense. They are just a common prefix that an object has.

For example:
An object listed in the console as:

* Folder1
  * Folder2
    * file.txt

Actually has the object key as /Folder1/Folder2/file.txt

The Get-S3Object function in the AWS.Tools.S3 module will return ALL object that match the provided prefix. So in our example:

```powershell
Get-S3Object -BucketName mybucket -Prefix Folder1\
```

Will return all objects with a prefix beginning with 'Folder1'. In our example that's may not be bad but in an S3 bucket with hundreds or thousands of objects with many longer prefixes this becomes very cumbersome to find the object(s) you are looking for.

The Get-S3Folder function lets you return ONLY the object that share a common prefix at the level of the provided prefix.

With our example above.

```powershell
Get-S3Folder -BucketName mybucket -Prefix Folder1
```

Will return an array containing one key object with the value:
Folder1/Folder2

The command:

```powershell
Get-S3Folder -BucketName mybucket -Prefix Folder1\Folder2
```

Will return an array containing one Key objects with the value:
Folder1/Folder2/file.txt

This makes it easy to find objects or prefixes you are looking for.
Lets say you have an S3 bucket with thousands of objects with very deep prefixes. Now you want to find the prefix under the 'projects' "folder" that contains "Highway-196". You can do that with the following:

```powershell
Get-S3Folder -BucketName projectfiles -Prefix projects | Where-Object {$_.Key -like "*Highway-196*"}
```

The returns a single key object with the value:
projects/Highway-196-Project"

Another issue with the standard S3 functions is restoring S3 objects from Glacier. The Restore-S3Object function can only restore a single object. While you could gather an array of objects and pipe the to this command that could get tedious. The Restore-S3Folder function makes this quite easy.

Using the "Highway 196" example above. We have no know that the common prefix value for the Highway 196 project files is "projects/Highway-196-Project"

So to restore all the objects that have a common prefix (are in the folder and sub-folders) "Highway-196-Project" We would do:

```powershell
Restore-S3Folder -BucketName projectfiles -Prefix 'projects/Highway-196-Project' -CopyLifeTime 90 -Tier Standard
```

Where CopyLifeTime is the number of says to keep the items in restored to the storage class and Tier is the storage class to restore the items to.

Standard Glacier restores can take up to 4 hours while deep glacier restores can take 12-24 hours. So, before you can download the items you need to know if the restore has completed. This again is not easy with the standard functions. So now we can use Get-S3RestoreProgress.

For our example above:

```powershell
Get-S3RestoreProgress -BucketName projectfiles -Prefix 'projects/Highway-196-Project' 
```

This will return an array of objects for each object with the common prefix (In the folder and sub-folders) with these properties.

|Property | Value |
| - | - |
| Key | The full key of the object |
| RestoreInProgress | True of the restore is in progress, False if completed |
| RestoreExpiration | The date the item expires and returns to Glacier |

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
| <nobr>MaxServiceCallHistory</nobr> |  | Int32 | To get the common prefixes we call the $AWSHistory.LastCommand. By default that only returns the last 10 commands. So we set this to 50 as our default. This is usually fine for most uses unless you have a prefix with lots of sub-prefixes and files. | false | false | 50 |

### Outputs

* An array of prefixes and/or files.

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

AWS Powershell Tools for S3 only has the ability to restore a single s3 object from glacier. This function allows you to restore all object with a common prefix.

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

* Response indicating success or failure.
