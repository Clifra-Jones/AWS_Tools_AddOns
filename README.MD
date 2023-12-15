# AWS_Tools_AddOns Module

Additional tools for working with AWS.Tools for Powershell

Author: Cliff Williams

ModuleVersion: 1.0.0

Company Name: Balfour Beatty US

Copyright: (c) Balfour Beatty US. All rights reserved.

License: [Microsoft Public License](https://opensource.org/licenses/MS-PL)

## Helper functions for working with AWS in Powershell

These functions were created for working with AWS in PowerShell.

### Aws S3 Helper Functions

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

Will return all objects with a prefix beginning with 'Folder1'. In our example that may not be bad but in an S3 bucket with hundreds or thousands of objects with many longer prefixes this becomes very cumbersome to find the object(s) you are looking for.

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

This returns a single key object with the value:
projects/Highway-196-Project"

Another issue with the standard S3 functions is restoring S3 objects from Glacier. The Restore-S3Object function can only restore a single object. While you could gather an array of objects and pipe them to this command that could get tedious. The Restore-S3Folder function makes this quite easy.

Using the "Highway 196" example above. We now know that the common prefix value for the Highway 196 project files is "projects/Highway-196-Project"

So to restore all the objects that have a common prefix (are in the folder and sub-folders) "Highway-196-Project" We would do:

```powershell
Restore-S3Folder -BucketName projectfiles -Prefix 'projects/Highway-196-Project' -CopyLifeTime 90 -Tier Standard
```

Where CopyLifeTime is the number of days to keep the items in the restored storage class and Tier is the storage class to restore the items to.

Standard Glacier restores can take up to 4 hours while deep glacier restores can take 12-24 hours. So, before you can download the items you need to know if the restore has completed. This again is not easy with the standard functions. So now we can use Get-S3RestoreProgress.

For our example above:

```powershell
Get-S3RestoreProgress -BucketName projectfiles -Prefix 'projects/Highway-196-Project' 
```

This will return an array of objects for each object with the common prefix (In the folder and sub-folders) with these properties.

|Property | Value |
| - | - |
| Key | The full key of the object |
| RestoreInProgress | True if the restore is in progress, False if completed |
| RestoreExpiration | The date the item expires and returns to Glacier |

### EC2 Helper Functions

#### Get-EC2Instances

This function returns a list of custom EC2 Instance objects with valuable information about the instance. This information is gathered from many sources that the standard EC2 Instance object does not contain.

### IAM Helper Functions

There are 2 functions for getting the permissions (inline and attached Policies) assigned to IAM Users, Groups, and Roles

Get-IAMUserPermissions
Get-IAMGroupPermissions
Get-IAMRolePermissions

See the [Module reference](docs/reference.html) for more details on these functions.
