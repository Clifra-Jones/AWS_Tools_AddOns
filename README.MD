# AWS Toold Add-Ons

Additional tools for working with AWS.Tools for Powershell

Author: Cliff Williams

Helper function for working with AWS in Powershell.

### Get-S3Folder

* **Description**: This function emulates working with folders (Common prefixes) in S3. It will list the files and top level keys for a given bucket and prefix.

* **Parameters**:
  * **BucketName**:
    * **Mandatory**: True
    * **Type**: String
    * **Description**: The name of the bucket (must be all lower case)
  * **Prefix**:
    * **Mandatory**: True
    * **Type**: String
    * **Description**:    The prefix to list.
  * **MaxServiceCallHistory**:
    * **Type**: Integer
    * **Default**: 50
    * **Description**:  To get the common prefixes we call the $AWSHistory.LastCommand. By default that only returns the last 10 commands.
                        So we set this to 50 as our default. This is usually fine for most uses unless you have a prefix with lot of sub-prefixes (Folders) and files.
  * **Files**:
    * **Type**: Switch
    * **Description**: Only return the files in the top level prefix.
  * **Folders**:
    * **Type**: switch
    * **Description**:    Only return the folders (Common Prefixes) in the top level prefix
  
    Note: If both these parameters are excluded all files and folders are returned

### Restore-S3Folder

**Description**:    AWS Powershell Tools for S3 only has the ability to restore a single s3 object from glacier. This finction allows you to restore
                all object with a common prefix (Folder).

* **Parameters**:
  * **BucketName**:
    * **Mandatory**: True
    * **Type**: String
    * **Description**: The name of the bucket
  * **Prefix**:
    * **Mandatory**: True
    * **Type**: String
    * **Description**: The full common prefix (Folder path) to restore.
  * **CopyLifetime**
    * **Mandatory**: True
    * **Type**: integer
    * **Description**: The Number of days to keep the restored objects before returning them to glacier.
  * **Tier**:
    * **Mandatory**: True
    * **Type**: String
    * **Description**: The storage tier to restore the objects to. Valid entries are Standard, Expedited, Bulk

### Get-S3RestoreProgress

**Description**:    Display the progress of a Glacier Restore.

* **Parameters**:
  * **BucketName**:
  * **Mandatory**: True
  * **Type**: String
        Description:    The bucket name.
    -Prefix
        Mandatory
        Type: String
        Description: The full common prefix (Folder) that was restored.

    Output will display the Key, RestoreInProgress (True/False) and if RestoreInProgress is false the RestoreExpiration Date.

