Param(
    [String]$path,
    [String]$user,
    [String]$outfile = ".\outfile.csv"
)

#Import-Module -Name $PSScriptRoot\NTFSSecurity -Verbose
#Import-Module $PSScriptRoot\NTFSSecurity

$permission = $user,"Modify","Allow"
# $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($readGroup.SID,"Read","Allow")
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$output = @()

ForEach ($item in (Get-ChildItem -Path $path -Directory)) {
    $thisACL = (Get-Acl $item)
    ForEach ($acl in ($thisACL.Access)){

        #if (($acl.GetAccessRules($True, $True, [System.Security.Principal.NTAccount]) | Where-Object {$_.IsInherited -match "False"} ) ){
        if (($acl | Where-Object {$_.IsInherited -eq $false}) ){
            #this enables inheritence, odd right, way to go MS
            $thisACL.SetAccessRule($False,$True)
            Write-Host "Enabling Inheritence on Folder: $item"
        }

        if (($thisACL | Where-Object {$_.AccessControlType -match "Deny"} ) ){
            $thisACL.RemoveAccessRule($acl)
            Write-Host "Removing Deny Permission from folder: $item"
        }
        
        if (($acl | Where-Object {$_.IsInherited -eq $false}) ){
            $thisACL.RemoveAccessRule($acl)
            Write-Host "Removing Deny Permission from folder: $item"
        }
        if (!($acl | Where-Object {$_ -match $permission} ) ){
            $thisACL.AddAccessRule($permission)
            Write-Host "Adding Permission to folder $item"
        }
        #(Get-Acl .\ActiveDirectory).GetAccessRules($True, $True, [System.Security.Principal.NTAccount])
        #ForEach ($acl in ($item.GetAccessControl().Access)){
        #     $item.GetAccessControl().Access
        #     $output += $acl | 
        #     Add-Member `
        #             -MemberType NoteProperty `
        #             -Name 'Folder' `
        #             -Value $item.FullName `
        #             -PassThru

    }

}

$output | Export-Csv -Path $outfile -NoTypeInformation