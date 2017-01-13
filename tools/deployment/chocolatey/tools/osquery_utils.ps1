# Helper function to toggle the Deny-Write ACL placed on the
# osqueryd parent folder for 'safe' execution on Windows.
function Set-DenyWriteAcl {
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="Medium")]
  param(
    [string] $targetDir = '',
    [string] $action = ''
  )
  if (($action -ine 'Add') -and ($action -ine 'Remove')) {
    Write-Debug "[-] Invalid action in Set-DenyWriteAcl."
    return $false
  }
  if($PSCmdlet.ShouldProcess($targetDir)){
    $acl = Get-Acl $targetDir
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $permType = [System.Security.AccessControl.AccessControlType]::Deny

    $permission = "everyone","write",$inheritanceFlag,$propagationFlag,$permType
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    # We only support adding or removing the ACL
    if ($action -ieq 'add') {
      $acl.SetAccessRule($accessRule)
    } else {
      $acl.RemoveAccessRule($accessRule)
    }
    $acl | Set-Acl $targetDir
    return $true
  }
  return $false
}
