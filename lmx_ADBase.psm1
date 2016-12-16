<#
lmxLABS Active Directory Base Module
=============================================================================
THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

This sample is not supported under any standard support program or
service. The code sample is provided AS IS without warranty of any kind.
lmxlabs further disclaims all implied warranties including, without
limitation, any implied warranties of merchantability or of fitness for a
particular purpose. The entire risk arising out of the use or performance of
the sample and documentation remains with you. In no event shall lmxlabs, 
its authors, or anyone else involved in the creation, production, or delivery 
of the script be liable for any damages whatsoever (including, without 
limitation, damages for loss of business profits, business interruption, loss
of business information, or other pecuniary loss) arising out of  the use of
or inability to use the sample or documentation, even if lmxlabs has been 
advised of the possibility of such damages.
=============================================================================
#>


function Get-ADForest{
    param(
        [String]$Name,
        [PsCredential]$Credential
    )
    if(!$Name){
        $Name = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
    }
    if($Credential){
        $CredUser = $Credential.UserName.ToString()
        $CredPwd = $Credential.GetNetworkCredential().Password.ToString()
        $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$Name,$CredUser,$CredPwd)
    }
    else{
        $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$Name)
    }
    return [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
}

function Get-ADDomain{
    param(
        [String]$Name,
        [PsCredential]$Credential
    )
    if(!$Name){
        $Name = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }
    if($Credential){
        $CredUser = $Credential.UserName.ToString()
        $CredPwd = $Credential.GetNetworkCredential().Password.ToString()
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$Name,$CredUser,$CredPwd)
    }
    else{
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$Name)
    }
    return [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
}

#function Get-ADDomainController{
#    param(
#        [String]$Name,
#        [PsCredential]$Credential
#    )
#
#}

#function Get-ADSite{}
#
#function Get-ADObject{}
#
#function Get-ADUser{}
#
#function Get-ADGroup{}
#
#function Get-ADGroupMember{}
#
#function Get-ADComputer{}
#
#function Search-AD{}
