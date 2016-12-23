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

New-Variable -Name DCLO_AvoidSelf -Value ([System.DirectoryServices.ActiveDirectory.LocatorOptions]::AvoidSelf) -Option ReadOnly
New-Variable -Name DCLO_ForceRediscovery -Value ([System.DirectoryServices.ActiveDirectory.LocatorOptions]::ForceRediscovery) -Option ReadOnly
New-Variable -Name DCLO_KdcRequired -Value ([System.DirectoryServices.ActiveDirectory.LocatorOptions]::KdcRequired) -Option ReadOnly
New-Variable -Name DCLO_TimeServerRequired -Value ([System.DirectoryServices.ActiveDirectory.LocatorOptions]::TimeServerRequired) -Option ReadOnly
New-Variable -Name DCLO_WriteableRequired -Value ([System.DirectoryServices.ActiveDirectory.LocatorOptions]::WriteableRequired) -Option ReadOnly

function Get-ADRootDSE{
    param(
        [String]$DomainName,
        [pscredential]$Credential
    )
    if($DomainName){
        $EntryPoint = "LDAP://$DomainName/RootDSE"
    }
    else{
        $EntryPoint = "LDAP://RootDSE"
    }
    if($Credential){
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry($EntryPoint,$Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password)
    }
    else{
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry($EntryPoint)
    }
    return $rootDSE
}

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

function Get-ADDomainController{
    param(
        [String]$Domain,
        [PsCredential]$Credential,
        [System.DirectoryServices.ActiveDirectory.LocatorOptions]$LocatorOption,
        [Switch]$All
    )
    if(!$Domain){
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }
    if($Credential){
        $CredUser = $Credential.UserName.ToString()
        $CredPwd = $Credential.GetNetworkCredential().Password.ToString()
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$Domain,$CredUser,$CredPwd)
    }
    else{
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$Domain)
    }
    if($All){
        return [System.DirectoryServices.ActiveDirectory.DomainController]::FindAll($DomainContext)
    }
    else{
        if(!$LocatorOption){
            return [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($DomainContext)
        }
        else{
            return [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($DomainContext,$LocatorOption)
        }
    }
}

function Get-ADObject {
    [cmdletbinding(DefaultParameterSetName="Domain")]
    param(
        [Parameter(ParameterSetName="Domain")][String]$DomainName,
        [Parameter(ParameterSetName="SearchBase")][String]$SearchBase,
        [Parameter(Mandatory=$true)][ValidateNotNull()][String]$LDAPFilter,
        [ValidateSet("BASE","ONELEVEL","SUBTREE")][String]$SearchScope = "SUBTREE",
        [ValidateSet("GC","LDAP")][String]$Mode="LDAP",
        [ValidateNotNull()][System.Int32]$PageSize = 1000,
        [String[]]$PropertyList,
        [pscredential]$Credential,
        [Switch]$GlobalCatalog,
        [Switch]$FindOne,
        [Switch]$GetObjects
    )

    switch ($PSCmdlet.ParameterSetName)
    {
        'Domain' {
            if($DomainName){
                $EntryPoint = "$($Mode)://$DomainName/RootDSE"
            }
            else{
                $EntryPoint = "$($Mode)://RootDSE"
            }
            if($Credential){
                $SearchBase = (New-Object System.DirectoryServices.DirectoryEntry($EntryPoint,$Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password)).defaultNamingContext
                $SearchBase = "$($Mode)://$SearchBase"
                $StartDN = New-Object System.DirectoryServices.DirectoryEntry($SearchBase,$Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password)
            }
            else{
                $SearchBase = (New-Object System.DirectoryServices.DirectoryEntry($EntryPoint)).defaultNamingContext
                $SearchBase = "$($Mode)://$SearchBase"
                $StartDN = New-Object System.DirectoryServices.DirectoryEntry($SearchBase)
            }
        }
        'SearchBase' {
            $SearchBase = "$($Mode)://$SearchBase"
            if($Credential){
                $StartDN = New-Object System.DirectoryServices.DirectoryEntry($SearchBase,$Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password)
            }
            else{
                $StartDN = New-Object System.DirectoryServices.DirectoryEntry($SearchBase)
            }
        }
    }
    $ADSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $ADSearcher.SearchRoot = $StartDN
    $ADSearcher.PageSize = $PageSize
    $ADSearcher.Filter = $LDAPFilter
    $ADSearcher.SearchScope = $SearchScope
    if ($PropertyList){foreach ($ADProperty in $PropertyList){[Void]$ADSearcher.PropertiesToLoad.Add($ADProperty)}}
    if ($FindOne) {$ADResults = $ADSearcher.FindOne()}
    else {$ADResults = $ADSearcher.FindAll()}
    return $ADResults
}

#function Get-ADSite{}
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

Export-ModuleMember -Function 'Get-ADRootDSE','Get-ADForest','Get-ADDomain','Get-ADDomainController','Get-ADObject'
Export-ModuleMember -Variable 'DCLO_AvoidSelf','DCLO_ForceRediscovery','DCLO_KdcRequired','DCLO_TimeServerRequired','DCLO_WriteableRequired'
