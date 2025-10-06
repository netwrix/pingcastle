Clear-Host
$RootDSE = [System.DirectoryServices.DirectoryEntry]([ADSI]"LDAP://RootDSE")
$NC = $RootDSE.Get("defaultNamingContext")

$dn = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://CN=Users," + $NC)

$Rech = new-object System.DirectoryServices.DirectorySearcher($dn)
$Rech.filter = "(description=DNS Administrators Group)"
$Rech.SearchScope = "onelevel"
#$a=$Rech.PropertiesToLoad.Add("distinguishedName");
#$a=$Rech.PropertiesToLoad.Add("name");
#$a=$Rech.PropertiesToLoad.Add("nTSecurityDescriptor");
$Rech.PageSize = 500;

$colResults = $Rech.FindAll()

foreach ($objResult in $colResults)
{
    $objItem = $objResult.Properties;
    Write-host $objItem.distinguishedname;
}