#Base Lists 
$Global:HumansNames = @('Frieren', 'Fern', 'Stark', 'Himmel', 'Heiter', 'Eisen', 'Minus', 'Aura', 'Qual', 'Flamme', 'Serie', 'Solitar', 'Richter', 'Macht', 'Denken', 'Laufen', 'Ubel', 'Kanne', 'Wirbel', 'Methode', 'Edel', 'Land', 'Lawine', 'Genau', 'Scharf', 'Revolte', 'Grausam', 'Lugner', 'Linie', 'Draht', 'Gluck', 'Sense', 'Lernen', 'Falsch', 'Burg', 'Tau', 'Lineal');
$Global:BadPasswords = @('joshuazhu');
$Global:GroupAssignments = @{
    'Hero Party'         = @('Frieren', 'Himmel', 'Heiter', 'Eisen');
    'Frieren Party'      = @('Frieren', 'Fern', 'Stark');
    'Great Mages'        = @('Frieren', 'Flamme', 'Serie', 'Minus')
    'First Class Mages'  = @('Serie', 'Frieren', 'Fern', 'Denken', 'Ubel', 'Land', 'Methode', 'Wirbel', 'Genau', 'Sense', 'Lernen', 'Falsch', 'Burg', 'Tau', 'Lineal');
    'Second Class Mages' = @('Kanne', 'Lawine', 'Scharf', 'Laufen')
    'Demons'             = @('Macht', 'Solitar', 'Aura', 'Qual', 'Lugner', 'Linie', 'Draht')
}
$Global:BadACL = @('GenericAll','GenericWrite','WriteOwner','WriteDACL','Self','WriteProperty');
$Global:ServicesAccountsAndSPNs = @('mssql_svc,mssqlserver','http_svc,httpserver','exchange_svc,exserver');
$Global:CreatedUsers = @();
$Global:AllObjects = @();
$Global:Domain = "";
#Strings 
$Global:Spacing = "`t"
$Global:PlusLine = "`t[+]"
$Global:ErrorLine = "`t[-]"
$Global:InfoLine = "`t[*]"
function Write-Good { param( $String ) Write-Host $Global:PlusLine  $String -ForegroundColor 'Green'}
function Write-Bad  { param( $String ) Write-Host $Global:ErrorLine $String -ForegroundColor 'red'  }
function Write-Info { param( $String ) Write-Host $Global:InfoLine $String -ForegroundColor 'gray' }
function ShowBanner {
    $banner  = @()
    $banner+= $Global:Spacing + ''
    $banner+= $Global:Spacing + 'VULN AD - Vulnerable Active Directory'
    $banner+= $Global:Spacing + ''                                                  
    $banner+= $Global:Spacing + 'By wazehell @safe_buffer and @Toidi357 and google gemini and https://frieren.fandom.com/wiki/Mage :)'
    $banner | foreach-object {
        Write-Host $_ -ForegroundColor (Get-Random -Input @('Green','Cyan','Yellow','gray','white'))
    }                             
}
function VulnAD-GetRandom {
   Param(
     [array]$InputList
   )
   return Get-Random -InputObject $InputList
}

function VulnAD-AddADUser {
    Add-Type -AssemblyName System.Web
    foreach ($name in $Global:HumansNames) {
        $SamAccountName = $name.ToLower()
        $password = "joshuazhu" # Your designated password
        
        Write-Info "Creating User: $name"
        Try { 
            New-ADUser -Name $name `
                       -GivenName $name `
                       -SamAccountName $SamAccountName `
                       -UserPrincipalName "$SamAccountName@$Global:Domain" `
                       -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                       -PassThru | Enable-ADAccount 
            
            $Global:CreatedUsers += $SamAccountName
        } Catch { Write-Bad "Failed to create $name (User may already exist)" }
    }
}

function VulnAD-AssignToGroups {
    foreach ($groupName in $Global:GroupAssignments.Keys) {
        Write-Info "Processing Group: $groupName"
        
        # Create the group if it doesn't exist
        Try { 
            New-ADGroup -Name $groupName -GroupScope Global -ErrorAction Stop
            Write-Good "Group $groupName Created"
        } Catch { Write-Info "Group $groupName already exists" }

        # Add designated members
        $members = $Global:GroupAssignments[$groupName]
        foreach ($member in $members) {
            Try {
                Add-ADGroupMember -Identity $groupName -Members ($member.ToLower()) -ErrorAction Stop
                Write-Info "  + Added $member to $groupName"
            } Catch {
                Write-Bad "  - Could not add $member to $groupName (User not found?)"
            }
        }
        $Global:AllObjects += $groupName
    }
}
function VulnAD-AddACL {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Destination,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Security.Principal.IdentityReference]$Source,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Rights

        )
        $ADObject = [ADSI]("LDAP://" + $Destination)
        $identity = $Source
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
        $type = [System.Security.AccessControl.AccessControlType] "Allow"
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
        $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
        $ADObject.psbase.commitchanges()
}
function VulnAD-BadAcls {
    # Get a list of the group names we actually created
    $AllCreatedGroups = $Global:GroupAssignments.Keys

    foreach ($abuse in $Global:BadACL) {
        # Select two random groups from your new Frieren categories
        $hgroup = VulnAD-GetRandom -InputList $AllCreatedGroups
        $mgroup = VulnAD-GetRandom -InputList $AllCreatedGroups
        
        $DstGroup = Get-ADGroup -Identity $hgroup
        $SrcGroup = Get-ADGroup -Identity $mgroup
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info "BadACL $abuse $mgroup to $hgroup"
    }
    
    for ($i=1; $i -le (Get-Random -Maximum 25); $i=$i+1 ) {
        $abuse = (VulnAD-GetRandom -InputList $Global:BadACL);
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $randomgroup = VulnAD-GetRandom -InputList $Global:AllObjects
        if ((Get-Random -Maximum 2)){
            $Dstobj = Get-ADUser -Identity $randomuser
            $Srcobj = Get-ADGroup -Identity $randomgroup
        }else{
            $Srcobj = Get-ADUser -Identity $randomuser
            $Dstobj = Get-ADGroup -Identity $randomgroup
        }
        VulnAD-AddACL -Source $Srcobj.sid -Destination $Dstobj.DistinguishedName -Rights $abuse 
        Write-Info "BadACL $abuse $randomuser and $randomgroup"
    }
}
function VulnAD-Kerberoasting {
    $selected_service = (VulnAD-GetRandom -InputList $Global:ServicesAccountsAndSPNs)
    $svc = $selected_service.split(',')[0];
    $spn = $selected_service.split(',')[1];
    $password = VulnAD-GetRandom -InputList $Global:BadPasswords;
    Write-Info "Kerberoasting $svc $spn"
    Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -RestrictToSingleComputer -PassThru } Catch {}
    foreach ($sv in $Global:ServicesAccountsAndSPNs) {
        if ($selected_service -ne $sv) {
            $svc = $sv.split(',')[0];
            $spn = $sv.split(',')[1];
            Write-Info "Creating $svc services account"
            $password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
            Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -RestrictToSingleComputer -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru } Catch {}

        }
    }
}
function VulnAD-ASREPRoasting {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
        $password = VulnAD-GetRandom -InputList $Global:BadPasswords;
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADAccountControl -Identity $randomuser -DoesNotRequirePreAuth 1
        Write-Info "AS-REPRoasting $randomuser"
    }
}
function VulnAD-DnsAdmins {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
        Add-ADGroupMember -Identity "DnsAdmins" -Members $randomuser
        Write-Info "DnsAdmins : $randomuser"
    }
}

function VulnAD-DCSync {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $ADObject = [ADSI]("LDAP://" + (Get-ADDomain $Global:Domain).DistinguishedName)
        $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
        $sid = (Get-ADUser -Identity $randomuser).sid

        $objectGuidGetChanges = New-Object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 89e95b76-444d-4c62-991a-0facbeda640c
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)
        $ADObject.psbase.CommitChanges()

        Set-ADUser $randomuser -Description "Replication Account"
        Write-Info "Giving DCSync to : $randomuser"
    }
}
function VulnAD-DisableSMBSigning {
    Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
}
function Invoke-VulnAD {
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName
    )
    ShowBanner
    $Global:Domain = $DomainName
    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain -LockoutDuration 00:01:00 -LockoutObservationWindow 00:01:00 -ComplexityEnabled $false -ReversibleEncryptionEnabled $False -MinPasswordLength 4
    
    # Create Users (One of each name, password: joshuazhu)
    VulnAD-AddADUser 
    Write-Good "All Frieren characters created."

    # Assign to Designated Groups
    VulnAD-AssignToGroups
    Write-Good "Designated group assignments complete."

    VulnAD-BadAcls
    Write-Good "BadACL Done"
    VulnAD-Kerberoasting
    Write-Good "Kerberoasting Done"
    VulnAD-ASREPRoasting
    Write-Good "AS-REPRoasting Done"
    VulnAD-DnsAdmins
    Write-Good "DnsAdmins Done"
    VulnAD-DCSync
    Write-Good "DCSync Done"
    VulnAD-DisableSMBSigning
    Write-Good "SMB Signing Disabled"
}
