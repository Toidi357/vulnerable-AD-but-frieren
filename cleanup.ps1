function Invoke-CleanupVulnAD {
    Write-Host "`n[*] Starting Cleanup Process..." -ForegroundColor Cyan

    # 1. Remove Groups from the Mapping
    # We use the keys from your Global:GroupAssignments hashtable
    foreach ($groupName in $Global:GroupAssignments.Keys) {
        if (Get-ADGroup -Filter "Name -eq '$groupName'") {
            Write-Host "[-] Removing Group: $groupName" -ForegroundColor Yellow
            Remove-ADGroup -Identity $groupName -Confirm:$false
        }
    }

    # 2. Remove Users from the Frieren Name List
    foreach ($name in $Global:HumansNames) {
        $samName = $name.ToLower()
        if (Get-ADUser -Filter "SamAccountName -eq '$samName'") {
            Write-Host "[-] Removing User: $samName" -ForegroundColor Yellow
            Remove-ADUser -Identity $samName -Confirm:$false
        }
    }

    # 3. Remove Service Accounts (Kerberoasting cleanup)
    $ServiceAccounts = @('mssql_svc', 'http_svc', 'exchange_svc')
    foreach ($svc in $ServiceAccounts) {
        if (Get-ADServiceAccount -Filter "Name -eq '$svc'") {
            Write-Host "[-] Removing Service Account: $svc" -ForegroundColor Yellow
            Remove-ADServiceAccount -Identity $svc -Confirm:$false
        }
    }

    Write-Host "[+] Cleanup Complete! Lab environment reset." -ForegroundColor Green
}

# Execute the cleanup
Invoke-CleanupVulnAD
