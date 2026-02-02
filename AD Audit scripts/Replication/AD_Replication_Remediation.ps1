
# PowerShell Script: AD Replication Remediation

# Step 1: Check Replication Status
Write-Host "Checking replication status..."
repadmin /replsummary
repadmin /showrepl *

# Step 2: Identify problematic Domain Controllers
Write-Host "Identifying domain controllers with replication issues..."
$dcdiagOutput = dcdiag /test:replications
$problemDCs = @()
foreach ($line in $dcdiagOutput) {
    if ($line -match "failed") {
        $dcName = ($line -split ":")[0].Trim()
        if (-not $problemDCs.Contains($dcName)) {
            $problemDCs += $dcName
        }
    }
}

# Step 3: Restart problematic Domain Controllers
foreach ($dc in $problemDCs) {
    Write-Host "Restarting domain controller: $dc"
    Restart-Computer -ComputerName $dc -Force
}

# Step 4: Clean up metadata for orphaned DCs
Write-Host "Cleaning up metadata..."
# Replace 'OrphanedDCName' with actual DC name if known
# ntdsutil metadata cleanup can be used interactively or scripted with repadmin
# Example:
# repadmin /removelingeringobjects <DestinationDC> <SourceDC_GUID> /advisory_mode

# Step 5: Validate replication health post-remediation
Write-Host "Validating replication health..."
repadmin /replsummary
repadmin /showrepl *
dcdiag /test:replications

Write-Host "Remediation script completed."
