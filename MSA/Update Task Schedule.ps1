<#
Update task schedule for gMSA enabled ADAssessment and ADSecurityAssessment tasks
#>


# Global Variables
$LogAnalyticsWorkspaceId = '<your-log-analytics-workspace-id>'  # Replace with your actual Log Analytics Workspace ID

$taskName = 'ADAssessment'
$taskPath = "\Microsoft\Operations Management Suite\AOI-$LogAnalyticsWorkspaceId\Assessments\ADAssessment\"

# Define new trigger time (e.g., daily at 2:30 AM)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 2:30AM

# Get the existing task
$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath

# Update the trigger
Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $trigger


$taskName = 'ADSecurityAssessment'
$taskPath = "\Microsoft\Operations Management Suite\AOI-$LogAnalyticsWorkspaceId\Assessments\ADSecurityAssessment\"

# Define new trigger time (e.g., daily at 2:30 AM)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2:30AM

# Get the existing task
$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath

# Update the trigger
Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $trigger
