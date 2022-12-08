<#
.SYNOPSIS
    Get all inbox rules for a mailbox
.DESCRIPTION
    This command will acquire OAuth token interactively(bydefault uses multi-tenant app)
    uses EWS to get all the inbox rules in a mailbox (Includes hidden ones)
.EXAMPLE
    PS C:\>.\InboxHiddenRules.ps1 -Mailbox foo@foo.com
    Will get tenantId from the mailbox and get Interactive OAUTH Token
.EXAMPLE
    PS C:\>.\InboxHiddenRules-MS.ps1 -Mailbox foofoo.com -OAuthClientId <clientguid> -OAuthRedirectUri https://localhost -OAuthTenantId <TenantId>
    Force interactive authentication to get AccessToken (with MS Graph permissions User.Read) and IdToken for specific Azure AD tenant and UPN using client id from application registration (public client).
#>
param 
(
    [Parameter(Position=0,Mandatory=$False,HelpMessage="Specifies the mailbox to be accessed.")]
    [ValidateNotNullOrEmpty()]
    [string]$Mailbox,

    [Parameter(Mandatory=$False,HelpMessage="The client Id that this script will identify as.  Must be registered in Azure AD.")]
    [string]$OAuthClientId = "d82d66ce-348b-4a2c-a8a4-44f8649ab242",

    [Parameter(Mandatory=$False,HelpMessage="The tenant Id of the tenant being accessed.")]
    [string]$OAuthTenantId = "",

    [Parameter(Mandatory=$False,HelpMessage="The redirect Uri of the Azure registered application.")]
    [string]$OAuthRedirectUri = "https://localhost",

    [Parameter(Mandatory=$False,HelpMessage="If using application permissions, specify the secret key OR certificate.")]
    [string]$OAuthSecretKey = "",
    
    [Parameter(Mandatory=$False,HelpMessage="If specified, tenantId is retrieved from ExternalDirectoryObjectId of Get-Mailbox")]
    [Switch]$detectTenantId = $true
)

#region Logging and Error Handling

Function LogToFile([string]$Details)
{
	if ( [String]::IsNullOrEmpty($LogFile) ) { return }
    $logInfo = "$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToLongTimeString())   $Details"
    if ($FastFileLogging)
    {
        if (!$script:logFileStream)
        {
            # Open a filestream to write to our log
            $script:logFileStream = New-Object IO.FileStream($LogFile, ([System.IO.FileMode]::Append), ([IO.FileAccess]::Write), ([IO.FileShare]::Read) )
            ReportError "Opening log file"
        }
        if ($script:logFileStream)
        {
            $streamWriter = New-Object System.IO.StreamWriter($script:logFileStream)
            $streamWriter.WriteLine($logInfo)
            $streamWriter.Dispose()
            if ( ErrorReported("Writing log file") )
            {
                $FastFileLogging = $false
            }
            else
            {
                return
            }
        }
    }
	$logInfo | Out-File $LogFile -Append
}

Function Log([string]$Details, [ConsoleColor]$Colour)
{
    if ($Colour -eq $null)
    {
        $Colour = [ConsoleColor]::White
    }
    Write-Host $Details -ForegroundColor $Colour
    LogToFile $Details
}
Log "$($MyInvocation.MyCommand.Name) version $($script:ScriptVersion) starting" Green

Function LogVerbose([string]$Details)
{
    Write-Verbose $Details
    if ($VerbosePreference -eq "SilentlyContinue") { return }
    LogToFile $Details
}

Function LogDebug([string]$Details)
{
    Write-Debug $Details
    if ($DebugPreference -eq "SilentlyContinue") { return }
    LogToFile $Details
}

Function LogToCSV([string]$Details)
{
    # Write details to CSV (if specified, otherwise just to console)

	Write-Host $Details -ForegroundColor White
	if ( $ExportCSV -eq "" ) { return	}

    $FileExists = Test-Path $ExportCSV
    if (!$FileExists)
    {
        if ($script:CSVHeaders -ne $Null)
        {
            $script:CSVHeaders | Out-File $ExportCSV
        }
    }

	$Details | Out-File $ExportCSV -Append
}

$script:LastError = $Error[0]
Function ErrorReported($Context)
{
    # Check for any error, and return the result ($true means a new error has been detected)

    # We check for errors using $Error variable, as try...catch isn't reliable when remoting
    if ([String]::IsNullOrEmpty($Error[0])) { return $false }

    # We have an error, have we already reported it?
    if ($Error[0] -eq $script:LastError) { return $false }

    # New error, so log it and return $true
    $script:LastError = $Error[0]
    if ($Context)
    {
        Log "Error ($Context): $($Error[0])" Red
    }
    else
    {
        Log "Error: $($Error[0])" Red
    }
    return $true
}

Function ReportError($Context)
{
    # Reports error without returning the result
    ErrorReported $Context | Out-Null
}


$script:LastError = $Error[0]
Function ErrorReported($Context)
{
    # Check for any error, and return the result ($true means a new error has been detected)

    # We check for errors using $Error variable, as try...catch isn't reliable when remoting
    if ([String]::IsNullOrEmpty($Error[0])) { return $false }

    # We have an error, have we already reported it?
    if ($Error[0] -eq $script:LastError) { return $false }

    # New error, so log it and return $true
    $script:LastError = $Error[0]
    if ($Context)
    {
        Log "Error ($Context): $($Error[0])" Red
    }
    else
    {
        Log "Error: $($Error[0])" Red
    }
    return $true
}

Function ReportError($Context)
{
    # Reports error without returning the result
    ErrorReported $Context | Out-Null
}

#endregion

#region Load Libraries & EWS Functions

function LoadLibraries()
{
    param (
        [bool]$searchProgramFiles,
        [bool]$searchLocalAppData = $false,
        $dllNames,
        [ref]$dllLocations = @()
    )
    # Attempt to find and load the specified libraries

    foreach ($dllName in $dllNames)
    {
        # First check if the dll is in current directory
        LogDebug "Searching for DLL: $dllName"
        $dll = $null
        try
        {
            $dll = Get-ChildItem $dllName -ErrorAction SilentlyContinue
        }
        catch {}

        if ($searchProgramFiles)
        {
            if ($dll -eq $null)
            {
	            $dll = Get-ChildItem -Recurse "C:\Program Files (x86)" -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and ( $_.Name -eq $dllName ) }
	            if (!$dll)
	            {
		            $dll = Get-ChildItem -Recurse "C:\Program Files" -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and ( $_.Name -eq $dllName ) }
	            }
            }
        }
        $script:LastError = $Error[0] # We do this to suppress any errors encountered during the search above

        if ($searchLocalAppData)
        {
            if ($dll -eq $null)
            {
	            $dll = Get-ChildItem -Recurse $env:LOCALAPPDATA -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and ( $_.Name -eq $dllName ) }
            }
        }
        $script:LastError = $Error[0] # We do this to suppress any errors encountered during the search above

        if ($dll -eq $null)
        {
            Log "Unable to load locate $dllName" Red
            return $false
        }
        else
        {
            try
            {
		        LogVerbose ([string]::Format("Loading {2} v{0} found at: {1}", $dll.VersionInfo.FileVersion, $dll.VersionInfo.FileName, $dllName))
		        Add-Type -Path $dll.VersionInfo.FileName
                if ($dllLocations)
                {
                    $dllLocations.value += $dll.VersionInfo.FileName
                    ReportError
                }
            }
            catch
            {
                ReportError "LoadLibraries"
                return $false
            }
        }
    }
    return $true
}

Function LoadEWSManagedAPI
{
	# Find and load the managed API
    $ewsApiLocation = @()
    $ewsApiLoaded = $(LoadLibraries -searchProgramFiles $true -searchLocalAppData $true -dllNames @("Microsoft.Exchange.WebServices.dll") -dllLocations ([ref]$ewsApiLocation))
    ReportError "LoadEWSManagedAPI"

    if (!$ewsApiLoaded)
    {
        # Failed to load the EWS API, so try to install it from Nuget
        Write-Host "EWS Managed API was not found - attempt to automatically download and install from Nuget?" -ForegroundColor White
        if ($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character -ne 'y')
        {
            Exit # Can't do anything with the EWS API
        }

        $ewsapi = Find-Package "Exchange.WebServices.Managed.Api"
        if (!$ewsapi)
        {
            Register-PackageSource -Name NuGet -Location https://www.nuget.org/api/v2 -ProviderName NuGet
            $ewsapi = Find-Package "Exchange.WebServices.Managed.Api" -Source Nuget
        }
        if ($ewsapi.Entities.Name.Equals("Microsoft"))
        {
	        # We have found EWS API package, so install as current user (confirm with user first)
		    Install-Package $ewsapi -Scope CurrentUser -Force
            $ewsApiLoaded = $(LoadLibraries -searchProgramFiles $false -searchLocalAppData $true -dllNames @("Microsoft.Exchange.WebServices.dll") -dllLocations ([ref]$ewsApiLocation))
            ReportError "LoadEWSManagedAPI"
        }
    }

    if ($ewsApiLoaded)
    {
        if ($ewsApiLocation[0])
        {
            Log "Using EWS Managed API found at: $($ewsApiLocation[0])" Gray
            $script:EWSManagedApiPath = $ewsApiLocation[0]
        }
        else
        {
            Write-Host "Failed to read EWS API location: $ewsApiLocation"
            Exit
        }
    }

    return $ewsApiLoaded
}


#endregion

#region Rules Checking functions
function Get-ExtendedProperty
{
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Exchange.WebServices.Data.Item]
        $Item,

        # Param2 help descriptio
        [ValidateNotNullOrEmpty()]
        [Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition]
        $Property
    )

    $Value = $null
    $Succeeded = $Item.TryGetProperty($Property, [ref]$Value)

    if($Succeeded)
    {
        $Value
    }
    else
    {
        Write-Warning ("Could not get value for " + [System.Convert]::ToString($Property.Tag,16))
    }
}

function Check-Action($bytearray, [REF] $isPotentiallyMalicious, [REF] $actionType, [REF] $actionCommand)
{


    $isPotentiallyMalicious.Value = $false
    $actionType.Value = ""
    $actionCommand.Value = ""


    if ($bytearray.Length -gt 30 )
    {
      if ($bytearray[2] -eq 1 -and $bytearray[14] -eq 5 )
      {
        if ($bytearray[29] -eq 0x14) 
        {
         $actionType.Value = "ID_ACTION_CUSTOM"
         $isPotentiallyMalicious.Value = $true

        } 
        elseif ($bytearray[29] -eq 0x1e) 
        {
         $actionType.Value = "ID_ACTION_EXECUTE"
         $isPotentiallyMalicious.Value = $true

        }
         elseif ($bytearray[29] -eq 0x20) 
        {
         $actionType.Value = "ID_ACTION_RUN_MACRO"
         $isPotentiallyMalicious.Value = $true
        }
      }
      
      if ($isPotentiallyMalicious.Value -eq $true)
      {
        foreach ($byte in $bytearray) 
        {
            if ($byte -gt 31 -and $byte -lt 127)
            {
                $returnstring += [char]$byte
            }
        }

        $actionCommand.Value  = $returnstring
      }
    }
}

function Convert-ByteArrays ($bytearray)
{
    if($bytearray -eq $null){ return ""}
    return  [Convert]::ToBase64String($bytearray)

}

#endregion








function GetMSALToken()
{
 
$MsalParams = @{
    ClientId = $OAuthClientId
    TenantId = $OAuthTenantId
    RedirectUri = $OAuthRedirectUri
    Interactive = $true
    Scopes   = "https://outlook.office.com/EWS.AccessAsUser.All"   
}
 
$MsalResponse = Get-MsalToken @MsalParams
return $MsalResponse
}

function CreateService($smtpAddress)
{
    # Creates and returns an ExchangeService object to be used to access mailboxes

	$exchangeService = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2)
    $msaltoken = GetMSALToken
	$exchangeService.Credentials = [Microsoft.Exchange.WebServices.Data.OAuthCredentials]$msaltoken.AccessToken
	if ($exchangeService.Credentials -eq $null)
	{
		# OAuth failed
		return $null
	}


    # Set EWS URL if specified, or use autodiscover if no URL specified.
	$EwsUrl = "https://outlook.office365.com/EWS/Exchange.asmx" 
    $exchangeService.URL = New-Object Uri($EwsUrl)
    

    if ($exchangeService.URL.AbsoluteUri.ToLower().Equals("https://outlook.office365.com/ews/exchange.asmx"))
    {
        # This is Office 365, so we'll add a small delay to try and avoid throttling
        if ($script:currentThrottlingDelay -lt 100)
        {
            $script:currentThrottlingDelay = 100
            LogVerbose "Office 365 mailbox, throttling delay set to $($script:currentThrottlingDelay)ms"
        }
    }
 
    $exchangeService.HttpHeaders.Add("X-AnchorMailbox", $smtpAddress)
    if ($Impersonate)
    {
		$exchangeService.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $smtpAddress)
	}

    # # We enable tracing so that we can retrieve the last response (and read any throttling information from it - this isn't exposed in the EWS Managed API)
    # if (![String]::IsNullOrEmpty($EWSManagedApiPath))
    # {
        # CreateTraceListener $exchangeService
        # if ($exchangeService.TraceListener -ne $null)
        # {
            # $exchangeService.TraceFlags = [Microsoft.Exchange.WebServices.Data.TraceFlags]::All
            # $exchangeService.TraceEnabled = $True
        # }
    # }

    #$script:services.Add($smtpAddress, $exchangeService)
    #LogVerbose "Currently caching $($script:services.Count) ExchangeService objects" $true
    return $exchangeService
}



function Detect-TenantId
{
    try 
    { 
        #Need to popup login again to Azure to retrieve TenantId
        $tenantId = Connect-AzureAD | select TenantId -ErrorAction SilentlyContinue
        return $tenantId.TenantId.ToString()
    }
    catch
    {
        Write-Host "failed to detect Tenant ID for mailbox $Mailbox" -ForegroundColor Red
        exit
    }
}


#$smtpAddress = Read-Host "Enter User mailbox Address "
$smtpAddress = $Mailbox
#####################################################################
if (!(LoadEWSManagedAPI))
{
	Write-Host "Failed to locate EWS Managed API, cannot continue" -ForegroundColor Red
	Exit
}

if( $detectTenantId -and $OAuthTenantId -eq "")
{
    $OAuthTenantId = Detect-TenantId
}
else
{
    if($OAuthTenantId -eq "") 
    {
        Write-Host -ForegroundColor Red "TenantId not specified and detection not specified. Use -detectTenantId"
        exit
    }
}

#Global Variables
[string]$hostName = "outlook.office365.com"

#Then let's setup our EWS credential
$exchService = CreateService($smtpAddress)

#Setup the EWS Search, Filter, and Property Conditions
# Setup the search query
$searchFilterCollection = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection([Microsoft.Exchange.WebServices.Data.LogicalOperator]::Or)
$searchFilter1 = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.ContactSchema]::ItemClass,"IPM.Rule")
$searchFilter2 = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.ContactSchema]::ItemClass,"IPM.ExtendedRule")
$searchFilter3 = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.ContactSchema]::ItemClass,"IPM.Note.Rules")
$searchFilter4 = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.ContactSchema]::ItemClass,"IPM.RuleOrganizer.ClientRules")

$searchFilterCollection.add($searchFilter1)
$searchFilterCollection.add($searchFilter2)
$searchFilterCollection.add($searchFilter3)
$searchFilterCollection.add($searchFilter4)

# Setup the search filter
# ptag property IDs and datatypes obtained from "[MS-OXPROPS]: Exchange Server Protocols Master Property List"
#   - https://msdn.microsoft.com/en-us/library/cc433490(v=exchg.80).aspx
$PidTagRuleMessageName = New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition(0x65EC, [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::String) # Rule name
$PidTagExtendedRuleMessageActions = new-object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition(0x0E99, [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Binary) # Binary blob that defines actions. Also the condition for "Start Application" rules
$PidTagExtendedRuleMessageCondition = new-object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition(0x0E9A, [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Binary) # 
$PidTagRuleMessageState = New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition(0x65E9, [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Integer) # Defines whether rule is enabled
$PidTagOfflineAddressBookName = New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition(0x6800, [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::String) # Form name
$dateTimeCreatedProperty = [Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated

$PropertySet = new-object Microsoft.Exchange.WebServices.Data.PropertySet
$PropertySet.Add([Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass)
$PropertySet.Add($PidTagRuleMessageName)
$PropertySet.Add($PidTagExtendedRuleMessageActions)
$PropertySet.Add($PidTagExtendedRuleMessageCondition)
$PropertySet.Add($PidTagRuleMessageState)
$PropertySet.Add($PidTagOfflineAddressBookName)
$propertySet.Add($dateTimeCreatedProperty)


#Get all the rules and dump them to csv
$Rules = @()

$itemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView(100,0,[Microsoft.Exchange.WebServices.Data.OffsetBasePoint]::Beginning)
$itemView.Traversal = [Microsoft.Exchange.WebServices.Data.ItemTraversal]::Shallow
$itemView.OrderBy.add([Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeReceived,[Microsoft.Exchange.WebServices.Data.SortDirection]::Ascending)
$itemView.PropertySet = $PropertySet
$itemView.Traversal = [Microsoft.Exchange.WebServices.Data.ItemTraversal]::Associated

$rfRootFolderID = new-object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox, $smtpAddress)
$rfRootFolder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchService,$rfRootFolderID)

# Do the search
$FindResults = $exchService.FindItems([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox, $searchFilterCollection, $itemView)

foreach($Item in $FindResults.Items)
{
    $ruleactionsbytearray = Get-ExtendedProperty -Item $Item -Property $PidTagExtendedRuleMessageActions
    $ruleconditionsbytearray = Get-ExtendedProperty -Item $Item -Property $PidTagExtendedRuleMessageCondition
    $readableactions = Convert-ByteArrays ($ruleactionsbytearray)
    $readableconditions = Convert-ByteArrays($ruleconditionsbytearray)

    $isPotentiallyMalicious = $false
    $actionType = ""
    $actionCommand = ""
    Check-Action ($ruleactionsbytearray) ([REF] $isPotentiallyMalicious) ([REF] $actionType) ([REF] $actionCommand)


    $Rules += New-Object PSObject -Property @{
        User        = $smtpAddress
        RuleName    = Get-ExtendedProperty -Item $Item -Property $PidTagRuleMessageName
        IsPotentiallyMalicious = $isPotentiallyMalicious
        ActionType  = $actionType
        ActionCommand = $actionCommand
        Action      = $readableactions
        Condition   = $readableconditions
        State       = Get-ExtendedProperty -Item $Item -Property $PidTagRuleMessageState
        DateCreated = $Item.DateTimeCreated
        ItemClass   = $Item.ItemClass
    }
    

}


$rulesExportPath = ".\MailboxRulesExport-" + (Get-Date).ToString('yyyy-MM-dd') + ".csv"
Write-Output "Rules exported to $rulesExportPath"
$Rules | Export-Csv -Path ($rulesExportPath)


																								

Write-Output "Rules found..."
$Rules




