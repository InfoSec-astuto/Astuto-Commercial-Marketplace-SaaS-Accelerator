# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE file in the project root for license information.

#
# Powershell script to deploy the resources - Customer portal, Publisher portal and the Azure SQL Database
#

#.\Deploy.ps1 `
# -WebAppNamePrefix "amp_saas_accelerator_<unique>" `
# -Location "<region>" `
# -PublisherAdminUsers "<your@email.address>"

Param(  
   [string][Parameter(Mandatory)]$WebAppNamePrefix, # Prefix used for creating web applications
   [string][Parameter()]$ResourceGroupForDeployment, # Name of the resource group to deploy the resources
   [string][Parameter(Mandatory)]$Location, # Location of the resource group
   [string][Parameter(Mandatory)]$PublisherAdminUsers, # Provide a list of email addresses (as comma-separated-values) that should be granted access to the Publisher Portal
   [string][Parameter()]$TenantID, # The value should match the value provided for Active Directory TenantID in the Technical Configuration of the Transactable Offer in Partner Center
   [string][Parameter()]$AzureSubscriptionID, # Subscription where the resources be deployed
   [string][Parameter()]$ADApplicationID, # The value should match the value provided for Active Directory Application ID in the Technical Configuration of the Transactable Offer in Partner Center
   [string][Parameter()]$ADApplicationSecret, # Secret key of the AD Application
   [string][Parameter()]$ADApplicationIDAdmin, # Multi-Tenant Active Directory Application ID 
   [string][Parameter()]$ADMTApplicationIDPortal, #Multi-Tenant Active Directory Application ID for the Landing Portal
   [string][Parameter()]$IsAdminPortalMultiTenant, # If set to true, the Admin Portal will be configured as a multi-tenant application. This is by default set to false. 
   [string][Parameter()]$SQLDatabaseName, # Name of the database (Defaults to AMPSaaSDB)
   [string][Parameter()]$SQLServerName, # Name of the database server (without database.windows.net)
   [string][Parameter()]$LogoURLpng,  # URL for Publisher .png logo
   [string][Parameter()]$LogoURLico,  # URL for Publisher .ico logo
   [string][Parameter()]$KeyVault, # Name of KeyVault
   [switch][Parameter()]$Quiet #if set, only show error / warning output from script commands
)

# ---------------------------------------------------------------------------
# Helper Function: Retry-Command
# Handles transient failures for operations (API calls, SQL cmds)
# ---------------------------------------------------------------------------
function Retry-Command {
    param (
        [ScriptBlock]$Command,
        [int]$MaxRetries = 10,
        [int]$DelaySeconds = 15,
        [string]$ActivityName = "Operation"
    )

    $retryCount = 0
    $completed = $false

    while (-not $completed) {
        try {
            & $Command
            $completed = $true
        }
        catch {
            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                Write-Host "❌ [$ActivityName] failed after $MaxRetries attempts." -ForegroundColor Red
                throw $_
            }
            Write-Host "⚠️  [$ActivityName] failed. Retrying in $DelaySeconds seconds... ($retryCount/$MaxRetries)" -ForegroundColor Yellow
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor DarkGray
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# ---------------------------------------------------------------------------
# Helper Function: WaitFor-Resource
# Uses Azure CLI 'wait' to ensure resource exists in ARM before proceeding
# ---------------------------------------------------------------------------
function WaitFor-Resource {
    param (
        [string]$ResourceGroup,
        [string]$Name,
        [string]$ResourceType, # e.g., Microsoft.Network/virtualNetworks
        [string]$ActivityName
    )
    
    Write-Host "⏳ Waiting for [$ActivityName] to be fully provisioned..." -ForegroundColor Cyan
    try {
        # First check if it exists using 'wait --exists'
        az resource wait --exists --resource-group $ResourceGroup --name $Name --resource-type $ResourceType --timeout 300
        
        # Double check provisioning state if possible
        $state = az resource show --resource-group $ResourceGroup --name $Name --resource-type $ResourceType --query properties.provisioningState -o tsv 2>$null
        if ($state -and $state -ne "Succeeded") {
             Write-Host "    Resource found but state is '$state'. Waiting for 'created' signal..." -ForegroundColor Yellow
             az resource wait --created --resource-group $ResourceGroup --name $Name --resource-type $ResourceType --timeout 300
        }
        Write-Host "    ✅ [$ActivityName] is ready." -ForegroundColor Green
    }
    catch {
        Write-Host "⚠️  Wait command timed out or failed. Proceeding with caution..." -ForegroundColor Yellow
    }
}

# Define the warning message
$message = @"
The SaaS Accelerator is offered under the MIT License as open source software and is not supported by Microsoft.

If you need help with the accelerator or would like to report defects or feature requests use the Issues feature on the GitHub repository at https://aka.ms/SaaSAccelerator

Do you agree? (Y/N)
"@

# Display the message in yellow
Write-Host $message -ForegroundColor Yellow

# Prompt the user for input
$response = Read-Host

# Check the user's response
if ($response -ne 'Y' -and $response -ne 'y') {
    Write-Host "You did not agree. Exiting..." -ForegroundColor Red
    exit
}

# Proceed if the user agrees
Write-Host "Thank you for agreeing. Proceeding with the script..." -ForegroundColor Green

#region Select Tenant / Subscription for deployment

$currentContext = az account show | ConvertFrom-Json
$currentTenant = $currentContext.tenantId
$currentSubscription = $currentContext.id

#Get TenantID if not set as argument
if(!($TenantID)) {    
    Get-AzTenant | Format-Table
    if (!($TenantID = Read-Host "⌨  Type your TenantID or press Enter to accept your current one [$currentTenant]")) { $TenantID = $currentTenant }    
}
else {
    Write-Host "🔑 Tenant provided: $TenantID"
}

#Get Azure Subscription if not set as argument
if(!($AzureSubscriptionID)) {    
    Get-AzSubscription -TenantId $TenantID | Format-Table
    if (!($AzureSubscriptionID = Read-Host "⌨  Type your SubscriptionID or press Enter to accept your current one [$currentSubscription]")) { $AzureSubscriptionID = $currentSubscription }
}
else {
    Write-Host "🔑 Azure Subscription provided: $AzureSubscriptionID"
}

#Set the AZ Cli context
az account set -s $AzureSubscriptionID
Write-Host "🔑 Azure Subscription '$AzureSubscriptionID' selected."

#endregion

$ErrorActionPreference = "Stop"
$startTime = Get-Date


#region Set up Variables and Default Parameters

if ($ResourceGroupForDeployment -eq "") {
    $ResourceGroupForDeployment = $WebAppNamePrefix 
}
if ($SQLServerName -eq "") {
    $SQLServerName = $WebAppNamePrefix + "-sql"
}
if ($SQLDatabaseName -eq "") {
    $SQLDatabaseName = $WebAppNamePrefix +"AMPSaaSDB"
}

if($KeyVault -eq "")
{
   $KeyVault=$WebAppNamePrefix+"-kv"
   $kv_check=$(az keyvault show -n $KeyVault -g $ResourceGroupForDeployment) 2>$null    

   if($kv_check -eq $null)
   {
		$KeyVaultApiUri="https://management.azure.com/subscriptions/$AzureSubscriptionID/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2019-09-01"
		$KeyVaultApiBody='{"name": "'+$KeyVault+'","type": "Microsoft.KeyVault/vaults"}'

		$kv_check=az rest --method post --uri $KeyVaultApiUri --headers 'Content-Type=application/json' --body $KeyVaultApiBody | ConvertFrom-Json

		if( $kv_check.reason -eq "AlreadyExists")
		{
			Write-Host ""
			Write-Host "🛑  KeyVault name $KeyVault already exists." -ForegroundColor Red
			exit 1
		}
	}
}

$SaaSApiConfiguration_CodeHash= git log --format='%H' -1
$azCliOutput = if($Quiet){'none'} else {'json'}

#endregion

#region Validate Parameters

if($WebAppNamePrefix.Length -gt 21) {
    Throw "🛑 Web name prefix must be less than 21 characters."
    exit 1
}

if(!($KeyVault -match "^[a-zA-Z][a-z0-9-]+$")) {
    Throw "🛑 KeyVault name only allows alphanumeric and hyphens, but cannot start with a number or special character."
    exit 1
}

#endregion 

#region pre-checks
$dotnetversion = dotnet --version
if(!$dotnetversion.StartsWith('8.')) {
    Throw "🛑 Dotnet 8 not installed. Install dotnet8 and re-run the script."
    Exit
}
#endregion

Write-Host "Starting SaaS Accelerator Deployment..."

#region Check If SQL Server Exist
$sql_exists = Get-AzureRmSqlServer -ServerName $SQLServerName -ResourceGroupName $ResourceGroupForDeployment -ErrorAction SilentlyContinue
if ($sql_exists) 
{
	Write-Host "🛑 SQl Server name $SQLServerName already exists." -ForegroundColor Red
    exit 1
}  
#endregion

#region Dowloading assets
if($LogoURLpng) { 
    Write-Host "📷 Logo image provided"
    Invoke-WebRequest -Uri $LogoURLpng -OutFile "../src/CustomerSite/wwwroot/contoso-sales.png"
    Invoke-WebRequest -Uri $LogoURLpng -OutFile "../src/AdminSite/wwwroot/contoso-sales.png"
}
if($LogoURLico) { 
    Write-Host "📷 Logo icon provided"
    Invoke-WebRequest -Uri $LogoURLico -OutFile "../src/CustomerSite/wwwroot/favicon.ico"
    Invoke-WebRequest -Uri $LogoURLico -OutFile "../src/AdminSite/wwwroot/favicon.ico"
}
#endregion
 
#region Create AAD App Registrations
$ISLoginAppProvided = ($ADApplicationIDAdmin -ne "" -or $ADMTApplicationIDPortal -ne "")
if($ISLoginAppProvided){ Write-Host "🔑 Multi-Tenant App Registrations provided." }

if($IsAdminPortalMultiTenant -eq "true"){ $IsAdminPortalMultiTenant = $true } else { $IsAdminPortalMultiTenant = $false }

if (!($ADApplicationID)) {   
    Write-Host "🔑 Creating Fulfilment API App Registration"
    try {   
        $ADApplication = az ad app create --only-show-errors --sign-in-audience AzureADMYOrg --display-name "$WebAppNamePrefix-FulfillmentAppReg" | ConvertFrom-Json
		$ADObjectID = $ADApplication.id
        $ADApplicationID = $ADApplication.appId
        
        Retry-Command -ActivityName "Create SP for Fulfillment App" -Command { az ad sp create --id $ADApplicationID }
        Retry-Command -ActivityName "Reset Credential" -Command {
            $Script:ADApplicationSecret = az ad app credential reset --id $ADObjectID --append --display-name 'SaaSAPI' --years 2 --query password --only-show-errors --output tsv
        }
        Write-Host "   🔵 FulfilmentAPI App Registration created."
    }
    catch { Write-Host "🚨🚨   $PSItem.Exception"; break; }
}

if (!($ADApplicationIDAdmin)) {  
    Write-Host "🔑 Creating Admin Portal SSO App Registration"
    try {
		$appCreateRequestBodyJson = @"
{
	"displayName" : "$WebAppNamePrefix-AdminPortalAppReg",
	"api": { "requestedAccessTokenVersion" : 2 },
	"signInAudience" : "AzureADMyOrg",
	"web": { 
		"redirectUris": [ "https://$WebAppNamePrefix-admin.azurewebsites.net", "https://$WebAppNamePrefix-admin.azurewebsites.net/Home/Index" ],
		"logoutUrl": "https://$WebAppNamePrefix-admin.azurewebsites.net/logout",
		"implicitGrantSettings": { "enableIdTokenIssuance" : true }
	},
	"requiredResourceAccess": [{ "resourceAppId": "00000003-0000-0000-c000-000000000000", "resourceAccess": [{ "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope" }] }]
}
"@	
		if ($PsVersionTable.Platform -ne 'Unix') { $appCreateRequestBodyJson = $appCreateRequestBodyJson.replace('"','\"').replace("`r`n","") }
		$adminPortalAppReg = $(az rest --method POST --headers "Content-Type=application/json" --uri https://graph.microsoft.com/v1.0/applications --body $appCreateRequestBodyJson  ) | ConvertFrom-Json
		$ADApplicationIDAdmin = $adminPortalAppReg.appId
		$ADMTObjectIDAdmin = $adminPortalAppReg.id
        Write-Host "   🔵 Admin Portal SSO App Registration created."

        if($LogoURLpng) { 
			$token=(az account get-access-token --resource "https://graph.microsoft.com" --query accessToken --output tsv)
			$logoWeb = Invoke-WebRequest $LogoURLpng
			$uploaded = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/applications/$ADMTObjectIDAdmin/logo" -Method "PUT" -Header @{"Authorization"="Bearer $token";"Content-Type"=$logoWeb.Headers["Content-Type"];} -Body $logoWeb.Content
        }
    }
    catch { Write-Host "🚨🚨   $PSItem.Exception"; break; }
}

if (!($ADMTApplicationIDPortal)) {  
    Write-Host "🔑 Creating Landing Page SSO App Registration"
    try {
		$appCreateRequestBodyJson = @"
{
	"displayName" : "$WebAppNamePrefix-LandingpageAppReg",
	"api": { "requestedAccessTokenVersion" : 2 },
	"signInAudience" : "AzureADandPersonalMicrosoftAccount",
	"web": { 
		"redirectUris": [ "https://$WebAppNamePrefix-portal.azurewebsites.net", "https://$WebAppNamePrefix-portal.azurewebsites.net/Home/Index" ],
		"logoutUrl": "https://$WebAppNamePrefix-portal.azurewebsites.net/logout",
		"implicitGrantSettings": { "enableIdTokenIssuance" : true }
	},
	"requiredResourceAccess": [{ "resourceAppId": "00000003-0000-0000-c000-000000000000", "resourceAccess": [{ "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope" }] }]
}
"@	
		if ($PsVersionTable.Platform -ne 'Unix') { $appCreateRequestBodyJson = $appCreateRequestBodyJson.replace('"','\"').replace("`r`n","") }
		$landingpageLoginAppReg = $(az rest --method POST --headers "Content-Type=application/json" --uri https://graph.microsoft.com/v1.0/applications --body $appCreateRequestBodyJson  ) | ConvertFrom-Json
		$ADMTApplicationIDPortal = $landingpageLoginAppReg.appId
		$ADMTObjectIDPortal = $landingpageLoginAppReg.id
        Write-Host "   🔵 Landing Page SSO App Registration created."
	
        if($LogoURLpng) { 
			$token=(az account get-access-token --resource "https://graph.microsoft.com" --query accessToken --output tsv)
			$logoWeb = Invoke-WebRequest $LogoURLpng
			$uploaded = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/applications/$ADMTObjectIDPortal/logo" -Method "PUT" -Header @{"Authorization"="Bearer $token";"Content-Type"=$logoWeb.Headers["Content-Type"];} -Body $logoWeb.Content
        }
    }
    catch { Write-Host "🚨🚨   $PSItem.Exception"; break; }
}
#endregion

#region Prepare Code Packages
if (!(Test-Path '../Publish')) {		
	Write-host "📜 Prepare publish files for the application"
	dotnet publish ../src/AdminSite/AdminSite.csproj -c release -o ../Publish/AdminSite/ -v q
    
    # FIX: Added -p:PublishReadyToRun=false to prevent OOM (Exit code 137) during crossgen2
	Write-host "   🔵 Preparing Metered Scheduler (ReadyToRun disabled for memory safety)"
	dotnet publish ../src/MeteredTriggerJob/MeteredTriggerJob.csproj -c release -o ../Publish/AdminSite/app_data/jobs/triggered/MeteredTriggerJob/ -v q --runtime win-x64 --self-contained true -p:PublishReadyToRun=false

	Write-host "   🔵 Preparing Customer Site"
	dotnet publish ../src/CustomerSite/CustomerSite.csproj -c release -o ../Publish/CustomerSite/ -v q

	Write-host "   🔵 Zipping packages"
	Compress-Archive -Path ../Publish/AdminSite/* -DestinationPath ../Publish/AdminSite.zip -Force
	Compress-Archive -Path ../Publish/CustomerSite/* -DestinationPath ../Publish/CustomerSite.zip -Force
}
#endregion

#region Deploy Azure Resources Infrastructure
Write-host "☁ Deploy Azure Resources"

#Set-up resource name variables
$WebAppNameService=$WebAppNamePrefix+"-asp"
$WebAppNameAdmin=$WebAppNamePrefix+"-admin"
$WebAppNamePortal=$WebAppNamePrefix+"-portal"
$VnetName=$WebAppNamePrefix+"-vnet"
$privateSqlEndpointName=$WebAppNamePrefix+"-db-pe"
$privateKvEndpointName=$WebAppNamePrefix+"-kv-pe"
$privateSqlDnsZoneName="privatelink.database.windows.net"
$privateKvDnsZoneName="privatelink.vaultcore.windows.net"
$privateSqlLink =$WebAppNamePrefix+"-db-link"
$privateKvlink =$WebAppNamePrefix+"-kv-link"
$WebSubnetName="web"
$SqlSubnetName="sql"
$KvSubnetName="kv"
$DefaultSubnetName="default"

$ADApplicationSecretKeyVault="@Microsoft.KeyVault(VaultName=$KeyVault;SecretName=ADApplicationSecret) "
$DefaultConnectionKeyVault="@Microsoft.KeyVault(VaultName=$KeyVault;SecretName=DefaultConnection) "
$ServerUri = $SQLServerName+".database.windows.net"
$ServerUriPrivate = $SQLServerName+".privatelink.database.windows.net"
$Connection="Server=tcp:"+$ServerUriPrivate+";Database="+$SQLDatabaseName+";TrustServerCertificate=True;Authentication=Active Directory Managed Identity;"

Write-host "   🔵 Resource Group"
az group create --location $Location --name $ResourceGroupForDeployment --output $azCliOutput
# CRITICAL FIX: Wait for RG to be ready
az group wait --created --name $ResourceGroupForDeployment

Write-host "      ➡️ Create VNET"
# CRITICAL FIX: Create VNet separate from subnets and WAIT
az network vnet create --resource-group $ResourceGroupForDeployment --name $VnetName --address-prefixes "10.0.0.0/20" --output $azCliOutput
WaitFor-Resource -ResourceGroup $ResourceGroupForDeployment -Name $VnetName -ResourceType "Microsoft.Network/virtualNetworks" -ActivityName "VNet Creation"

Write-host "      ➡️ Creating Subnets..."
# CRITICAL FIX: Serialized subnet creation with retries
Retry-Command -ActivityName "Create Default Subnet" -Command {
    az network vnet subnet create --resource-group $ResourceGroupForDeployment --vnet-name $VnetName -n $DefaultSubnetName --address-prefixes "10.0.0.0/24" --output $azCliOutput
}

Retry-Command -ActivityName "Create Web Subnet" -Command {
    az network vnet subnet create --resource-group $ResourceGroupForDeployment --vnet-name $VnetName -n $WebSubnetName --address-prefixes "10.0.1.0/24" --service-endpoints Microsoft.Sql Microsoft.KeyVault --delegations Microsoft.Web/serverfarms --output $azCliOutput 
}

Retry-Command -ActivityName "Create SQL Subnet" -Command {
    az network vnet subnet create --resource-group $ResourceGroupForDeployment --vnet-name $VnetName -n $SqlSubnetName --address-prefixes "10.0.2.0/24"  --output $azCliOutput 
}

Retry-Command -ActivityName "Create KV Subnet" -Command {
    az network vnet subnet create --resource-group $ResourceGroupForDeployment --vnet-name $VnetName -n $KvSubnetName --address-prefixes "10.0.3.0/24"   --output $azCliOutput 
}

# Verify Subnets Exist
Write-Host "      ➡️ Verifying Network Fabric..."
$subnetCheck = az network vnet subnet show --resource-group $ResourceGroupForDeployment --vnet-name $VnetName --name $WebSubnetName --query id -o tsv 2>$null
if (-not $subnetCheck) { Throw "🛑 Fatal Error: Web Subnet failed to create. Aborting deployment." }


Write-host "      ➡️ Create Sql Server"
$userId = az ad signed-in-user show --query id -o tsv 
$userdisplayname = az ad signed-in-user show --query displayName -o tsv 
az sql server create --name $SQLServerName --resource-group $ResourceGroupForDeployment --location $Location  --enable-ad-only-auth --external-admin-principal-type User --external-admin-name $userdisplayname --external-admin-sid $userId --output $azCliOutput
WaitFor-Resource -ResourceGroup $ResourceGroupForDeployment -Name $SQLServerName -ResourceType "Microsoft.Sql/servers" -ActivityName "SQL Server"

az sql server update --name $SQLServerName --resource-group $ResourceGroupForDeployment --set minimalTlsVersion="1.2"
az sql server firewall-rule create --resource-group $ResourceGroupForDeployment --server $SQLServerName -n AllowAzureIP --start-ip-address "0.0.0.0" --end-ip-address "0.0.0.0" --output $azCliOutput

if ($env:ACC_CLOUD -eq $null){
    try {
        $publicIp = (Invoke-WebRequest -uri "https://api.ipify.org" -UseBasicParsing).Content
        if ($publicIp) {
            Retry-Command -ActivityName "Add Client IP to SQL" -Command {
                az sql server firewall-rule create --resource-group $ResourceGroupForDeployment --server $SQLServerName -n AllowIP --start-ip-address "$publicIp" --end-ip-address "$publicIp" --output $azCliOutput
            }
        }
    } catch { Write-Host "⚠️  Could not detect public IP." }
}

Write-host "      ➡️ Create SQL DB"
az sql db create --resource-group $ResourceGroupForDeployment --server $SQLServerName --name $SQLDatabaseName  --edition Standard  --capacity 10 --zone-redundant false --output $azCliOutput

Write-host "   🔵 KeyVault"
az keyvault create --name $KeyVault --resource-group $ResourceGroupForDeployment --enable-rbac-authorization false --output $azCliOutput
WaitFor-Resource -ResourceGroup $ResourceGroupForDeployment -Name $KeyVault -ResourceType "Microsoft.KeyVault/vaults" -ActivityName "KeyVault"

Write-host "      ➡️ Add Secrets"
Retry-Command -ActivityName "Set AD Secret" -Command {
    az keyvault secret set --vault-name $KeyVault --name ADApplicationSecret --value="$ADApplicationSecret" --output $azCliOutput
}
Retry-Command -ActivityName "Set Connection Secret" -Command {
    az keyvault secret set --vault-name $KeyVault --name DefaultConnection --value $Connection --output $azCliOutput
}

Write-host "      ➡️ Update Firewall"
# Ensure KV is ready for firewall rules
Retry-Command -ActivityName "Update KV Firewall" -Command {
    az keyvault update --name $KeyVault --resource-group $ResourceGroupForDeployment --default-action Deny --output $azCliOutput
    az keyvault network-rule add --name $KeyVault --resource-group $ResourceGroupForDeployment --vnet-name $VnetName --subnet $WebSubnetName --output $azCliOutput
}

Write-host "   🔵 App Service Plan"
az appservice plan create -g $ResourceGroupForDeployment -n $WebAppNameService --sku B1 --output $azCliOutput

Write-host "   🔵 Admin Portal WebApp"
az webapp create -g $ResourceGroupForDeployment -p $WebAppNameService -n $WebAppNameAdmin  --runtime dotnet:8 --output $azCliOutput
WaitFor-Resource -ResourceGroup $ResourceGroupForDeployment -Name $WebAppNameAdmin -ResourceType "Microsoft.Web/sites" -ActivityName "Admin WebApp"

$WebAppNameAdminId = az webapp identity assign -g $ResourceGroupForDeployment  -n $WebAppNameAdmin --identities [system] --query principalId -o tsv
Retry-Command -ActivityName "AdminPortal KV Policy" -Command {
    az keyvault set-policy --name $KeyVault  --object-id $WebAppNameAdminId --secret-permissions get list --key-permissions get list --resource-group $ResourceGroupForDeployment --output $azCliOutput
}
Write-host "      ➡️ Set Configuration"
Retry-Command -ActivityName "AdminPortal Config" -Command {
    az webapp config connection-string set -g $ResourceGroupForDeployment -n $WebAppNameAdmin -t SQLAzure --output $azCliOutput --settings DefaultConnection=$DefaultConnectionKeyVault 
    az webapp config appsettings set -g $ResourceGroupForDeployment  -n $WebAppNameAdmin --output $azCliOutput --settings KnownUsers=$PublisherAdminUsers SaaSApiConfiguration__AdAuthenticationEndPoint=https://login.microsoftonline.com SaaSApiConfiguration__ClientId=$ADApplicationID SaaSApiConfiguration__ClientSecret=$ADApplicationSecretKeyVault SaaSApiConfiguration__FulFillmentAPIBaseURL=https://marketplaceapi.microsoft.com/api SaaSApiConfiguration__FulFillmentAPIVersion=2018-08-31 SaaSApiConfiguration__GrantType=client_credentials SaaSApiConfiguration__MTClientId=$ADApplicationIDAdmin SaaSApiConfiguration__IsAdminPortalMultiTenant=$IsAdminPortalMultiTenant SaaSApiConfiguration__Resource=20e940b3-4c77-4b0b-9a53-9e16a1b010a7 SaaSApiConfiguration__TenantId=$TenantID SaaSApiConfiguration__SignedOutRedirectUri=https://$WebAppNamePrefix-admin.azurewebsites.net/Home/Index/ SaaSApiConfiguration_CodeHash=$SaaSApiConfiguration_CodeHash
    az webapp config set -g $ResourceGroupForDeployment -n $WebAppNameAdmin --always-on true  --output $azCliOutput
}

Write-host "   🔵 Customer Portal WebApp"
az webapp create -g $ResourceGroupForDeployment -p $WebAppNameService -n $WebAppNamePortal --runtime dotnet:8 --output $azCliOutput
WaitFor-Resource -ResourceGroup $ResourceGroupForDeployment -Name $WebAppNamePortal -ResourceType "Microsoft.Web/sites" -ActivityName "Customer WebApp"

$WebAppNamePortalId= az webapp identity assign -g $ResourceGroupForDeployment  -n $WebAppNamePortal --identities [system] --query principalId -o tsv 
Retry-Command -ActivityName "CustomerPortal KV Policy" -Command {
    az keyvault set-policy --name $KeyVault  --object-id $WebAppNamePortalId --secret-permissions get list --key-permissions get list --resource-group $ResourceGroupForDeployment --output $azCliOutput
}
Write-host "      ➡️ Set Configuration"
Retry-Command -ActivityName "CustomerPortal Config" -Command {
    az webapp config connection-string set -g $ResourceGroupForDeployment -n $WebAppNamePortal -t SQLAzure --output $azCliOutput --settings DefaultConnection=$DefaultConnectionKeyVault
    az webapp config appsettings set -g $ResourceGroupForDeployment  -n $WebAppNamePortal --output $azCliOutput --settings SaaSApiConfiguration__AdAuthenticationEndPoint=https://login.microsoftonline.com SaaSApiConfiguration__ClientId=$ADApplicationID SaaSApiConfiguration__ClientSecret=$ADApplicationSecretKeyVault SaaSApiConfiguration__FulFillmentAPIBaseURL=https://marketplaceapi.microsoft.com/api SaaSApiConfiguration__FulFillmentAPIVersion=2018-08-31 SaaSApiConfiguration__GrantType=client_credentials SaaSApiConfiguration__MTClientId=$ADMTApplicationIDPortal SaaSApiConfiguration__Resource=20e940b3-4c77-4b0b-9a53-9e16a1b010a7 SaaSApiConfiguration__TenantId=$TenantID SaaSApiConfiguration__SignedOutRedirectUri=https://$WebAppNamePrefix-portal.azurewebsites.net/Home/Index/ SaaSApiConfiguration_CodeHash=$SaaSApiConfiguration_CodeHash
    az webapp config set -g $ResourceGroupForDeployment -n $WebAppNamePortal --always-on true --output $azCliOutput
}
#endregion

#region Deploy Code
Write-host "📜 Deploy Code"

Write-host "   🔵 Deploy Database"
$ConnectionString="Server=tcp:"+$ServerUri+";Database="+$SQLDatabaseName+";Authentication=Active Directory Default;"
Set-Content -Path ../src/AdminSite/appsettings.Development.json -value "{`"ConnectionStrings`": {`"DefaultConnection`":`"$ConnectionString`"}}"
dotnet-ef migrations script  --output script.sql --idempotent --context SaaSKitContext --project ../src/DataAccess/DataAccess.csproj --startup-project ../src/AdminSite/AdminSite.csproj

# RACE CONDITION FIX: Retry SQL Command
Retry-Command -ActivityName "Execute SQL Migrations" -Command { Invoke-Sqlcmd -InputFile ./script.sql -ConnectionString $ConnectionString }

$AddAppsIdsToDB = "CREATE USER [$WebAppNameAdmin] FROM EXTERNAL PROVIDER;ALTER ROLE db_datareader ADD MEMBER  [$WebAppNameAdmin];ALTER ROLE db_datawriter ADD MEMBER  [$WebAppNameAdmin]; GRANT EXEC TO [$WebAppNameAdmin]; CREATE USER [$WebAppNamePortal] FROM EXTERNAL PROVIDER;ALTER ROLE db_datareader ADD MEMBER [$WebAppNamePortal];ALTER ROLE db_datawriter ADD MEMBER [$WebAppNamePortal]; GRANT EXEC TO [$WebAppNamePortal];"
Retry-Command -ActivityName "Add DB Users" -Command { Invoke-Sqlcmd -Query $AddAppsIdsToDB -ConnectionString $ConnectionString }

Write-host "   🔵 Deploy Code to WebApps"
az webapp deploy --resource-group $ResourceGroupForDeployment --name $WebAppNameAdmin --src-path "../Publish/AdminSite.zip" --type zip --output $azCliOutput
az webapp deploy --resource-group $ResourceGroupForDeployment --name $WebAppNamePortal --src-path "../Publish/CustomerSite.zip" --type zip --output $azCliOutput

Write-host "   🔵 Update Firewall for WebApps and SQL"
# CRITICAL FIX: Validate Subnet before attaching Vnet Integration
if (az network vnet subnet show --resource-group $ResourceGroupForDeployment --vnet-name $VnetName --name $WebSubnetName --query id -o tsv) {
    Retry-Command -ActivityName "VNet Integration Portal" -Command { az webapp vnet-integration add --resource-group $ResourceGroupForDeployment --name $WebAppNamePortal --vnet $VnetName --subnet $WebSubnetName --output $azCliOutput }
    Retry-Command -ActivityName "VNet Integration Admin" -Command { az webapp vnet-integration add --resource-group $ResourceGroupForDeployment --name $WebAppNameAdmin --vnet $VnetName --subnet $WebSubnetName --output $azCliOutput }
    Retry-Command -ActivityName "SQL VNet Rule" -Command { az sql server vnet-rule create --name $WebAppNamePrefix-vnet --resource-group $ResourceGroupForDeployment --server $SQLServerName --vnet-name $VnetName --subnet $WebSubnetName --output $azCliOutput }
} else {
    Write-Host "⚠️  Web Subnet not found. Skipping VNet integration." -ForegroundColor Red
}

Write-host "   🔵 Clean up"
Remove-Item -Path ../src/AdminSite/appsettings.Development.json
Remove-Item -Path script.sql
#endregion

#region Create Private Endpoints
# Wrapped in retry to handle potential resource lag
Retry-Command -ActivityName "Private Endpoints" -Command {
    $sqlServerId=az sql server show --name $SQLServerName --resource-group $ResourceGroupForDeployment --query id -o tsv
    az network private-endpoint create --name $privateSqlEndpointName --resource-group $ResourceGroupForDeployment --vnet-name $vnetName --subnet $SqlSubnetName --private-connection-resource-id $sqlServerId --group-ids sqlServer --connection-name sqlConnection
    az network private-dns zone create --name $privateSqlDnsZoneName --resource-group $ResourceGroupForDeployment
    az network private-dns link vnet create --name $privateSqlLink --resource-group $ResourceGroupForDeployment --virtual-network $vnetName --zone-name $privateSqlDnsZoneName --registration-enabled false
    az network private-endpoint dns-zone-group create --resource-group $ResourceGroupForDeployment --endpoint-name $privateSqlEndpointName --name "sql-zone-group"   --private-dns-zone $privateSqlDnsZoneName   --zone-name "sqlserver"

    $keyVaultId=az keyvault show --name $KeyVault --resource-group $ResourceGroupForDeployment --query id -o tsv
    az network private-endpoint create --name $privateKvEndpointName --resource-group $ResourceGroupForDeployment --vnet-name $vnetName --subnet $KvSubnetName --private-connection-resource-id $keyVaultId --group-ids vault  --connection-name kvConnection
    az network private-dns zone create --name $privateKvDnsZoneName --resource-group $ResourceGroupForDeployment
    az network private-dns link vnet create --name $privateKvLink --resource-group $ResourceGroupForDeployment --virtual-network $vnetName --zone-name $privateKvDnsZoneName --registration-enabled false
    az network private-endpoint dns-zone-group create --resource-group $ResourceGroupForDeployment --endpoint-name $privateKvEndpointName --name "Kv-zone-group"   --private-dns-zone $privateKvDnsZoneName   --zone-name "Kv-zone"
}
#endregion

#region Present Output

Write-host "✅ If the intallation completed without error complete the folllowing checklist:"
if ($ISLoginAppProvided) {  
	Write-host "   🔵 Add The following URLs to the multi-tenant Landing Page AAD App Registration in Azure Portal:"
	Write-host "      ➡️ https://$WebAppNamePrefix-portal.azurewebsites.net"
	Write-host "      ➡️ https://$WebAppNamePrefix-portal.azurewebsites.net/"
	Write-host "      ➡️ https://$WebAppNamePrefix-portal.azurewebsites.net/Home/Index"
	Write-host "      ➡️ https://$WebAppNamePrefix-portal.azurewebsites.net/Home/Index/"
	Write-host "   🔵 Add The following URLs to the multi-tenant Admin Portal AAD App Registration in Azure Portal:"
	Write-host "      ➡️ https://$WebAppNamePrefix-admin.azurewebsites.net"
	Write-host "      ➡️ https://$WebAppNamePrefix-admin.azurewebsites.net/"
	Write-host "      ➡️ https://$WebAppNamePrefix-admin.azurewebsites.net/Home/Index"
	Write-host "      ➡️ https://$WebAppNamePrefix-admin.azurewebsites.net/Home/Index/"
	Write-host "   🔵 Verify ID Tokens checkbox has been checked-out ?"
}

Write-host "   🔵 Add The following URL in PartnerCenter SaaS Technical Configuration"
Write-host "      ➡️ Landing Page section:       https://$WebAppNamePrefix-portal.azurewebsites.net/"
Write-host "      ➡️ Connection Webhook section: https://$WebAppNamePrefix-portal.azurewebsites.net/api/AzureWebhook"
Write-host "      ➡️ Tenant ID:                  $TenantID"
Write-host "      ➡️ AAD Application ID section: $ADApplicationID"
$duration = (Get-Date) - $startTime
Write-Host "Deployment Complete in $($duration.Minutes)m:$($duration.Seconds)s"
Write-Host "DO NOT CLOSE THIS SCREEN.  Please make sure you copy or perform the actions above before closing."
#endregion
