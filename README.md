# PublicScripts
This script uses EWS Managed API, which means this must be enabled on the target mailbox in order to succeed. For the Managed API to be used, there needs to exist an AAD Application with EWS delegated only permissions, which will be used for OAUTH authentication. The reason for using delegation permission only, is so that the script can only be executed against the authenticated mailbox and not for others, which would be a security concern.
To facilitate the script execution, I have created a multi-tenant application with EWS Permission only, but if the customer wants a self owned application, then it can be changed in the parameters.

1.	Simple execution Scenario: Call the script passing only the SMTP address

.\InboxHiddenRules.ps1 -Mailbox foo@foo.onmicrosoft.com
The OAUTH Authentication  dialog will be displayed, and the user will need to give consent(only first time execution):


![image](https://user-images.githubusercontent.com/38019684/206328599-419be792-0cbc-4589-83be-052582a89f6f.png)
![image](https://user-images.githubusercontent.com/38019684/206328637-770ca979-a489-4543-9665-da919943f2a0.png)

If no further parameters are specified, the default multi-tenant application will be used (d82d66ce-348b-4a2c-a8a4-44f8649ab242), and the tenant ID will be automatically detected, however, a second prompt will appear, as the script will need to connect to Azure AD to get this value.
![image](https://user-images.githubusercontent.com/38019684/206328734-112b64f5-9a14-40f5-9484-ffa81057daf8.png)


2.	Specifying a custom application ID 
.\InboxHiddenRules-MS.ps1 -Mailbox foo@foo.onmicrosoft.com -OAuthClientId <GUID AppID>

This scenario allows the user to specify a custom Application Id, if they prefer to use an internal AAD application only. The tenant ID will still be automatically detected, so it will bring the authentication dialog as on previous scenario.

3.	Specifying Custom Application ID and Tenant ID
.\InboxHiddenRules-MS.ps1 -Mailbox foo@foo.onmicrosoft.com -OAuthClientId <GUID AppID> -OAuthTenantId <TenantID>

In this parameter configuration, a custom application ID will be used, and no automatic detection of Tenant ID will occur




4.	Sample result returned from the Script (Dataset returned per found rule)
ActionType             : 
Action                 : OUY2NEVBN0I1MzAwMUFDODlFRTZDMzEtQk9PS0lOR1MgVEUA (Shortened for readability)
                         8AbwBrAGkAbgBnAHMAIABHAHUAcgB1AA==
ItemClass              : IPM.Rule.Version2.Message
IsPotentiallyMalicious : False
State                  : 1
Condition              : AAAKBAMAAGABAAAAAgEBAJ0AAAAAAAAA3KdAyMBC (Shortened for readability)
ActionCommand          : 
RuleName               : The Bookings Guru
DateCreated            : 11/8/2022 7:08:16 PM
User                   : foo@foo.onmicrosoft.com

