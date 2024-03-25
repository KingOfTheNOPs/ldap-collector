# ldap-collector
C# utility to collect Active Directory data. Uses Costura.Fody to embedd all your resources into your assembly which allows for it to be ran with BOF.NET. Optional arguments for naming file, saving to zip, password protecting zip file, and output SDDL into bofhound friendly format. 

## Usage

```
  -d, --domain        Required. Specify a Domain: -d LDAP://domain.local

  -q, --query         Required. Specify a query: -q (&((objectClass=user))

  -f, --file          Specify where to save results: -f C:\Windows\Temp\ldap.txt

  -z, --zipname       Specify the zipname to save results to: -z ldap.zip

  -p, --pass          Specify password to encrypt file with: -p password

  -r, --properties    Required. Specify what properties your want to query: -r samaccountname

  -s, --showacl       (Default: false) Specify if you would like to translate the SDDL: -s

  -i, --index         (Default: Int32.MaxValue) Specify number of results returned: -i 10

  -b, --bofhound      (Default: false) Specify if you would like to convert SDDL to base64 for bofhound: -b

  --help              Display this help screen.

  --version           Display version information.
```
### Example Usage

```
ldap-collector.exe -d LDAP://test.local -q "(&(objectClass=user)samaccountname=administrator)" -r samaccountname,pwdlastset,ntSecurityDescriptor,objectsid,objectGuid
```
#### Output Example
```
samaccountname           : Administrator,
pwdlastset               : 133464744651266761,
ntSecurityDescriptor     : G:S-1-5-21-1620280429-3693627270-3510196929-512D:PAI(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1620280429-3693627270-3510196929-517)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;S-1-5-21-1620280429-3693627270-3510196929-512)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;S-1-5-21-1620280429-3693627270-3510196929-519)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)

objectsid                : S-1-5-21-1620280429-3693627270-3510196929-500,
objectGuid               : 29c7885a-c590-4b3d-9ada-2db0d78392a7,
```


## Usage with https://github.com/williamknows/BOF.NET

For instances when your beacon needs to sleep but you need to collect AD data
```
bofnet_init 
bofnet_load /opt/tools/ldap-collector.exe
bofnet_executeassembly ldap-collector bofnet_executeassembly ldap-collector -d LDAP://test.local -q "(&(objectclass=user))" -r samaccountname,objectsid,ntsecuritydescriptor,pwdlastset -f C:\Windows\Tasks\ldap3.txt -p password123 -z zippy.zip
download C:\Windows\Tasks\zippy.zip
```

## bofhound compatible collection
The following properties can be collected per objectClass and remain compatible with [bofhound](https://github.com/fortalice/bofhound)
```
ldap-collector.exe -d LDAP://test.local -q "(&(objectClass=Group))" -r objectClass,cn,description,distinguishedName,instanceType,whenCreated,whenChanged,uSNCreated,uSNChanged,nTSecurityDescriptor,name,objectGUID,objectSid,adminCount,sAMAccountName,sAMAccountType,systemFlags,groupType,objectCategory,isCriticalSystemObject,dSCorePropagationData -b -f beacon_group.log
ldap-collector.exe -d LDAP://test.local -q "(&(objectClass=Domain))" -r objectClass,distinguishedName,instanceType,whenCreated,whenChanged,subRefs,uSNCreated,uSNChanged,nTSecurityDescriptor,name,objectGUID,creationTime,forceLogoff,lockoutDuration,lockOutObservationWindow,lockoutThreshold,maxPwdAge,minPwdAge,minPwdLength,modifiedCountAtLastProm,nextRid,pwdProperties,pwdHistoryLength,objectSid,serverState,uASCompat,modifiedCount,nTMixedDomain,rIDManagerReference,fSMORoleOwner,systemFlags,wellKnownObjects,objectCategory,isCriticalSystemObject,gPLink,dSCorePropagationData,otherWellKnownObjects,masteredBy,ms-DS-MachineAccountQuota,msDS-Behavior-Version,msDS-PerUserTrustQuota,msDS-AllUsersTrustQuota,msDS-PerUserTrustTombstonesQuota,msDs-masteredBy,msDS-IsDomainFor,msDS-NcType,msDS-ExpirePasswordsOnSmartCardOnlyAccounts,dc -b -f beacon_domain.log
ldap-collector.exe -d LDAP://test.local -q "(&(objectClass=Computer))" -r accountExpires,badPasswordTime,badPwdCount,cn,dNSHostName,distinguishedName,instanceType,isCriticalSystemObject,lastLogoff,lastLogon,lastLogonTimestamp,localPolicyFlags,logonCount,memberOf,nTSecurityDescriptor,name,objectCategory,objectClass,objectGUID,objectSid,operatingSystem,operatingSystemVersion,primaryGroupID,pwdLastSet,sAMAccountName,sAMAccountType,servicePrincipalName,userAccountControl,whenChanged,whenCreated -b -f beacon_computer.log 
ldap-collector.exe -d LDAP://test.local -q "(&(objectClass=User))" -r accountExpires,adminCount,badPasswordTime,badPwdCount,cn,codePage,countryCode,dSCorePropagationData,description,distinguishedName,instanceType,isCriticalSystemObject,lastLogoff,lastLogon,lastLogonTimestamp,logonCount,logonHours,memberOf,msDS-SupportedEncryptionTypes,nTSecurityDescriptor,name,objectCategory,objectClass,objectGUID,objectSid,primaryGroupID,pwdLastSet,sAMAccountName,sAMAccountType,uSNChanged,uSNCreated,userAccountControl,whenChanged,whenCreated,serviceprincipalname -b -f beacon_user.log 
```
Additional queries but not tested to be BOFHound compatible
```
Find CA servers
ldap-collector.exe -d "LDAP://CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local" -q "(&(!name=AIA))" -r name
Find Templates
ldap-collector.exe -d "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local" -q "(name=*)" -r name,displayName,distinguishedName,msPKI-Cert-Template-OID,msPKI-Enrollment-Flag,pKIExtendedKeyUsage,msPKI-Certificate-Name-Flag
Find SCCM Servers
ldap-collector.exe -d "LDAP://CN=System Management,CN=System,DC=test,DC=local" -q "(name=*)" -r cn,distinguishedName,name,mSSMSSiteCode,mSSMSRoamingBoundaries,mSSMSSourceForest,mSSMSMPName,mSSMSDeviceManagementPoint,mSSMSDefaultMP
```
Parse with bofhound (file must start with beacon and end in .log)
```
bofhound -i -i /opt/tools/ldapsearch/ --all-properties
```
Upload files into bloodhound (tested with community edition)


## References
- Code inspired by Mr.Un1K0d3r's Offensive Coding Class and https://github.com/Mr-Un1k0d3r/ADHuntTool