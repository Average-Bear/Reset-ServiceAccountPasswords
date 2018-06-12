# Reset-ServiceAccountPasswords

Current goals: 
- Complete all documentation (mostly done).
- Do a search for KeePass.exe location, then feed the filepath instead of hardcoding a location; all required .DLL's should be located in the KeePass folder unless structure is different (for some reason).

Achieved goals: 
- Access KeePass Master DB and retrieve all accounts information as a secure string.
- Bring secure string back to Binary, then to string again because change method doesn't accept Secure Strings.
- Integrated Get-NonStandardServiceAccounts output. 
- Used Get-NonStandarServiceAccounts information from server and passed it into the account search within the KeePass Database.
- Included a Do{ While{}} loop to handle mistyped Master DB Password.
- Remove any cleartext and binary strings immediately after decryption.
- Remove all user created variables (current PowerShell session).

Notes: This script is currently working. Be sure to check current path locations for KeePass variables.

Thanks!

