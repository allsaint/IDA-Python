


-C     Comments or metadata to add to the public key
-t      The type of GitHub SSH key to create |RSA|
-o     Use the newest OpenSSH format |Leave blank|

`ssh-keygen`
```powershell
ssh-keygen -o -t rsa -C "allsaint.github.io keys"
```
Then paste key public key in github ssh keys.

`ssh-agent`
```powershell
Get-Service ssh-agent
Get-Service ssh-agent | Select StartType
Set-Service ssh-agent -StartupType Manual
```
