import datetime
import json
import logging
import re
import socket
import sys
import time
from base64 import b64decode
from collections.abc import Iterator
from enum import IntFlag
from typing import Callable, Self, Type
from uuid import UUID, uuid4
from xml.etree import ElementTree

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_CALLBACK_ACE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
    SYSTEM_MANDATORY_LABEL_ACE,
)
from pyasn1.type.useful import GeneralizedTime

import src.ms_nmf as ms_nmf
from src.ms_nns import NNS

from .soap_templates import (
    LDAP_PULL_FSTRING,
    LDAP_PUT_FSTRING,
    LDAP_QUERY_FSTRING,
    LDAP_RENEW_FSTRING,
    NAMESPACES,
)


_BARE_AMPERSAND_RE = re.compile(
    r"&(?!amp;|lt;|gt;|apos;|quot;|#[0-9]+;|#x[0-9a-fA-F]+;)"
)

_ENUMERATION_CONTEXT_RENEW_INTERVAL_SECONDS = 5 * 60
_ENUMERATION_CONTEXT_RENEW_DURATION = "PT30M"
_ADWS_REQUEST_RETRIES = 3
_ADWS_RETRY_BASE_DELAY_SECONDS = 1
_ADWS_TRANSIENT_FAULTS = ("OperationTimeout", "ReservedConnectionInvalidated")
_ADWS_INVALID_ENUMERATION_FAULTS = (
    "NoSuchEnumCtxGuidExists",
    "ReservedConnectionInvalidated",
)


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-systemflags
class SystemFlags(IntFlag):
    NONE = 0x00000000
    NO_REPLICATION = 0x00000001
    REPLICATE_TO_GC = 0x00000002
    CONSTRUCTED = 0x00000004
    CATEGORY_1 = 0x00000010
    NOT_DELETED = 0x02000000
    CANNOT_MOVE = 0x04000000
    CANNOT_RENAME = 0x08000000
    MOVED_WITH_RESTRICTIONS = 0x10000000
    MOVED = 0x20000000
    RENAMED = 0x40000000
    CANNOT_DELETE = 0x80000000


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
class InstanceTypeFlags(IntFlag):
    HEAD_OF_NAMING_CONTEXT = 0x00000001
    REPLICA_NOT_INSTANTIATED = 0x00000002
    OBJECT_WRITABLE = 0x00000004
    NAMING_CONTEXT_HELD = 0x00000008
    CONSTRUCTING_NAMING_CONTEXT = 0x00000010
    REMOVING_NAMING_CONTEXT = 0x00000020


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-grouptype
class GroupTypeFlags(IntFlag):
    SYSTEM_GROUP = 0x00000001
    GLOBAL_SCOPE = 0x00000002
    DOMAIN_LOCAL_SCOPE = 0x00000004
    UNIVERSAL_SCOPE = 0x00000008
    APP_BASIC_GROUP = 0x00000010
    APP_QUERY_GROUP = 0x00000020
    SECURITY_GROUP = 0x80000000


# https://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
class AccountPropertyFlag(IntFlag):
    SCRIPT = 0x0001
    ACCOUNTDISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    PASSWD_CANT_CHANGE = 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    TEMP_DUPLICATE_ACCOUNT = 0x0100
    NORMAL_ACCOUNT = 0x0200
    DISABLED_ACCOUNT = 0x0202  # Not officially documented
    ENABLED_PASSWORD_NOT_REQUIRED = 0x0220  # Not officially documented
    DISABLED_PASSWORD_NOT_REQUIRED = 0x0222  # Not officially documented
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    ENABLED_PASSWORD_DOESNT_EXPIRE = 0x10200  # Not officially documented
    DISABLED_PASSWORD_DOESNT_EXPIRE = 0x10202  # Not officially documented
    DISABLED_PASSWORD_DOESNT_EXPIRE_NOT_REQUIRED = 0x10222  # Not officially documented
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    ENABLED_SMARTCARD_REQUIRED = 0x40200  # Not officially documented
    DISABLED_SMARTCARD_REQUIRED = 0x40202  # Not officially documented
    DISABLED_SMARTCARD_REQUIRED_PASSWORD_NOT_REQUIRED = (
        0x40222  # Not officially documented
    )
    DISABLED_SMARTCARD_REQUIRED_PASSWORD_DOESNT_EXPIRE = (
        0x50202  # Not officially documented
    )
    DISABLED_SMARTCARD_REQUIRED_PASSWORD_DOESNT_EXPIRE_NOT_REQUIRED = (
        0x50222  # Not officially documented
    )
    TRUSTED_FOR_DELEGATION = 0x80000
    DOMAIN_CONTROLLER = 0x82000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000


# https://github.com/fortra/impacket/blob/829239e334fee62ace0988a0cb5284233d8ec3c4/impacket/dcerpc/v5/samr.py#L176
class SamAccountType(IntFlag):
    SAM_DOMAIN_OBJECT = 0x00000000
    SAM_GROUP_OBJECT = 0x10000000
    SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
    SAM_ALIAS_OBJECT = 0x20000000
    SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
    SAM_USER_OBJECT = 0x30000000
    SAM_MACHINE_ACCOUNT = 0x30000001
    SAM_TRUST_ACCOUNT = 0x30000002
    SAM_APP_BASIC_GROUP = 0x40000000
    SAM_APP_QUERY_GROUP = 0x40000001


# https://github.com/fortra/impacket/blob/829239e334fee62ace0988a0cb5284233d8ec3c4/examples/describeTicket.py#L118
BUILT_IN_GROUPS = {
    "498": "Enterprise Read-Only Domain Controllers",
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-Only Domain Controllers",
    "522": "Cloneable Controllers",
    "525": "Protected Users",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
    "553": "RAS and IAS Servers",
    "571": "Allowed RODC Password Replication Group",
    "572": "Denied RODC Password Replication Group",
}

# Universal SIDs
WELL_KNOWN_SIDS = {
    "S-1-0": "Null Authority",
    "S-1-0-0": "Nobody",
    "S-1-1": "World Authority",
    "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3": "Creator Authority",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-2": "Creator Owner Server",
    "S-1-3-3": "Creator Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-5-80-0": "All Services",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "This Organization",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority",
    "S-1-5-20": "NT Authority",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authority",
    "S-1-5-80": "NT Service",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-16-0": "Untrusted Mandatory Level",
    "S-1-16-4096": "Low Mandatory Level",
    "S-1-16-8192": "Medium Mandatory Level",
    "S-1-16-8448": "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level",
    "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level",
    "S-1-16-28672": "Secure Process Mandatory Level",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}


class ADWSError(Exception): ...


class ADWSReferralError(ADWSError):
    """Raised when the DC returns a LDAP referral (Win32ErrorCode 8235).

    The DC does not host the requested partition and refers us to another
    DC via <Referral>ldap://target-dc/target-dn</Referral>. Callers can
    catch this exception and retry against target_dc.

    Attributes:
        target_dc: FQDN of the DC that hosts the referred partition.
        target_dn: Distinguished name to use as base DN on target_dc.
        original_msg: Original error text from the SOAP fault.
    """

    def __init__(self, target_dc: str, target_dn: str, original_msg: str = ""):
        self.target_dc = target_dc
        self.target_dn = target_dn
        self.original_msg = original_msg
        super().__init__(f"LDAP referral to {target_dc}: {target_dn}")


class ADWSAuthType: ...


class KerberosAuth(ADWSAuthType):
    def __init__(self, kdc_host: str | None = None):
        self.kdc_host = kdc_host


class NTLMAuth(ADWSAuthType):
    def __init__(self, password: str | None = None, hashes: str | None = None):
        if not (password or hashes):
            raise ValueError("NTLM auth requires either a password or hashes.")

        if password and hashes:
            raise ValueError("Provide either a password or hashes, not both.")

        if hashes:
            self.nt = hashes
        else:
            self.nt = None

        self.password = password


class ADWSConnect:
    SID_RANGE_QUERY_CHUNK_SIZE = 256
    MAX_REFERRAL_HOPS = 3

    def __init__(
        self,
        fqdn: str,
        domain: str,
        username: str,
        auth: ADWSAuthType,
        resource: str,
    ):
        """Creates an ADWS client connection to the specified endpoint
        useing the specified auth.  Allows for making different types of
        queries to the ADWS Server.

        The client connects to different endpoints which allow different types
        of requests to be made.  **See [MS-ADDM]: 2.1 for a full list of endpoints.**  This
        client only supports endpoints which use windows integrated authentication.

        Args:
            fqdn (str): fqdn of the domain controler the adws service is running on
            domain (str): the domain
            username (str): user to auth as
            auth (ADWSAuthType): auth mechanism to use
            resource (str): the resource dictates what endpoint the client
                connects to which in turn dictates what types of requests
                it can make
        """
        self._fqdn = fqdn
        self._domain = domain
        self._username = username
        self._auth = auth

        self._resource: str = resource
        """the connection mode of the client <'Resource', 'ResourceFactory',
                'Enumeration', AccountManagement',  'TopologyManagement'>"""

        self._nmf: ms_nmf.NMFConnection = self._connect(self._fqdn, self._resource)

    def _swap_endpoint(self, target_dc: str, hops: int = 0) -> None:
        """Reconnect this client to a different DC after receiving an LDAP referral.

        Resolves target_dc via DNS, opens a new NMF connection against it, and
        updates self._fqdn so subsequent SOAP payloads use the referred DC's name.
        The old NMF is released to garbage collection.

        Bounded by ADWSConnect.MAX_REFERRAL_HOPS to prevent infinite loops on
        misconfigured multi-DC deployments.

        Args:
            target_dc: FQDN of the DC to reconnect to (from ADWSReferralError.target_dc).
            hops: Current recursion depth (caller manages this).

        Raises:
            RuntimeError: If MAX_REFERRAL_HOPS reached or DNS resolution fails.
        """
        if hops >= self.MAX_REFERRAL_HOPS:
            logging.error(
                f"Max referral hops ({self.MAX_REFERRAL_HOPS}) reached. "
                f"Last referral was to {target_dc}. Aborting."
            )
            raise RuntimeError(
                f"Max referral hops ({self.MAX_REFERRAL_HOPS}) reached"
            )

        logging.warning(
            f"LDAP referral (hop {hops + 1}/{self.MAX_REFERRAL_HOPS}): "
            f"following to {target_dc}"
        )

        try:
            target_ip = socket.gethostbyname(target_dc)
        except socket.gaierror as gai:
            logging.error(
                f"Cannot resolve referred DC {target_dc}: {gai}. "
                f"Add it to /etc/hosts or point -dc to a DC that hosts "
                f"the target partition directly."
            )
            raise RuntimeError(
                f"Cannot resolve referred DC {target_dc}"
            ) from gai

        logging.info(
            f"Reconnecting to {target_dc} ({target_ip})"
        )

        # Update self._fqdn BEFORE reconnecting - _create_NNS_from_auth uses
        # self._fqdn to build the NNS/Kerberos target.
        self._fqdn = target_dc

        # Open new NMF connection to the referred DC. The old self._nmf will
        # be released to GC when we reassign below.
        self._nmf = self._connect(target_ip, self._resource)

    def _create_NNS_from_auth(self, sock: socket.socket) -> NNS:
        if isinstance(self._auth, NTLMAuth):
            return NNS(
                socket=sock,
                fqdn=self._fqdn,
                domain=self._domain,
                username=self._username,
                password=self._auth.password,
                nt=self._auth.nt if self._auth.nt else "",
            )
        if isinstance(self._auth, KerberosAuth):
            return NNS(
                socket=sock,
                fqdn=self._fqdn,
                domain=self._domain,
                username=self._username,
                auth_protocol="kerberos",
                kdc_host=self._auth.kdc_host,
            )
        raise NotImplementedError

    def _connect(self, remoteName: str, resource: str) -> ms_nmf.NMFConnection:
        """Connect to the specified ADWS endpoint at the
        remoteName

        Args:
            remoteName (str): fqdn
            resource (str): endpoint to connect to <'Resource', 'ResourceFactory',
                'Enumeration', AccountManagement',  'TopologyManagement'>
        """

        server_address: tuple[str, int] = (remoteName, 9389)
        logging.info(f"Connecting to {remoteName} for resource:{self._resource}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server_address)

        nmf = ms_nmf.NMFConnection(
            self._create_NNS_from_auth(sock),
            fqdn=remoteName,
        )

        nmf.connect(f"Windows/{resource}")

        return nmf

    def _format_selection_properties(
        self,
        attributes: list | None,
        range_hints: dict[str, tuple[int, int | str | None]] | None = None,
    ) -> str:
        """Format ad:SelectionProperty elements, including optional range retrieval."""

        if attributes is None:
            return ""

        selection_properties = []
        for attr in attributes:
            range_attrs = ""
            if range_hints and attr in range_hints:
                range_low, range_high = range_hints[attr]
                range_attrs = f' RangeLow="{range_low}"'
                if range_high is not None:
                    range_attrs += f' RangeHigh="{range_high}"'

            selection_properties.append(
                f"<ad:SelectionProperty{range_attrs}>addata:{attr}</ad:SelectionProperty>"
            )

        return "\n".join(selection_properties) + ("\n" if selection_properties else "")

    def _iter_response_objects(self, et: ElementTree.Element) -> list[ElementTree.Element]:
        return et.findall(".//ad:value/../..", namespaces=NAMESPACES)

    def _get_object_identity(self, item: ElementTree.Element) -> str | None:
        object_ref = item.find("./ad:objectReferenceProperty/ad:value", namespaces=NAMESPACES)
        if object_ref is not None and object_ref.text:
            return object_ref.text

        distinguished_name = item.find("./addata:distinguishedName/ad:value", namespaces=NAMESPACES)
        if distinguished_name is not None and distinguished_name.text:
            return distinguished_name.text

        return None

    def _get_object_distinguished_name(self, item: ElementTree.Element) -> str | None:
        distinguished_name = item.find("./addata:distinguishedName/ad:value", namespaces=NAMESPACES)
        if distinguished_name is not None and distinguished_name.text:
            return distinguished_name.text
        return None

    def _get_object_sid(self, item: ElementTree.Element) -> str | None:
        sid_value = item.find("./addata:objectSid/ad:value", namespaces=NAMESPACES)
        if sid_value is None or sid_value.text is None:
            return None
        try:
            return LDAP_SID(data=b64decode(sid_value.text)).formatCanonical()
        except Exception:
            return None

    @staticmethod
    def _sid_parts(sid: str) -> tuple[int, ...]:
        parts = sid.split("-")
        if len(parts) < 4 or parts[0].upper() != "S":
            raise ValueError(f"Invalid SID: {sid}")
        try:
            values = tuple(int(part) for part in parts[1:])
        except ValueError as error:
            raise ValueError(f"Invalid SID: {sid}") from error
        if any(value < 0 for value in values):
            raise ValueError(f"Invalid SID: {sid}")
        return values

    @classmethod
    def _sid_filter_value(cls, sid: str) -> str:
        cls._sid_parts(sid)
        encoded_sid = LDAP_SID()
        try:
            encoded_sid.fromCanonical(sid)
            return "".join(f"\\{byte:02X}" for byte in encoded_sid.getData())
        except Exception as error:
            raise ValueError(f"Invalid SID: {sid}") from error

    @classmethod
    def sid_range_queries(
        cls, query: str, start_sid: str, end_sid: str
    ) -> Iterator[tuple[str, str, str]]:
        """Split an inclusive numeric RID interval into one-page SID queries."""
        start_parts = cls._sid_parts(start_sid)
        end_parts = cls._sid_parts(end_sid)
        if start_parts[:-1] != end_parts[:-1]:
            raise ValueError("start and end SID must use the same SID authority")
        if start_parts[-1] > end_parts[-1]:
            raise ValueError("start SID must not be greater than end SID")

        sid_prefix = "S-" + "-".join(str(value) for value in start_parts[:-1])
        for chunk_start in range(
            start_parts[-1], end_parts[-1] + 1, cls.SID_RANGE_QUERY_CHUNK_SIZE
        ):
            chunk_end = min(
                chunk_start + cls.SID_RANGE_QUERY_CHUNK_SIZE - 1, end_parts[-1]
            )
            matches = "".join(
                f"(objectSid={cls._sid_filter_value(f'{sid_prefix}-{rid}')})"
                for rid in range(chunk_start, chunk_end + 1)
            )
            yield (
                f"(&{query}(|{matches}))",
                f"{sid_prefix}-{chunk_start}",
                f"{sid_prefix}-{chunk_end}",
            )

    def _find_attribute_element(
        self, item: ElementTree.Element, attr: str
    ) -> ElementTree.Element | None:
        return item.find(f"./addata:{attr}", namespaces=NAMESPACES)

    def _reverse_attribute_values(self, attr_elem: ElementTree.Element) -> None:
        values = attr_elem.findall("./ad:value", namespaces=NAMESPACES)
        if len(values) < 2:
            return

        for value in values:
            attr_elem.remove(value)

        for value in reversed(values):
            attr_elem.append(value)

    def _extract_ranged_attributes_for_item(
        self, item: ElementTree.Element
    ) -> dict[str, tuple[int, int]]:
        ranged_attributes: dict[str, tuple[int, int]] = {}

        for part in list(item):
            if "RangeLow" not in part.attrib or "RangeHigh" not in part.attrib:
                continue

            attr_name = self._get_tag_name(part)
            try:
                range_low = int(part.attrib["RangeLow"])
                range_high = int(part.attrib["RangeHigh"])
            except (KeyError, ValueError):
                continue

            ranged_attributes[attr_name] = (range_low, range_high)

        return ranged_attributes

    def _merge_attribute_values(
        self,
        base_results: ElementTree.Element,
        ranged_results: ElementTree.Element,
        attr: str,
    ) -> int:
        merged_values = 0
        base_objects = {
            object_id: item
            for item in self._iter_response_objects(base_results)
            if (object_id := self._get_object_identity(item)) is not None
        }

        for ranged_item in self._iter_response_objects(ranged_results):
            object_id = self._get_object_identity(ranged_item)
            if object_id is None or object_id not in base_objects:
                continue

            ranged_attr = self._find_attribute_element(ranged_item, attr)
            if ranged_attr is None:
                continue

            base_item = base_objects[object_id]
            base_attr = self._find_attribute_element(base_item, attr)
            if base_attr is None:
                self._reverse_attribute_values(ranged_attr)
                base_item.append(ranged_attr)
                value_count = len(ranged_attr.findall("./ad:value", namespaces=NAMESPACES))
                ranged_attr.attrib["RangeLow"] = "0"
                ranged_attr.attrib["RangeHigh"] = str(value_count - 1) if value_count else "0"
                merged_values += len(ranged_attr.findall("./ad:value", namespaces=NAMESPACES))
                continue

            self._reverse_attribute_values(base_attr)
            self._reverse_attribute_values(ranged_attr)

            existing_low = int(base_attr.attrib.get("RangeLow", "0"))

            existing_high_value = base_attr.attrib.get(
                "RangeHigh",
                str(len(base_attr.findall("./ad:value", namespaces=NAMESPACES)) - 1),
            )
            if existing_high_value == "*":
                existing_high = len(base_attr.findall("./ad:value", namespaces=NAMESPACES)) - 1
            else:
                existing_high = int(existing_high_value)

            incoming_low = int(ranged_attr.attrib.get("RangeLow", str(existing_high + 1)))
            incoming_high_value = ranged_attr.attrib.get(
                "RangeHigh",
                str(
                    incoming_low
                    + len(ranged_attr.findall("./ad:value", namespaces=NAMESPACES))
                    - 1
                ),
            )
            if incoming_high_value == "*":
                incoming_high = incoming_low + len(
                    ranged_attr.findall("./ad:value", namespaces=NAMESPACES)
                ) - 1
            else:
                incoming_high = int(incoming_high_value)

            for value in ranged_attr.findall("./ad:value", namespaces=NAMESPACES):
                base_attr.append(value)
                merged_values += 1

            base_attr.attrib["RangeLow"] = str(min(existing_low, incoming_low))
            base_attr.attrib["RangeHigh"] = str(max(existing_high, incoming_high))

        return merged_values

    def _expand_ranged_attributes(
        self,
        remoteName: str,
        query: str,
        basedn: str | None,
        results: ElementTree.Element,
        page_writer: Callable[[list[ElementTree.Element]], None] | None = None,
    ) -> None:
        for item in self._iter_response_objects(results):
            object_dn = self._get_object_distinguished_name(item)
            if object_dn is None:
                continue

            ranged_attributes = self._extract_ranged_attributes_for_item(item)
            for attr, (range_low, range_high) in ranged_attributes.items():
                next_low = range_high + 1

                while True:
                    enum_ctx = self._query_enumeration(
                        remoteName=remoteName,
                        nmf=self._nmf,
                        query="(objectClass=*)",
                        basedn=object_dn,
                        attributes=[attr],
                        range_hints={attr: (next_low, "*")},
                    )
                    if enum_ctx is None:
                        break

                    ranged_page = ElementTree.Element("wsen:Items")
                    more_results = True
                    while more_results:
                        et, more_results = self._pull_results(
                            remoteName=remoteName, nmf=self._nmf, enum_ctx=enum_ctx
                        )
                        page_items = et.findall(".//wsen:Items", namespaces=NAMESPACES)
                        if page_writer is not None and page_items:
                            page_writer(page_items)
                        for page_item in page_items:
                            ranged_page.append(page_item)

                    merged_values = self._merge_attribute_values(results, ranged_page, attr)
                    if merged_values == 0:
                        break

                    print(
                        "[*] Collecting ADWS ranged data: received "
                        f"{merged_values} additional {attr} values for {object_dn}",
                        file=sys.stderr,
                        flush=True,
                    )

                    ranged_objects = self._iter_response_objects(ranged_page)
                    if not ranged_objects:
                        break

                    next_ranges = self._extract_ranged_attributes_for_item(ranged_objects[0])
                    next_range = next_ranges.get(attr)
                    if next_range is None:
                        break

                    _, returned_high = next_range
                    next_low = returned_high + 1

    def _query_enumeration(
        self,
        remoteName: str,
        nmf: ms_nmf.NMFConnection,
        query: str,
        basedn: str,
        attributes: list,
        range_hints: dict[str, tuple[int, int | str | None]] | None = None,
    ) -> str | None:
        """Send the query and set up an enumeration context for the results

        Args:
            remoteName (str): remote server fqdn, used for soap addressing
            nmf (ms_nmf.NMFConnection): the transport to use
            query (str): the ldap query to use
            basedn (str): The base objects distinguished name for the query
            attributes (list): ldap attributes to return

        Returns:
            str or None: the enumeration context, or None in error
        """
        fAttributes = self._format_selection_properties(attributes, range_hints)

        if basedn is None:
            basedn = ",".join([f"DC={i}" for i in self._domain.split(".")])

        query_description = query
        if len(query_description) > 1000:
            query_description = (
                query_description[:997]
                + f"... [{len(query):,} characters; remainder omitted]"
            )
        logging.info(f"Using query: {query_description}")
        logging.info(f"Using distingushedName: {basedn}")

        query_vars = {
            "uuid": str(uuid4()),
            "fqdn": remoteName,
            "query": query,
            "attributes": fAttributes,
            "baseobj": basedn,
        }

        enumeration = LDAP_QUERY_FSTRING.format(**query_vars)
        et = self._request_with_retries(
            remoteName=remoteName,
            nmf=nmf,
            request=enumeration,
            operation="Enumerate",
        )

        enum_ctx = et.find(".//wsen:EnumerationContext", NAMESPACES)

        return enum_ctx.text if enum_ctx is not None else None

    def _pull_results(
        self, remoteName: str, nmf: ms_nmf.NMFConnection, enum_ctx: str
    ) -> tuple[ElementTree.Element, bool]:
        """pull the results of an enumeration ctx from server.

        Returns the results, and if there are no more results,
        returns the last result and false.

        Args:
            remoteName (str): the fqdn of the server, for soap addressing
            nmf (ms_nmf.NMFConnection): the transport to use
            enum_ctx (str): the enumeration ctx to pull

        Returns:
            Tuple(Element, bool): the result, and more to pull
        """

        pull_vars = {
            "uuid": str(uuid4()),
            "fqdn": remoteName,
            "enum_ctx": enum_ctx,
        }

        pull = LDAP_PULL_FSTRING.format(**pull_vars)
        et = self._request_with_retries(
            remoteName=remoteName,
            nmf=nmf,
            request=pull,
            operation="Pull",
        )

        final_pkt = et.find(".//wsen:EndOfSequence", namespaces=NAMESPACES)
        if final_pkt is not None:
            return (et, False)

        return (et, True)

    def _renew_enumeration(
        self, remoteName: str, nmf: ms_nmf.NMFConnection, enum_ctx: str
    ) -> str:
        """Renew an active enumeration context without restarting its query."""
        logging.info("Renewing ADWS enumeration context")
        renew_vars = {
            "uuid": str(uuid4()),
            "fqdn": remoteName,
            "enum_ctx": enum_ctx,
            "expires": _ENUMERATION_CONTEXT_RENEW_DURATION,
        }

        et = self._request_with_retries(
            remoteName=remoteName,
            nmf=nmf,
            request=LDAP_RENEW_FSTRING.format(**renew_vars),
            operation="Renew",
        )

        # A RenewResponse may replace the context representation. If it does not,
        # the context supplied in the request remains current.
        renewed_ctx = et.find(
            ".//wsen:RenewResponse/wsen:EnumerationContext", NAMESPACES
        )
        if renewed_ctx is None or renewed_ctx.text is None:
            return enum_ctx

        return renewed_ctx.text

    def _request_with_retries(
        self,
        remoteName: str,
        nmf: ms_nmf.NMFConnection,
        request: str,
        operation: str,
    ) -> ElementTree.Element:
        """Send an ADWS request with bounded fault and transport retries."""
        reconnect_transport = False

        for retry in range(_ADWS_REQUEST_RETRIES + 1):
            try:
                if reconnect_transport:
                    current_socket = getattr(nmf, "_sock", None)
                    if current_socket is not None:
                        try:
                            current_socket.close()
                        except OSError:
                            pass

                    nmf = self._connect(remoteName, self._resource)
                    self._nmf = nmf
                    reconnect_transport = False

                nmf.send(request)
                response = nmf.recv()
                et = self._handle_str_to_xml(response)
                if not et:
                    raise ValueError("was unable to parse xml from the server response")
                return et
            except ADWSError as error:
                if not any(code in str(error) for code in _ADWS_TRANSIENT_FAULTS):
                    raise
                failure = error
            except OSError as error:
                reconnect_transport = True
                failure = error

            if retry == _ADWS_REQUEST_RETRIES:
                raise failure

            logging.warning(
                "ADWS %s failed (%s); retrying request %d/%d",
                operation,
                failure,
                retry + 1,
                _ADWS_REQUEST_RETRIES,
            )
            time.sleep(_ADWS_RETRY_BASE_DELAY_SECONDS * (retry + 1))

        raise RuntimeError("unreachable")

    @staticmethod
    def _is_valid_xml_char(char: str) -> bool:
        codepoint = ord(char)
        return (
            codepoint in (0x09, 0x0A, 0x0D)
            or 0x20 <= codepoint <= 0xD7FF
            or 0xE000 <= codepoint <= 0xFFFD
            or 0x10000 <= codepoint <= 0x10FFFF
        )

    @classmethod
    def _replace_invalid_xml_chars(cls, xmlstr: str) -> tuple[str, int, list[int]]:
        invalid_offsets: list[int] = []
        cleaned: list[str] = []
        invalid_count = 0

        for offset, char in enumerate(xmlstr):
            if cls._is_valid_xml_char(char):
                cleaned.append(char)
                continue

            invalid_count += 1
            if len(invalid_offsets) < 5:
                invalid_offsets.append(offset)
            cleaned.append("\ufffd")

        return ("".join(cleaned) if invalid_count else xmlstr, invalid_count, invalid_offsets)

    @staticmethod
    def _escape_bare_ampersands(xmlstr: str) -> tuple[str, int]:
        return _BARE_AMPERSAND_RE.subn("&amp;", xmlstr)

    @staticmethod
    def _is_xml_name_start_char(char: str) -> bool:
        return char.isalpha() or char in "_:"

    @staticmethod
    def _is_xml_name_char(char: str) -> bool:
        return char.isalnum() or char in "_:.-"

    @classmethod
    def _looks_like_xml_tag(cls, xmlstr: str, offset: int) -> bool:
        if xmlstr.startswith(("<!--", "<![CDATA[", "<?", "<!DOCTYPE"), offset):
            return True

        name_start = offset + 1
        is_end_tag = name_start < len(xmlstr) and xmlstr[name_start] == "/"
        if is_end_tag:
            name_start += 1

        if name_start >= len(xmlstr) or not cls._is_xml_name_start_char(xmlstr[name_start]):
            return False

        name_end = name_start + 1
        while name_end < len(xmlstr) and cls._is_xml_name_char(xmlstr[name_end]):
            name_end += 1

        if name_end >= len(xmlstr):
            return False

        next_char = xmlstr[name_end]
        if next_char == ">":
            return True
        if next_char == "/" and name_end + 1 < len(xmlstr) and xmlstr[name_end + 1] == ">":
            return True
        if not next_char.isspace():
            return False

        tag_end = xmlstr.find(">", name_end)
        next_tag = xmlstr.find("<", name_end)
        if tag_end == -1 or (next_tag != -1 and next_tag < tag_end):
            return False

        tag_remainder = xmlstr[name_end:tag_end].strip()
        if is_end_tag:
            return not tag_remainder
        if tag_remainder in ("", "/"):
            return True

        return "=" in tag_remainder

    @classmethod
    def _escape_obvious_stray_angle_brackets(cls, xmlstr: str) -> tuple[str, int]:
        escaped: list[str] = []
        escaped_count = 0

        for offset, char in enumerate(xmlstr):
            if char == "<" and not cls._looks_like_xml_tag(xmlstr, offset):
                escaped.append("&lt;")
                escaped_count += 1
                continue
            escaped.append(char)

        return ("".join(escaped) if escaped_count else xmlstr, escaped_count)

    @staticmethod
    def _trim_to_xml_document(xmlstr: str) -> tuple[str, int]:
        start = xmlstr.find("<")
        end = xmlstr.rfind(">")

        if start == -1 or end == -1 or end <= start:
            return xmlstr, 0

        trimmed = xmlstr[start : end + 1]
        removed = start + (len(xmlstr) - end - 1)
        return (trimmed, removed) if removed else (xmlstr, 0)

    def _parse_xml_response(self, xmlstr: str) -> ElementTree.Element:
        try:
            return ElementTree.fromstring(xmlstr)
        except ElementTree.ParseError as original_error:
            repaired = xmlstr
            repair_notes: list[str] = []

            repaired, invalid_count, invalid_offsets = self._replace_invalid_xml_chars(repaired)
            if invalid_count:
                repair_notes.append(
                    f"replaced {invalid_count} invalid XML character(s) at offsets {invalid_offsets}"
                )

            repaired, ampersand_count = self._escape_bare_ampersands(repaired)
            if ampersand_count:
                repair_notes.append(f"escaped {ampersand_count} bare ampersand(s)")

            repaired, angle_count = self._escape_obvious_stray_angle_brackets(repaired)
            if angle_count:
                repair_notes.append(f"escaped {angle_count} stray angle bracket(s)")

            repaired, trimmed_count = self._trim_to_xml_document(repaired)
            if trimmed_count:
                repair_notes.append(f"trimmed {trimmed_count} non-XML character(s)")

            if repaired != xmlstr:
                try:
                    parsed = ElementTree.fromstring(repaired)
                except ElementTree.ParseError:
                    logging.debug(
                        "Unable to recover malformed ADWS XML response after repairs; original error: %s",
                        original_error,
                    )
                else:
                    logging.warning(
                        "Recovered malformed ADWS XML response: %s; original parser error: %s",
                        "; ".join(repair_notes),
                        original_error,
                    )
                    return parsed

            raise original_error

    def _handle_str_to_xml(self, xmlstr: str) -> ElementTree.Element | None:
        """Takes an xml string and returns an Element of the root
         node of an xml object.
        Also deals with error and faults in the response

        Args:
            xmlstr (str): str form of xml data

        Returns:
            Element: xml object

        Raises:
            ADWSError: Raises if there is a fault in the
            soap message return by the server
        """

        def manually_cut_out_fault(xml_str: str) -> str:
            """cut out the fault text description using
            slices.  This is dirty and not certain but
            if it cant be parsed with xml parsers, its
            all we have.

            Args:
                xml_str (str): str of xml data

            Returns:
                str: the fault msg
            """
            starttag = xml_str.find(":Text") + len(":Text")
            endtag = xml_str[starttag:].find(":Text")
            return xml_str[starttag : starttag + endtag]

        try:
            et = self._parse_xml_response(xmlstr)
        except ElementTree.ParseError:
            if ":Fault>" in xmlstr or ":Reason>" in xmlstr:
                msg = manually_cut_out_fault(xmlstr)
                raise ADWSError(msg)
            raise

        base_msg = str()

        fault = et.find(".//soapenv:Fault", namespaces=NAMESPACES)
        if fault is None:  # maybe there isnt actually anything erroring?
            return et

        reason = fault.find(".//soapenv:Text", namespaces=NAMESPACES)
        base_msg += reason.text if reason is not None else ""  # type: ignore

        detail = fault.find(".//soapenv:Detail", namespaces=NAMESPACES)
        if detail is not None:
            ElementTree.indent(detail)
            detail_xmlstr = (
                ElementTree.tostring(detail, encoding="unicode")
                if detail is not None
                else ""
            )
        else:
            detail_xmlstr = ""

        # Detect LDAP referrals (Win32ErrorCode 8235). The DC does not host
        # the requested partition. Raise a specialized exception so callers
        # can catch and retry against the referred DC.
        referral_match = re.search(
            r"<[^>]*:?Referral>\s*ldap://([^/]+)/([^<]+)\s*</[^>]*:?Referral>",
            detail_xmlstr,
        )
        win32_match = re.search(r"<[^>]*:?Win32ErrorCode>\s*(\d+)\s*<", detail_xmlstr)
        if referral_match and win32_match and win32_match.group(1) == "8235":
            raise ADWSReferralError(
                target_dc=referral_match.group(1).strip(),
                target_dn=referral_match.group(2).strip(),
                original_msg=base_msg + detail_xmlstr,
            )

        raise ADWSError(base_msg + detail_xmlstr)

    def _get_tag_name(self, elem: ElementTree.Element) -> str:
        return elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

    def _format_flags(self, value: int, intflag_class: Type[IntFlag]) -> str:
        """
        Formats an integer value into a string of flags based on an IntFlag class.

        Args:
            value (int): The integer value to format.
            intflag_class (Type[IntFlag]): The IntFlag class to use for flag names.

        Returns:
            str: The formatted string representing the flags.
        """
        flags = [
            flag.name if flag & int(value) else f"{flag.value:#010x}"
            for flag in intflag_class
            if flag & int(value)
        ]
        flags = [flag for flag in flags if flag]

        flag_results = f" flags: {', '.join(flags)}" if flags else ""
        return f"{value}{flag_results}"

    def _pretty_print_response(
        self,
        et: ElementTree.Element,
        print_synthetic_vars: bool = False,
        parse_values: bool = False,
        show_no_objects_message: bool = True,
        print_trailing_separator: bool = True,
        flush_each_object: bool = False,
    ) -> int:
        """Pretty print the xml ldap objects in the response.

        Handle translating types from LDAPSyntax to human readable

        Args:
            et (ElementTree.Element): response xml element tree
            print_synthetic_vars (bool): print synthetic vars, see ([MS-ADDM]: 2.3.3)
            parse_values (bool): Parse attributes to readable format
            show_no_objects_message (bool): Print the no-results message when no objects are present.
            print_trailing_separator (bool): Print the final separator after all objects.
            flush_each_object (bool): Flush stdout after each object.

        Returns:
            int: Number of objects printed.
        """

        obj = self._iter_response_objects(et)
        if not obj:
            if not show_no_objects_message:
                return 0
            print("[-] No objects found")
            if print_trailing_separator:
                print("--------------------")
            return 0

        for item in obj:
            synthetic_attributes = []
            

            object_values: dict[str, str] = {}
            for part in item.findall(".//ad:value/..", namespaces=NAMESPACES):
                if "LdapSyntax" not in part.attrib:
                    if print_synthetic_vars:
                        synthetic_attributes.append(part)
                    continue

                name = self._get_tag_name(part)
                syntax = part.attrib["LdapSyntax"]
                values = [
                    value.text
                    for value in part.findall(".//ad:value", namespaces=NAMESPACES)
                    if value is not None and value.text
                ]

                parsed: list[str] = []
                if syntax == "SidString":
                    for value in values:
                        sid = LDAP_SID(data=b64decode(value)).formatCanonical()
                        if sid in WELL_KNOWN_SIDS:
                            sid += f" Well known sid: {WELL_KNOWN_SIDS[sid]}"
                        parsed.append(sid)
                if name in ["objectGUID"]:
                    parsed = [str(UUID(bytes_le=b64decode(value))).upper() for value in values]
                
                if parse_values:
                    if syntax == "GeneralizedTimeString":
                        parsed = [
                            GeneralizedTime(value).asDateTime.astimezone().isoformat()
                            for value in values
                        ]
                    
                    elif name in [
                        "accountExpires",
                        "lastLogoff",
                        "badPasswordTime",
                        "lastLogon",
                        "pwdLastSet",
                        "lastLogonTimestamp",
                    ]:
                        for v in values:
                            if int(v) == 0x0 or int(v) == 0x7FFFFFFFFFFFFFFF:
                                parsed.append("none/never")
                            else:
                                us = int(v) / 10
                                parsed.append(
                                    (
                                        datetime.datetime(
                                            1601, 1, 1, tzinfo=datetime.timezone.utc
                                        )
                                        + datetime.timedelta(microseconds=us)
                                    ).isoformat()
                                )
                    
                    elif name == "userAccountControl":
                        parsed = [
                            self._format_flags(int(value), AccountPropertyFlag)
                            for value in values
                        ]
                    
                    if name == "sAMAccountType":
                        parsed = [
                            self._format_flags(int(value), SamAccountType)
                            for value in values
                        ]
                    elif name == "primaryGroupID":
                        parsed = []
                        for value in values:
                            group = value
                            if value in BUILT_IN_GROUPS:
                                group += f" Well known group: {BUILT_IN_GROUPS[value]}"
                            parsed.append(group)
                    elif name == "groupType":
                        parsed = [
                            self._format_flags(int(value), GroupTypeFlags)
                            for value in values
                        ]
                    
                    elif name == "instanceType":
                        parsed = [
                            self._format_flags(int(value), InstanceTypeFlags)
                            for value in values
                        ]
                    elif name == "systemFlags":
                        parsed = [
                            self._format_flags(int(value), SystemFlags) for value in values
                        ]
                    
                    elif name == "msDS-AllowedToActOnBehalfOfOtherIdentity":
                        parsed = []
                        for value in values:
                            sd = SR_SECURITY_DESCRIPTOR(data=b64decode(value))
                            aces = [
                                ace["Ace"]["Sid"].formatCanonical()
                                for ace in sd["Dacl"].aces
                                if ace["AceType"]
                                in (
                                    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE.ACE_TYPE,
                                    ACCESS_ALLOWED_ACE.ACE_TYPE,
                                    ACCESS_ALLOWED_CALLBACK_ACE.ACE_TYPE,
                                    ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
                                    SYSTEM_MANDATORY_LABEL_ACE.ACE_TYPE,
                                )
                            ]
                            parsed.append(f"{value} DACL ACE SIDs: {' '.join(aces)}")
                
                if parse_values and name == "nTSecurityDescriptor":
                    continue
                else:
                    object_values[name] = ", ".join(parsed if parsed else values)

            format_str = f"{{}}: {{}}"
            print("--------------------")

            for k, v in object_values.items():
                print(format_str.format(k, v))

            if flush_each_object:
                sys.stdout.flush()

            """
            if print_synthetic_vars:
                for part in synthetic_attributes:
                    name = self._get_tag_name(part)
                    values = [
                        value.text
                        for value in part.findall(".//ad:value", namespaces=NAMESPACES)
                        if value is not None and value.text
                    ]
                    print(f"{name}: {' '.join(values)}")
            """
        if print_trailing_separator:
            print("--------------------")

        return len(obj)

    @classmethod
    def print_soapy_data(
        cls, data_path: str = ".soapy_data", parse_values: bool = False
    ) -> tuple[int, int, int]:
        """Render recovered spool pages in SOAPy's BOFHound-compatible format."""
        client = object.__new__(cls)
        recovered: dict[str, ElementTree.Element] = {}
        unidentified: list[ElementTree.Element] = []
        page_count = 0
        invalid_record_count = 0

        with open(data_path, encoding="utf-8") as data_file:
            for line in data_file:
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    invalid_record_count += 1
                    continue

                if not isinstance(record, dict):
                    invalid_record_count += 1
                    continue

                if record.get("type") != "page":
                    continue

                if not isinstance(record.get("xml"), list):
                    invalid_record_count += 1
                    continue

                for page_xml in record["xml"]:
                    try:
                        page = ElementTree.fromstring(page_xml)
                    except (ElementTree.ParseError, TypeError):
                        invalid_record_count += 1
                        continue

                    page_count += 1
                    for item in client._iter_response_objects(page):
                        identity = client._get_object_identity(item)
                        if identity is None:
                            unidentified.append(item)
                            continue

                        existing = recovered.get(identity)
                        if existing is None:
                            recovered[identity] = item
                            continue

                        existing_parts = {part.tag: part for part in list(existing)}
                        for incoming_part in list(item):
                            existing_part = existing_parts.get(incoming_part.tag)
                            if existing_part is None:
                                existing.append(incoming_part)
                                existing_parts[incoming_part.tag] = incoming_part
                                continue

                            # Ordinary attributes in a later page/query are a new
                            # snapshot, not extra values. Appending those snapshots
                            # produced invalid fields such as "lastLogon: 1, 2".
                            # RangeLow=0 also starts a newer ranged snapshot. Only
                            # non-zero ranged segments extend an existing attribute.
                            incoming_range_low = incoming_part.attrib.get("RangeLow")
                            if incoming_range_low is None or incoming_range_low == "0":
                                existing.remove(existing_part)
                                existing.append(incoming_part)
                                existing_parts[incoming_part.tag] = incoming_part
                                continue

                            existing_values = {
                                (value.text, tuple(sorted(value.attrib.items())))
                                for value in existing_part.findall(
                                    "./ad:value", namespaces=NAMESPACES
                                )
                            }
                            for value in incoming_part.findall(
                                "./ad:value", namespaces=NAMESPACES
                            ):
                                value_key = (value.text, tuple(sorted(value.attrib.items())))
                                if value_key not in existing_values:
                                    existing_part.append(value)
                                    existing_values.add(value_key)

                            existing_part.attrib.update(incoming_part.attrib)

        results = ElementTree.Element("wsen:Items")
        for item in [*recovered.values(), *unidentified]:
            results.append(item)

        printed = client._pretty_print_response(
            results,
            parse_values=parse_values,
            flush_each_object=True,
        )
        return printed, page_count, invalid_record_count

    def put(
        self,
        object_ref: str,
        operation: str,
        attribute: str,
        data_type: str,
        value: str,
    ) -> bool:
        """CRUD on attribute

        Args:
            client (NMFConnection): connected client
            object_ref (str): DN of object to write attribute on
            fqdn (str): fqdn of the DC
            operation (str): operation to preform on the attribute: <'add', 'delete', 'replace'> [MS-WSTIM]: 3.2.4.2.3.1
            attribute (str): attribute type including the namespace
            data_type (str): datatype, <'string', 'base64Base'> [MS-ADDM]: 2.3.4
            value (str): string value for attribute in UTF-8

        Returns:
            bool: error
        """
        if self._resource != "Resource":
            raise NotImplementedError("Put is only supported on 'put' clients")

        put_vars = {
            "object_ref": object_ref,
            "uuid": str(uuid4()),
            "fqdn": self._fqdn,
            "operation": operation,
            "attribute": attribute,
            "data_type": data_type,
            "value": value,
        }

        put_msg = LDAP_PUT_FSTRING.format(**put_vars)

        # Retry loop for LDAP referrals. The DC may not host the requested
        # partition and refer us to one that does. _swap_endpoint reconnects
        # this client to the referred DC and updates self._fqdn so we can
        # rebuild the payload with the new fqdn before retrying.
        _hops = 0
        while True:
            self._nmf.send(put_msg)
            resp_str = self._nmf.recv()
            try:
                et = self._handle_str_to_xml(resp_str)
                break
            except ADWSReferralError as _referral:
                self._swap_endpoint(_referral.target_dc, hops=_hops)
                _hops += 1
                put_vars["fqdn"] = self._fqdn
                put_msg = LDAP_PUT_FSTRING.format(**put_vars)
        if not et:
            raise ValueError("was unable to parse xml from the server response")

        body = et.find(".//soapenv:Body", namespaces=NAMESPACES)

        return (
            body is None
            or len(body) == 0
            and (body.text is None or body.text.strip() == "")
        )

    def pull(
        self,
        query: str,
        basedn: str,
        attributes: list,
        print_incrementally: bool = False,
        parse_values: bool = False,
        data_path: str | None = None,
        print_results: bool = True,
        start_sid: str | None = None,
        end_sid: str | None = None,
    ) -> ElementTree.Element:
        """Makes an LDAP query using ADWS to the specified server

        Args:
            fqdn (str): the fqdn of the domain controller
            query (str): the ldap query as a string
            baseobj (str): The base objects distinguished name for the query
            print_incrementally (bool): print the results as they come in
            parse_values (bool): When printing results parse to human readable values
            data_path (str): Append successfully collected pages to this recovery file.
            print_results (bool): Print LDAP objects after collection.
            start_sid (str): Inclusive lower objectSid bound.
            end_sid (str): Inclusive upper objectSid bound.

        Returns:
            ElementTree.Element: The soap response as xml
        """
        if self._resource != "Enumeration":
            raise NotImplementedError("Pull is only supported on 'pull' clients")

        query_id = str(uuid4())
        data_file = open(data_path, "a", encoding="utf-8") if data_path is not None else None

        def write_data(record: dict) -> None:
            if data_file is None:
                return
            json.dump(record, data_file, ensure_ascii=False, separators=(",", ":"))
            data_file.write("\n")
            data_file.flush()

        def write_pages(page_items: list[ElementTree.Element]) -> None:
            write_data(
                {
                    "type": "page",
                    "id": query_id,
                    "xml": [
                        ElementTree.tostring(item, encoding="unicode")
                        for item in page_items
                    ],
                }
            )

        write_data(
            {
                "type": "query",
                "id": query_id,
                "query": query,
                "base_dn": basedn,
                "attributes": attributes,
                "start_sid": start_sid,
                "end_sid": end_sid,
            }
        )

        try:
            enum_ctx = self._query_enumeration(
                remoteName=self._fqdn,
                nmf=self._nmf,
                query=query,
                basedn=basedn,
                attributes=attributes,
            )
            if enum_ctx is None:
                logging.error(
                    "Server did not return an enumeration context in response to making a query"
                )
                raise ValueError("unable to get enumeration context")

            ElementTree.register_namespace("wsen", NAMESPACES["wsen"])
            results: ElementTree.Element = ElementTree.Element("wsen:Items")
            last_context_renewal = time.monotonic()
            collected_objects = 0
            collected_pages = 0
            received_objects = 0
            seen_object_ids: set[str] = set()
            last_collected_sid: str | None = None
            if print_results:
                collection_message = (
                    "[*] Collecting ADWS data; results will print when collection "
                    "completes"
                )
            else:
                collection_message = (
                    f"[*] Collecting ADWS data into {data_path}; use --show "
                    "to print BOFHound-compatible output"
                )
            print(collection_message, file=sys.stderr, flush=True)
            more_results = True
            while more_results:
                try:
                    if (
                        time.monotonic() - last_context_renewal
                        >= _ENUMERATION_CONTEXT_RENEW_INTERVAL_SECONDS
                    ):
                        enum_ctx = self._renew_enumeration(
                            remoteName=self._fqdn, nmf=self._nmf, enum_ctx=enum_ctx
                        )
                        last_context_renewal = time.monotonic()

                    et, more_results = self._pull_results(
                        remoteName=self._fqdn, nmf=self._nmf, enum_ctx=enum_ctx
                    )
                except ADWSError as error:
                    if not any(
                        code in str(error) for code in _ADWS_INVALID_ENUMERATION_FAULTS
                    ):
                        raise

                    next_start_sid = None
                    if last_collected_sid is not None:
                        sid_parts = self._sid_parts(last_collected_sid)
                        next_start_sid = "S-" + "-".join(
                            str(value) for value in (*sid_parts[:-1], sid_parts[-1] + 1)
                        )
                    print(
                        "[!] ADWS enumeration limit reached; the query will not be "
                        "restarted because that would replay the same objects",
                        file=sys.stderr,
                        flush=True,
                    )
                    resume_start_sid = start_sid or next_start_sid
                    if start_sid is not None and end_sid is not None:
                        print(
                            "[!] Incomplete bounded SID query; retry only "
                            f"--start-sid {start_sid} --end-sid {end_sid}",
                            file=sys.stderr,
                            flush=True,
                        )
                    elif last_collected_sid is not None:
                        print(
                            f"[!] Last observed SID: {last_collected_sid}; next "
                            f"suggested --start-sid: {next_start_sid}",
                            file=sys.stderr,
                            flush=True,
                        )
                    write_data(
                        {
                            "type": "checkpoint",
                            "id": query_id,
                            "last_sid": last_collected_sid,
                            "next_start_sid": next_start_sid,
                            "resume_start_sid": resume_start_sid,
                            "end_sid": end_sid,
                            "message": str(error),
                        }
                    )
                    raise

                # A PullResponse can replace an enumeration context. Reusing the old
                # one after that point results in InvalidEnumerationContext.
                updated_ctx = et.find(
                    ".//wsen:PullResponse/wsen:EnumerationContext", NAMESPACES
                )
                if updated_ctx is not None and updated_ctx.text is not None:
                    enum_ctx = updated_ctx.text

                page_items = et.findall(".//wsen:Items", namespaces=NAMESPACES)
                if page_items:
                    page_objects = sum(
                        len(self._iter_response_objects(page)) for page in page_items
                    )
                    collected_pages += len(page_items)
                    received_objects += page_objects
                    write_pages(page_items)

                    new_objects = 0
                    for page in page_items:
                        unique_page = ElementTree.Element(page.tag, page.attrib)
                        for item in self._iter_response_objects(page):
                            identity = self._get_object_identity(item)
                            if identity is not None:
                                if identity in seen_object_ids:
                                    continue
                                seen_object_ids.add(identity)
                            object_sid = self._get_object_sid(item)
                            if object_sid is not None:
                                last_collected_sid = object_sid
                            unique_page.append(item)
                            new_objects += 1
                        if len(unique_page):
                            results.append(unique_page)
                    collected_objects += new_objects

                    print(
                        "[*] Collecting ADWS data: "
                        f"{collected_objects} unique objects saved "
                        f"(+{new_objects} new this page; {received_objects} "
                        f"received across {collected_pages} pages)",
                        file=sys.stderr,
                        flush=True,
                    )

            write_data({"type": "base_complete", "id": query_id})

            print(
                "[*] Base ADWS collection complete: "
                f"{collected_objects} objects; collecting ranged attribute values",
                file=sys.stderr,
                flush=True,
            )

            # Drain the primary enumeration before performing ranged attribute
            # retrieval or formatting. Those operations can take long enough over a
            # proxied connection for ADWS to invalidate the LDAP connection it has
            # reserved for the primary enumeration.
            self._expand_ranged_attributes(
                remoteName=self._fqdn,
                query=query,
                basedn=basedn,
                results=results,
                page_writer=write_pages,
            )
            if print_results:
                print(
                    f"[*] ADWS data collection complete; printing {collected_objects} "
                    "objects",
                    file=sys.stderr,
                    flush=True,
                )
                if print_incrementally:
                    self._pretty_print_response(
                        results,
                        parse_values=parse_values,
                        flush_each_object=True,
                    )
                else:
                    self._pretty_print_response(results, parse_values=parse_values)

            write_data({"type": "complete", "id": query_id})
            if not print_results:
                print(
                    f"[+] ADWS data collection complete: {collected_objects} "
                    f"objects saved to {data_path}; run SOAPy --show",
                    file=sys.stderr,
                    flush=True,
                )
            return results
        except Exception as error:
            write_data({"type": "error", "id": query_id, "message": str(error)})
            raise
        finally:
            if data_file is not None:
                data_file.close()

    @classmethod
    def pull_client(cls, ip: str, domain: str, username: str, auth: ADWSAuthType) -> Self:
        return cls(ip, domain, username, auth, "Enumeration")

    @classmethod
    def put_client(cls, ip: str, domain: str, username: str, auth: ADWSAuthType) -> Self:
        return cls(ip, domain, username, auth, "Resource")

    @classmethod
    def create_client(
        cls, ip: str, domain: str, username: str, auth: ADWSAuthType
    ) -> Self:
        # return cls(ip, domain, username, auth, "ResourceFactory")
        raise NotImplementedError()

    @classmethod
    def accounts_cap_client(
        cls, ip: str, domain: str, username: str, auth: ADWSAuthType
    ) -> Self:
        # return cls(ip, domain, username, auth, "AccountManagement")
        raise NotImplementedError()

    @classmethod
    def topology_cap_client(
        cls, ip: str, domain: str, username: str, auth: ADWSAuthType
    ) -> Self:
        # return cls(ip, domain, username, auth, "TopologyManagement")
        raise NotImplementedError()
