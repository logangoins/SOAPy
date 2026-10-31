#!/usr/bin/env python3

from base64 import b64encode, b64decode
from uuid import uuid4
import datetime
import socket
from struct import unpack
from typing import Tuple, List, Dict, Optional

import dns.resolver
from impacket.structure import Structure

import logging
from src.adws import ADWSAuthType, ADWSConnect, ADWSReferralError
# SOAP/XML templates and namespaces moved to src.soap_templates to keep this file lean.
from src.soap_templates import (
    NAMESPACES,
    LDAP_PUT_FSTRING,
    LDAP_DELETE_FOR_RESOURCE,
    LDAP_CREATE_FOR_RESOURCEFACTORY,
    LDAP_ROOT_DSE_FSTRING,
)

# -----------------------
# DNS binary structure classes (MS-DNSP)
# -----------------------

class DNS_RECORD(Structure):
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

class DNS_RPC_NAME(Structure):
    structure = (
        ('cchNameLength', 'B-dnsName'),
        ('dnsName', ':')
    )

class DNS_COUNT_NAME(Structure):
    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':')
    )

    def toFqdn(self) -> str:
        ind = 0
        labels = []
        for i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
            labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
            ind += nextlen + 1
        labels.append('')
        return '.'.join(labels)

class DNS_RPC_NODE(Structure):
    structure = (
        ('wLength', '>H'),
        ('wRecordCount', '>H'),
        ('dwFlags', '>L'),
        ('dwChildCount', '>L'),
        ('dnsNodeName', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self) -> str:
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical: str):
        self['address'] = socket.inet_aton(canonical)

class DNS_RPC_RECORD_NODE_NAME(Structure):
    structure = (
        ('nameNode', ':', DNS_COUNT_NAME),
    )

class DNS_RPC_RECORD_SOA(Structure):
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_NULL(Structure):
    structure = (
        ('bData', ':'),
    )

class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    structure = (
        ('wPreference', '>H'),
        ('nameExchange', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_AAAA(Structure):
    structure = (
        ('ipv6Address', '16s'),
    )

class DNS_RPC_RECORD_SRV(Structure):
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_TS(Structure):
    structure = (
        ('entombedTime', '<Q'),
    )

    def toDatetime(self) -> datetime.datetime:
        microseconds = self['entombedTime'] / 10.0
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=microseconds)

# -----------------------
# Utility helpers
# -----------------------

RECORD_TYPE_MAPPING = {
    0: 'ZERO',
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    33: 'SRV',
    65281: 'WINS'
}

def get_next_serial(dnsserver: Optional[str], dc: str, zone: str, tcp: bool) -> int:
    resolver = dns.resolver.Resolver()
    server = dnsserver if dnsserver else dc
    try:
        socket.inet_aton(server)
        resolver.nameservers = [server]
    except Exception:
        pass
    try:
        res = resolver.resolve(zone, 'SOA', tcp=tcp)
    except Exception:
        return 1
    for answer in res:
        try:
            return answer.serial + 1
        except Exception:
            try:
                return int(answer.to_text().split()[-1]) + 1
            except Exception:
                return 1
    return 1

def new_record(rtype: int, serial: int) -> DNS_RECORD:
    nr = DNS_RECORD()
    nr['Type'] = rtype
    nr['Serial'] = serial
    nr['TtlSeconds'] = 180
    nr['Rank'] = 240
    return nr

def _xml_text_or_inner_value(elem, namespaces):
    if elem is None:
        return None
    child = elem.find('.//ad:value', namespaces=namespaces)
    if child is not None and child.text and child.text.strip():
        return child.text.strip()
    if elem.text and elem.text.strip():
        return elem.text.strip()
    return None

def get_rootdse_contexts(adws_client: ADWSConnect) -> Dict[str, object]:
    """
    Query RootDSE via ADWS to obtain naming contexts and schema DN etc.
    Uses LDAP_ROOT_DSE_FSTRING imported from src.soap_templates.
    """
    msgid = f"urn:uuid:{uuid4()}"
    payload = LDAP_ROOT_DSE_FSTRING.format(uuid=msgid, fqdn=adws_client._fqdn)
    adws_client._nmf.send(payload)
    raw = adws_client._nmf.recv()
    try:
        et = adws_client._handle_str_to_xml(raw)
        if et is None:
            raise RuntimeError("client._handle_str_to_xml returned None")
    except Exception:
        from xml.etree import ElementTree as ET
        s = raw if isinstance(raw, str) else raw.decode(errors="ignore")
        start = s.find('<')
        if start != -1:
            s = s[start:]
        try:
            et = ET.fromstring(s)
        except Exception as e:
            raise RuntimeError(f"Failed parsing RootDSE XML: {e}\nRaw (truncated): {s[:1000]}")
    ns = NAMESPACES if isinstance(NAMESPACES, dict) else {
        'ad': "http://schemas.microsoft.com/2008/1/ActiveDirectory",
        'addata': "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
    }
    def _find_once(attr):
        candidates = [
            f".//addata:{attr}/ad:value",
            f".//ad:{attr}/ad:value",
            f".//addata:{attr}",
            f".//ad:{attr}",
            f".//{attr}/ad:value",
            f".//{attr}",
        ]
        for xp in candidates:
            for elem in et.findall(xp, namespaces=ns):
                v = _xml_text_or_inner_value(elem, namespaces=ns)
                if v:
                    return v
        return None
    def _find_all(attr):
        vals = []
        candidates = [
            f".//addata:{attr}/ad:value",
            f".//ad:{attr}/ad:value",
            f".//addata:{attr}",
            f".//ad:{attr}",
            f".//{attr}/ad:value",
            f".//{attr}",
        ]
        for xp in candidates:
            for elem in et.findall(xp, namespaces=ns):
                v = _xml_text_or_inner_value(elem, namespaces=ns)
                if v and v not in vals:
                    vals.append(v)
        return vals
    contexts = {
        "schemaNamingContext": _find_once("schemaNamingContext"),
        "rootDomainNamingContext": _find_once("rootDomainNamingContext"),
        "configurationNamingContext": _find_once("configurationNamingContext"),
        "defaultNamingContext": _find_once("defaultNamingContext"),
        "namingContexts": _find_all("namingContexts") or _find_all("namingContext") or [],
        "domainFunctionality": _find_all("domainFunctionality"),
        "forestFunctionality": _find_all("forestFunctionality"),
    }
    if not contexts["defaultNamingContext"] and contexts["namingContexts"]:
        contexts["defaultNamingContext"] = contexts["namingContexts"][0]
    if not contexts["schemaNamingContext"] and contexts["defaultNamingContext"]:
        contexts["schemaNamingContext"] = "CN=Schema," + contexts["defaultNamingContext"]
    return contexts

# -----------------------
# dnsNode discovery and builders
# -----------------------





def _pull_with_referral_follow(pull_client, query, basedn, attributes):
    """Run pull_client.pull with automatic LDAP referral following.

    When the DC returns Win32ErrorCode 8235 (ERROR_DS_REFERRAL), the pull raises
    ADWSReferralError. We swap the client to the referred DC via _swap_endpoint
    and restart the pull. The enumeration context created on the original DC is
    no longer valid on the referred DC, so we must restart from scratch (not
    just retry the same Pull request).

    Bounded by ADWSConnect.MAX_REFERRAL_HOPS to prevent infinite loops on
    misconfigured multi-DC deployments.
    """
    _hops = 0
    while True:
        try:
            return pull_client.pull(
                query=query, basedn=basedn, attributes=attributes,
            )
        except ADWSReferralError as e:
            pull_client._swap_endpoint(e.target_dc, hops=_hops)
            _hops += 1


def find_dns_node(
    target: str,
    zone: str,
    ip: str,
    domain: str,
    username: str,
    auth: ADWSAuthType,
    forest: bool = False,
    legacy: bool = False,
    pull_client: Optional[ADWSConnect] = None,
    res_client: Optional[ADWSConnect] = None,
) -> Tuple[Optional[str], List[bytes], bool]:
    """
    Locate the dnsNode for the given target and zone.

    Optional: accept a pull_client and res_client to reuse existing ADWS connections
    (reduces repeated "Connecting to ..." logs).

    Returns:
      (node_dn or None, list_of_raw_dnsRecord_bytes, tombstoned_flag)
    """
    # Reuse provided res_client / pull_client if available (avoid creating new connections)
    if res_client is None:
        res_client = ADWSConnect(ip, domain, username, auth, "Resource")
    contexts = get_rootdse_contexts(res_client)
    domainroot = contexts.get("defaultNamingContext") or contexts.get("rootDomainNamingContext")
    if not domainroot:
        domainroot = ",".join([f"DC={p}" for p in domain.split(".") if p])

    if forest:
        dnsroot = f"CN=MicrosoftDNS,DC=ForestDnsZones,{domainroot}"
    else:
        if legacy:
            dnsroot = f"CN=MicrosoftDNS,CN=System,{domainroot}"
        else:
            dnsroot = f"CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}"

    searchtarget = f"DC={zone},{dnsroot}"
    query = f"(&(objectClass=dnsNode)(name={target}))"

    if pull_client is None:
        pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    try:
        et = _pull_with_referral_follow(
            pull_client, query, searchtarget,
            ["dnsRecord", "dNSTombstoned", "distinguishedName", "name"],
        )
    except Exception:
        # fallback to a broader search under dnsroot if the constructed base didn't match
        et = _pull_with_referral_follow(
            pull_client, query, dnsroot,
            ["dnsRecord", "dNSTombstoned", "distinguishedName", "name"],
        )

    node_dn: Optional[str] = None
    raw_records: List[bytes] = []
    tombstoned = False

    nodes = et.findall(".//addata:dnsNode", namespaces=NAMESPACES) + et.findall(".//addata:entry", namespaces=NAMESPACES)
    for node in nodes:
        dn_elem = node.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
        if dn_elem is not None and dn_elem.text:
            node_dn = dn_elem.text
        ts_elem = node.find(".//addata:dNSTombstoned/ad:value", namespaces=NAMESPACES)
        if ts_elem is not None and ts_elem.text:
            tombstoned = ts_elem.text.lower() == "true"
        for rec in node.findall(".//addata:dnsRecord/ad:value", namespaces=NAMESPACES):
            if rec is None or rec.text is None:
                continue
            try:
                raw = b64decode(rec.text)
            except Exception:
                raw = rec.text.encode("latin-1")
            raw_records.append(raw)

    if node_dn is None:
        for item in et.findall(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES):
            if item is not None and item.text:
                node_dn = item.text
                break

    return node_dn, raw_records, tombstoned

# -----------------------
# Build bytes helpers
# -----------------------

def build_a_record_bytes(ip_str: str, serial: int, ttl: int = 180) -> bytes:
    rec = new_record(1, serial)
    rec['TtlSeconds'] = ttl
    a = DNS_RPC_RECORD_A()
    a.fromCanonical(ip_str)
    rec['Data'] = a
    return rec.getData()

def build_ts_record_bytes(entombed_time_filetime: int) -> bytes:
    rec = new_record(0, 0)
    ts = DNS_RPC_RECORD_TS()
    ts['entombedTime'] = entombed_time_filetime
    rec['Data'] = ts
    return rec.getData()

def _split_target_and_zone(fqdn_record: str, domain: str) -> Tuple[str, str]:
    parts = fqdn_record.split(".")
    if len(parts) >= 2:
        target = parts[0]
        zone = ".".join(parts[1:])
    elif len(parts) == 1 and parts[0] != "":
        target = parts[0]
        zone = domain
    else:
        raise ValueError("fqdn_record must be at least 'name.zone' or a single host name (zone fallback to domain).")
    return target, zone

def _b64(data: bytes) -> str:
    return b64encode(data).decode("utf-8")

def _make_msgid() -> str:
    return f"urn:uuid:{uuid4()}"

# -----------------------
# Strict Replace setter for dNSTombstoned (single attempt only)
# -----------------------

def _set_dnstombstoned_replace_boolean(resource_client: ADWSConnect, object_ref: str, value: bool) -> bool:
    """
    Send a single strict ModifyRequest Replace following Microsoft's ADWS example:
      - SOAP Action: http://schemas.xmlsoap.org/ws/2004/09/transfer/Put
      - Include IdentityManagementOperation element in header (mustUnderstand=1)
      - Use ad:objectReferenceProperty (can be DN or GUID) and ad:instance
      - Body: ModifyRequest (DirectoryAccess namespace) with a single Change Operation="replace"
        and <AttributeType>addata:dNSTombstoned</AttributeType> plus
        <ad:value xsi:type="xsd:boolean">true|false</ad:value>

    Returns True on success (no SOAP Fault), False otherwise. Prints the raw response (truncated)
    and any parsed Fault for debugging.
    """
    val = "TRUE" if value else "FALSE"
    msgid = _make_msgid()

    # Use LDAP_PUT_FSTRING imported from src.soap_templates
    payload = LDAP_PUT_FSTRING.format(
        uuid=msgid,
        fqdn=resource_client._fqdn,
        object_ref=object_ref,
        operation="replace",
        attribute="addata:dNSTombstoned",
        data_type="boolean",
        value=val,
    )

    # send and receive raw response, with retry on LDAP referral.
    # If the target DC does not host the partition, _swap_endpoint reconnects
    # resource_client to the referred DC and we rebuild the payload with its fqdn.
    et = None
    raw = ""
    _hops = 0
    while True:
        try:
            resource_client._nmf.send(payload)
            raw = resource_client._nmf.recv()
        except Exception as e:
            print(f"[ERROR] transport error sending Replace dNSTombstoned: {e}")
            return False
        try:
            et = resource_client._handle_str_to_xml(raw)
            break
        except ADWSReferralError as _referral:
            try:
                resource_client._swap_endpoint(_referral.target_dc, hops=_hops)
            except Exception as e:
                print(f"[ERROR] referral follow failed: {e}")
                return False
            _hops += 1
            payload = LDAP_PUT_FSTRING.format(
                uuid=_make_msgid(),
                fqdn=resource_client._fqdn,
                object_ref=object_ref,
                operation="replace",
                attribute="addata:dNSTombstoned",
                data_type="boolean",
                value=val,
            )
        except Exception:
            et = None
            break

    s = raw if isinstance(raw, str) else raw.decode(errors="ignore")
    print("[DEBUG] Replace dNSTombstoned response (truncated):")
    print(s[:2000])

    # if parsed and contains a SOAP Fault -> failure
    if et is not None:
        # SOAP Fault elements are in the SOAP envelope namespace
        fault = et.find(".//{http://www.w3.org/2003/05/soap-envelope}Fault")
        if fault is not None:
            # print fault detail for user
            try:
                from xml.etree import ElementTree as ET
                print("[DEBUG] Parsed Fault:")
                print(ET.tostring(fault, encoding="unicode"))
            except Exception:
                pass
            return False

    # no Fault detected -> assume success
    return True

# -----------------------
# High-level ADWS operations
# -----------------------

def add_dns_record_adws(
    fqdn_record: str,
    ip_addr: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    allow_multiple: bool = False,
    ttl: int = 180,
    tcp: bool = False,
    forest: bool = False,
    legacy: bool = False,
) -> bool:
    """
    Add an A record via ADWS. Creates dnsNode if needed.

    Behavior (ADWS-only):
      - If the dnsNode exists, append the A record via ADWS Put(add).
      - If the dnsNode does not exist, create it via ResourceFactory Create
        (without dNSTombstoned). The function will NOT set dNSTombstoned automatically
        after creation to avoid ADWS BadPutOrCreateValue errors; if needed, set the flag
        later with the explicit tombstone/resurrect helpers.

    This function now reuses a small set of ADWS clients (resource/pull/put)
    to avoid creating many connections and producing repeated "Connecting to ..." logs.
    """
    target, zone = _split_target_and_zone(fqdn_record, domain)

    # Reuse clients to reduce noisy connection logs
    resource_client = ADWSConnect(ip, domain, username, auth, "Resource")
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    put_client = ADWSConnect.put_client(ip, domain, username, auth)

    node_dn, existing_raw, tomb = find_dns_node(
        target=target,
        zone=zone,
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        forest=forest,
        legacy=legacy,
        pull_client=pull_client,
        res_client=resource_client,
    )

    serial = get_next_serial(None, ip, zone, tcp)
    record_bytes = build_a_record_bytes(ip_addr, serial, ttl)

    # If node exists, add A record (respect allow_multiple)
    if node_dn:
        if not allow_multiple:
            for raw in existing_raw:
                try:
                    dr = DNS_RECORD(raw)
                    if dr["Type"] == 1:
                        a = DNS_RPC_RECORD_A(dr["Data"])
                        raise RuntimeError(
                            f"A record already exists (points to {a.formatCanonical()}). Use modify or allow_multiple."
                        )
                except Exception:
                    pass
        put_client.put(
            object_ref=node_dn,
            operation="add",
            attribute="addata:dnsRecord",
            data_type="base64Binary",
            value=_b64(record_bytes),
        )
        print(f"[+] Added A record {target}.{zone} -> {ip_addr} (ADWS Put add on {node_dn})")
        return True

    # Need to create dnsNode via ResourceFactory Create (do NOT include dNSTombstoned)
    contexts = get_rootdse_contexts(resource_client)
    schemaNamingContext = contexts.get("schemaNamingContext")
    if not schemaNamingContext:
        schemaNamingContext = "CN=Schema," + ",".join([f"DC={p}" for p in domain.split(".") if p])

    objectCategory = f"CN=Dns-Node,{schemaNamingContext}"

    # domain_dn (DC=example,DC=local)
    domain_parts = [p for p in domain.split(".") if p]
    domain_dn = ",".join([f"DC={p}" for p in domain_parts])
    container_root = f"CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}"

    # enumerate dnsZone objects and pick the correct one (reuse pull_client).
    # ADWSConnect.pull() handles LDAP referrals transparently via
    # _request_with_retries + _swap_endpoint: if the target DC does not host
    # the DomainDnsZones partition, the underlying request layer swaps this
    # client to the referred DC and retries automatically.
    try:
        et_zones = _pull_with_referral_follow(
            pull_client, "(objectClass=dnsZone)", container_root,
            ["distinguishedName"],
        )
    except Exception as e:
        raise RuntimeError(f"Failed to enumerate dnsZone under {container_root}: {e}")

    # If the pull was referred to another DC (multi-DC forest), the pull_client
    # has been swapped to that DC. Use its fqdn for the subsequent Create,
    # otherwise AD returns CouldntFindParentObjectForCreation because the
    # parent container does not exist on the original DC.
    create_target_fqdn = pull_client._fqdn
    if create_target_fqdn != resource_client._fqdn:
        try:
            create_target_ip = socket.gethostbyname(create_target_fqdn)
            logging.info(
                f"Routing Create toward {create_target_fqdn} ({create_target_ip}) "
                f"which hosts the DomainDnsZones partition"
            )
        except socket.gaierror as gai:
            logging.warning(
                f"Cannot resolve {create_target_fqdn} for Create routing: {gai}. "
                f"Falling back to original DC {ip}."
            )
            create_target_ip = ip
            create_target_fqdn = resource_client._fqdn
    else:
        create_target_ip = ip

    zone_dns = []
    for elem in et_zones.findall(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES):
        if elem is not None and elem.text:
            zone_dns.append(elem.text.strip())

    # choose matching zone DN
    chosen_zone_dn = None
    zone_lc = zone.lower()
    for zdn in zone_dns:
        first_rdn = zdn.split(",", 1)[0].strip()
        if first_rdn.lower().startswith("dc="):
            rdn_val = first_rdn[3:].lower()
        else:
            rdn_val = first_rdn.lower()
        if zone_lc == rdn_val or (zone_lc in rdn_val) or (rdn_val in zone_lc):
            chosen_zone_dn = zdn
            break

    if not chosen_zone_dn:
        # try some candidates
        zone_parts = [p for p in zone.split(".") if p]
        if zone_parts:
            cand1 = f"DC={zone},{container_root}"
            cand2 = f"DC={zone_parts[0]},{container_root}"
            for c in (cand1, cand2):
                if c in zone_dns:
                    chosen_zone_dn = c
                    break
    if not chosen_zone_dn and zone_dns:
        chosen_zone_dn = zone_dns[0]

    if not chosen_zone_dn:
        raise RuntimeError(f"Could not find dnsZone DN for zone '{zone}'. Enumerated: {zone_dns}")

    valid_container = chosen_zone_dn

    # build attributes for creation (without dNSTombstoned)
    base_atav_parts = []
    base_atav_parts.append(
        "      <AttributeTypeAndValue>\n"
        "        <AttributeType>addata:objectClass</AttributeType>\n"
        "        <AttributeValue>\n"
        "          <ad:value xsi:type=\"xsd:string\">dnsNode</ad:value>\n"
        "        </AttributeValue>\n"
        "      </AttributeTypeAndValue>\n"
    )
    base_atav_parts.append(
        "      <AttributeTypeAndValue>\n"
        "        <AttributeType>ad:container-hierarchy-parent</AttributeType>\n"
        "        <AttributeValue>\n"
        f"          <ad:value xsi:type=\"xsd:string\">{valid_container}</ad:value>\n"
        "        </AttributeValue>\n"
        "      </AttributeTypeAndValue>\n"
    )
    base_atav_parts.append(
        "      <AttributeTypeAndValue>\n"
        "        <AttributeType>addata:objectCategory</AttributeType>\n"
        f"        <AttributeValue>\n          <ad:value xsi:type=\"xsd:string\">{objectCategory}</ad:value>\n"
        "        </AttributeValue>\n"
        "      </AttributeTypeAndValue>\n"
    )
    base_atav_parts.append(
        "      <AttributeTypeAndValue>\n"
        "        <AttributeType>addata:name</AttributeType>\n"
        "        <AttributeValue>\n"
        f"          <ad:value xsi:type=\"xsd:string\">{target}</ad:value>\n"
        "        </AttributeValue>\n"
        "      </AttributeTypeAndValue>\n"
    )
    base_atav_parts.append(
        "      <AttributeTypeAndValue>\n"
        "        <AttributeType>addata:dnsRecord</AttributeType>\n"
        "        <AttributeValue>\n"
        f"          <ad:value xsi:type=\"xsd:base64Binary\">{_b64(record_bytes)}</ad:value>\n"
        "        </AttributeValue>\n"
        "      </AttributeTypeAndValue>\n"
    )

    # Try RDN styles: DC=<target> then CN=<target>
    rdn_candidates = [f"DC={target}", f"CN={target}"]
    last_exc = None
    for rdn in rdn_candidates:
        atav_parts = []
        atav_parts.append(base_atav_parts[0])  # objectClass
        # relative RDN
        atav_parts.append(
            "      <AttributeTypeAndValue>\n"
            "        <AttributeType>ad:relativeDistinguishedName</AttributeType>\n"
            "        <AttributeValue>\n"
            f"          <ad:value xsi:type=\"xsd:string\">{rdn}</ad:value>\n"
            "        </AttributeValue>\n"
            "      </AttributeTypeAndValue>\n"
        )
        atav_parts.extend(base_atav_parts[1:])
        atav_xml = "".join(atav_parts)

        msg_id = _make_msgid()
        create_payload = LDAP_CREATE_FOR_RESOURCEFACTORY.format(
            uuid=msg_id,
            fqdn=create_target_fqdn,
            atav_xml=atav_xml,
            container_dn=valid_container,
            object_class="dnsNode",
        )

        # Debug: show payload if needed
        # print("[DEBUG] Create payload (RDN=%s):\n%s" % (rdn, create_payload))

        try:
            rf_client = ADWSConnect(create_target_ip, domain, username, auth, "ResourceFactory")
            # Retry loop for LDAP referrals: if the target DC does not host the
            # DomainDnsZones partition, _swap_endpoint reconnects rf_client to
            # the referred DC and we rebuild the payload with its fqdn.
            _hops = 0
            while True:
                rf_client._nmf.send(create_payload)
                response = rf_client._nmf.recv()
                try:
                    et = rf_client._handle_str_to_xml(response)
                    break
                except ADWSReferralError as _referral:
                    rf_client._swap_endpoint(_referral.target_dc, hops=_hops)
                    _hops += 1
                    # Rebuild payload with new fqdn (rf_client._fqdn was updated by _swap_endpoint)
                    create_payload = LDAP_CREATE_FOR_RESOURCEFACTORY.format(
                        uuid=str(uuid4()),
                        fqdn=rf_client._fqdn,
                        atav_xml=atav_xml,
                        container_dn=valid_container,
                        object_class="dnsNode",
                    )
            if et is None:
                raise RuntimeError("Create/AddRequest returned empty or malformed response")
            new_dn = f"{rdn},{valid_container}"

            # Do NOT attempt to set dNSTombstoned here. Creating without dNSTombstoned
            # avoids ADWS BadPutOrCreateValue errors. If the caller needs the attribute,
            # they should set it explicitly using the tombstone/resurrect helpers.
            print(f"[+] Created dnsNode {new_dn} and added A record {ip_addr}")
            return True
        except Exception as e:
            last_exc = e
            print(f"[DEBUG] Create attempt with RDN {rdn} failed: {e}")
            continue

    # if we get here, all create attempts failed
    raise RuntimeError(f"All Create attempts failed. Last error: {last_exc}")

def modify_dns_record_adws(
    fqdn_record: str,
    new_ip: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    ttl: int = 180,
    tcp: bool = False,
    forest: bool = False,
    legacy: bool = False,
) -> bool:
    target, zone = _split_target_and_zone(fqdn_record, domain)

    # reuse pull client for find_dns_node to reduce connections
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    resource_client = ADWSConnect(ip, domain, username, auth, "Resource")

    node_dn, existing_raw, tomb = find_dns_node(
        target=target,
        zone=zone,
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        forest=forest,
        legacy=legacy,
        pull_client=pull_client,
        res_client=resource_client,
    )
    if not node_dn:
        raise RuntimeError("Target dnsNode not found; cannot modify")

    serial = get_next_serial(None, ip, zone, tcp)
    new_bytes = build_a_record_bytes(new_ip, serial, ttl)

    put_client = ADWSConnect.put_client(ip, domain, username, auth)

    for raw in existing_raw:
        try:
            put_client.put(
                object_ref=node_dn,
                operation="delete",
                attribute="addata:dnsRecord",
                data_type="base64Binary",
                value=_b64(raw),
            )
        except Exception:
            pass

    put_client.put(
        object_ref=node_dn,
        operation="add",
        attribute="addata:dnsRecord",
        data_type="base64Binary",
        value=_b64(new_bytes),
    )

    print(f"[+] Replaced A record for {target}.{zone} with {new_ip} via ADWS Put operations")
    return True


def remove_dns_record_adws(
    fqdn_record: str,
    ip_to_remove: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    tcp: bool = False,
    forest: bool = False,
    legacy: bool = False,
    ldapdelete: bool = False,
) -> bool:
    """
    Remove an A record via ADWS.

    Behavior change:
      - If multiple DNS records exist for the node, remove only the matching A record (ADWS Put delete).
      - If this is the only DNS record for the node, convert it to a tombstone:
          * Replace dnsRecord with a TS (type 0) record
          * (dNSTombstoned Modify is optional and may be performed separately)
      - If ldapdelete=True perform a full delete of the dnsNode via Resource Delete.
    """
    target, zone = _split_target_and_zone(fqdn_record, domain)

    # reuse clients to reduce connections
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    resource_client = ADWSConnect(ip, domain, username, auth, "Resource")
    put_client = ADWSConnect.put_client(ip, domain, username, auth)

    node_dn, existing_raw, tomb = find_dns_node(
        target=target,
        zone=zone,
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        forest=forest,
        legacy=legacy,
        pull_client=pull_client,
        res_client=resource_client,
    )
    if not node_dn:
        raise RuntimeError("Target dnsNode not found; cannot remove")

    # If caller requests full LDAP-style delete via Resource, do that
    if ldapdelete:
        msg_id = _make_msgid()
        delete_payload = LDAP_DELETE_FOR_RESOURCE.format(
            object_dn=node_dn,
            uuid=msg_id,
            fqdn=resource_client._fqdn,
        )
        # Retry loop for LDAP referrals: if the target DC does not host the
        # DomainDnsZones partition, _swap_endpoint reconnects resource_client
        # to the referred DC and we rebuild the payload with its fqdn.
        _hops = 0
        while True:
            resource_client._nmf.send(delete_payload)
            response = resource_client._nmf.recv()
            try:
                et = resource_client._handle_str_to_xml(response)
                break
            except ADWSReferralError as _referral:
                resource_client._swap_endpoint(_referral.target_dc, hops=_hops)
                _hops += 1
                delete_payload = LDAP_DELETE_FOR_RESOURCE.format(
                    object_dn=node_dn,
                    uuid=_make_msgid(),
                    fqdn=resource_client._fqdn,
                )
        if et is None:
            raise RuntimeError("DeleteResponse empty/malformed")
        print(f"[+] Deleted dnsNode {node_dn} via ADWS Resource Delete")
        return True

    # If multiple records, remove only the specific A record requested
    if len(existing_raw) > 1:
        found = None
        for record in existing_raw:
            try:
                dr = DNS_RECORD(record)
                if dr["Type"] == 1:
                    a = DNS_RPC_RECORD_A(dr["Data"])
                    if a.formatCanonical() == ip_to_remove:
                        found = record
                        break
            except Exception:
                continue
        if not found:
            raise RuntimeError("Could not find a matching A record for the specified IP")
        put_client.put(
            object_ref=node_dn,
            operation="delete",
            attribute="addata:dnsRecord",
            data_type="base64Binary",
            value=_b64(found),
        )
        print(f"[+] Removed A record {target}.{zone} -> {ip_to_remove} via ADWS Put(delete)")
        return True

    # If only one record exists, tombstone the node (TS record). dNSTombstoned modify not enforced here.
    diff = datetime.datetime.utcnow() - datetime.datetime(1601, 1, 1)
    tstime = int(diff.total_seconds() * 10000000)

    ts_bytes = build_ts_record_bytes(tstime)

    # Remove any existing records first
    for raw in existing_raw:
        try:
            put_client.put(
                object_ref=node_dn,
                operation="delete",
                attribute="addata:dnsRecord",
                data_type="base64Binary",
                value=_b64(raw),
            )
        except Exception:
            pass

    # Add TS record
    put_client.put(
        object_ref=node_dn,
        operation="add",
        attribute="addata:dnsRecord",
        data_type="base64Binary",
        value=_b64(ts_bytes),
    )

    # Note: intentionally NOT attempting to change dNSTombstoned here to avoid ADWS validation failures.
    return True


def tombstone_dns_record_adws(
    fqdn_record: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    tcp: bool = False,
    forest: bool = False,
    legacy: bool = False,
) -> bool:
    target, zone = _split_target_and_zone(fqdn_record, domain)

    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    resource_client = ADWSConnect(ip, domain, username, auth, "Resource")
    node_dn, existing_raw, _ = find_dns_node(
        target=target,
        zone=zone,
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        forest=forest,
        legacy=legacy,
        pull_client=pull_client,
        res_client=resource_client,
    )
    if not node_dn:
        raise RuntimeError("Target dnsNode not found; cannot tombstone")

    diff = datetime.datetime.utcnow() - datetime.datetime(1601, 1, 1)
    tstime = int(diff.total_seconds() * 10000000)

    ts_bytes = build_ts_record_bytes(tstime)

    put_client = ADWSConnect.put_client(ip, domain, username, auth)

    for raw in existing_raw:
        try:
            put_client.put(
                object_ref=node_dn,
                operation="delete",
                attribute="addata:dnsRecord",
                data_type="base64Binary",
                value=_b64(raw),
            )
        except Exception:
            pass

    put_client.put(
        object_ref=node_dn,
        operation="add",
        attribute="addata:dnsRecord",
        data_type="base64Binary",
        value=_b64(ts_bytes),
    )

    # Keep behavior same as other helpers: the strict Replace for dNSTombstoned can be done separately.
    print(f"[+] Tombstone applied to dnsNode {target}.{zone} (TS record added).")
    return True


def resurrect_dns_record_adws(
    fqdn_record: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    tcp: bool = False,
    forest: bool = False,
    legacy: bool = False,
) -> bool:
    target, zone = _split_target_and_zone(fqdn_record, domain)

    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    resource_client = ADWSConnect(ip, domain, username, auth, "Resource")
    node_dn, existing_raw, _ = find_dns_node(
        target=target,
        zone=zone,
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        forest=forest,
        legacy=legacy,
        pull_client=pull_client,
        res_client=resource_client,
    )
    if not node_dn:
        raise RuntimeError("Target dnsNode not found; cannot resurrect")

    if len(existing_raw) > 1:
        raise RuntimeError("Multiple records present; resurrect behavior is undefined in this helper")

    diff = datetime.datetime.utcnow() - datetime.datetime(1601, 1, 1)
    tstime = int(diff.total_seconds() * 10000000)
    ts_bytes = build_ts_record_bytes(tstime)

    put_client = ADWSConnect.put_client(ip, domain, username, auth)

    for raw in existing_raw:
        try:
            put_client.put(
                object_ref=node_dn,
                operation="delete",
                attribute="addata:dnsRecord",
                data_type="base64Binary",
                value=_b64(raw),
            )
        except Exception:
            pass

    put_client.put(
        object_ref=node_dn,
        operation="add",
        attribute="addata:dnsRecord",
        data_type="base64Binary",
        value=_b64(ts_bytes),
    )

    # Leave dNSTombstoned change to caller if they need it
    print(f"[+] Resurrect helper wrote TS record for {target}.{zone} (caller's responsibility to set dNSTombstoned=False if needed).")
    return True
