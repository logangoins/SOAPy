import json
import logging
from unittest.mock import Mock
from xml.etree import ElementTree as ET

import pytest

from src.ad_dns_manager_adws import _pull_with_referral_follow
from src.adws import ADWSConnect, ADWSError, ADWSReferralError
from src.soap_templates import NAMESPACES


DN = "CN=TEST,DC=example,DC=com"


def response(attributes="", empty=False):
    items = "" if empty else (
        '<addata:computer><addata:distinguishedName LdapSyntax="DirectoryString">'
        f"<ad:value>{DN}</ad:value></addata:distinguishedName>"
        f"{attributes}</addata:computer>"
    )
    return ET.fromstring(
        f'<wsen:PullResponse xmlns:wsen="{NAMESPACES["wsen"]}" '
        f'xmlns:addata="{NAMESPACES["addata"]}" xmlns:ad="{NAMESPACES["ad"]}">'
        f"<wsen:Items>{items}</wsen:Items></wsen:PullResponse>"
    )


@pytest.fixture
def client():
    # Exercise collection and formatting without connecting to a domain controller.
    client = object.__new__(ADWSConnect)
    client._resource = "Enumeration"
    client._fqdn = "dc.example.com"
    client._domain = "example.com"
    client._nmf = Mock()
    client._request_with_retries = Mock(return_value=ET.fromstring(
        f'<response xmlns:wsen="{NAMESPACES["wsen"]}">'
        '<wsen:EnumerationContext>context</wsen:EnumerationContext></response>'
    ))
    client._pull_results = Mock(return_value=(response(), False))
    return client


@pytest.mark.parametrize("debug_only", [False, True])
@pytest.mark.parametrize("level", [logging.INFO, logging.DEBUG])
@pytest.mark.parametrize("empty", [False, True])
def test_lookup_output(client, capsys, caplog, debug_only, level, empty):
    caplog.set_level(level)
    client._pull_results.return_value = (response(empty=empty), False)
    result = client.pull("(objectClass=*)", None, ["distinguishedName"], debug_only=debug_only)
    output = capsys.readouterr()
    visible = not debug_only or level == logging.DEBUG
    expected = "No objects found" if empty else f"distinguishedName: {DN}"
    assert (expected in output.out) == visible
    assert len(client._iter_response_objects(result)) == (0 if empty else 1)
    if not visible:
        assert output.out == output.err == caplog.text == ""
    else:
        assert "Using query:" in caplog.text
        assert "ADWS data collection complete" in output.err + caplog.text


@pytest.mark.parametrize("debug_only", [False, True])
def test_saved_collection_and_recovery(client, capsys, caplog, tmp_path, debug_only):
    caplog.set_level(logging.DEBUG)
    data_path = tmp_path / ".soapy_data"
    client.pull(
        "(objectClass=*)", None, ["distinguishedName"],
        data_path=str(data_path), print_results=False, debug_only=debug_only,
    )
    assert capsys.readouterr().out == ""
    records = [json.loads(line) for line in data_path.read_text().splitlines()]
    assert [record["type"] for record in records] == ["query", "page", "base_complete", "complete"]
    assert ADWSConnect.print_soapy_data(str(data_path)) == (1, 1, 0)
    assert f"distinguishedName: {DN}" in capsys.readouterr().out


@pytest.mark.parametrize("level", [logging.INFO, logging.DEBUG])
def test_ranged_lookup_output(client, capsys, caplog, level):
    caplog.set_level(level)
    initial = response(
        '<addata:member LdapSyntax="DirectoryString" RangeLow="0" RangeHigh="0">'
        '<ad:value>first</ad:value></addata:member>'
    )
    additional = response(
        '<addata:member LdapSyntax="DirectoryString" RangeLow="1" RangeHigh="*">'
        '<ad:value>second</ad:value></addata:member>'
    )
    client._pull_results.side_effect = [(initial, False), (additional, False)]
    result = client.pull("(objectClass=*)", None, ["member"], debug_only=True)
    values = result.findall(".//addata:member/ad:value", NAMESPACES)
    assert [value.text for value in values] == ["first", "second"]
    output = capsys.readouterr()
    if level == logging.INFO:
        assert output.out == output.err == caplog.text == ""
    else:
        assert "second" in output.out
        assert "Collecting ADWS ranged data" in caplog.text


def test_internal_referral_retry_keeps_output_quiet(client, capsys, caplog):
    caplog.set_level(logging.INFO)
    client._request_with_retries.side_effect = [
        ADWSReferralError("other.example.com", DN),
        client._request_with_retries.return_value,
    ]
    client._swap_endpoint = Mock()
    result = _pull_with_referral_follow(client, "(objectClass=*)", None, ["distinguishedName"])
    assert len(client._iter_response_objects(result)) == 1
    client._swap_endpoint.assert_called_once_with("other.example.com", hops=0)
    output = capsys.readouterr()
    assert output.out == output.err == caplog.text == ""


def test_internal_lookup_errors_propagate(client):
    client._pull_results.side_effect = ADWSError("lookup failed")
    with pytest.raises(ADWSError, match="lookup failed"):
        client.pull("(objectClass=*)", None, ["distinguishedName"], debug_only=True)
