"""Unit tests for handler extraction, UPnP parsing, and auth matrix."""

from pathlib import Path

from tools.web.auth_matrix import classify_auth
from tools.web.handler_extract import extract_handlers
from tools.web.upnp_parse import find_upnp_xmls, parse_upnp_xml


def test_extract_goahead_form(tmp_path: Path) -> None:
    """handler_extract finds GoAhead formXxx handlers."""
    binary = tmp_path / "httpd"
    binary.write_bytes(
        b"httpd\x00formexeCommand\x00websFormDefine\x00formWifiBasic\x00"
    )
    result = extract_handlers(binary)
    assert result["goahead_registered"] is True
    routes = {h["route"] for h in result["goahead_forms"]}
    assert "/goform/formexeCommand" in routes
    assert "/goform/formWifiBasic" in routes


def test_extract_cgi_strings(tmp_path: Path) -> None:
    """handler_extract finds .cgi strings."""
    binary = tmp_path / "cgibin"
    binary.write_bytes(b"/cgi-bin/login.cgi\x00/admin/config.cgi\x00")
    result = extract_handlers(binary)
    routes = {h["route"] for h in result["cgi_strings"]}
    assert "/cgi-bin/login.cgi" in routes


def test_extract_http_env(tmp_path: Path) -> None:
    """handler_extract reports HTTP_ environment variable references."""
    binary = tmp_path / "handler"
    binary.write_bytes(b"HTTP_COOKIE\x00HTTP_USER_AGENT\x00")
    result = extract_handlers(binary)
    assert "HTTP_COOKIE" in result["http_env_vars"]


def test_parse_upnp_xml(tmp_path: Path) -> None:
    """parse_upnp_xml extracts actions with direction=in inputs."""
    xml = tmp_path / "DevUpg.xml"
    xml.write_text(
        '''<?xml version="1.0"?>
        <scpd>
          <actionList>
            <action>
              <name>Upgrade</name>
              <argumentList>
                <argument>
                  <name>NewDownloadURL</name>
                  <direction>in</direction>
                </argument>
                <argument>
                  <name>NewStatusURL</name>
                  <direction>in</direction>
                </argument>
                <argument>
                  <name>Status</name>
                  <direction>out</direction>
                </argument>
              </argumentList>
            </action>
          </actionList>
        </scpd>
        ''',
        encoding="utf-8",
    )
    result = parse_upnp_xml(xml)
    assert result["action_count"] == 1
    action = result["actions"][0]
    assert action["name"] == "Upgrade"
    assert action["high_impact"] is True
    input_names = {a["name"] for a in action["inputs"]}
    assert input_names == {"NewDownloadURL", "NewStatusURL"}


def test_find_upnp_xmls(tmp_path: Path) -> None:
    """find_upnp_xmls locates SCPD-style XML files."""
    root = tmp_path / "rootfs"
    (root / "upnp").mkdir(parents=True)
    (root / "upnp" / "DevUpg.xml").write_text(
        "<scpd><actionList><action><name>Upgrade</name></action></actionList></scpd>",
        encoding="utf-8",
    )
    (root / "config.xml").write_text("<config></config>", encoding="utf-8")
    found = find_upnp_xmls(root)
    assert len(found) == 1


def test_auth_matrix_preauth_no_evidence(tmp_path: Path) -> None:
    """No auth evidence yields preauth with lower confidence."""
    binary = tmp_path / "httpd"
    binary.write_bytes(b"formexeCommand handler")
    result = classify_auth("/goform/formexeCommand", binary, "formexeCommand", None)
    assert result.hint == "preauth"
    assert result.confidence == 0.5


def test_auth_matrix_auth_function(tmp_path: Path) -> None:
    """Presence of auth function moves hint to auth."""
    binary = tmp_path / "httpd"
    binary.write_bytes(b"formexeCommand check_auth")
    result = classify_auth("/goform/formexeCommand", binary, "formexeCommand", None)
    assert result.hint == "auth"
    assert result.confidence >= 0.8


def test_auth_matrix_route_exemption(tmp_path: Path) -> None:
    """Route-level noauth marker yields preauth with higher confidence."""
    binary = tmp_path / "httpd"
    binary.write_bytes(b"handler")
    result = classify_auth("/public/noauth/login", binary, "login", None)
    assert result.hint == "preauth"
    assert result.confidence >= 0.75
