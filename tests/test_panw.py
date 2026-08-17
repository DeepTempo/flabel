"""Tier-1 label decisions, tested against recorded device responses.

Never contacts a firewall (PRD §5: `[LAB]` criteria only). The XML below is the shape of what
the real device returned on 2026-08-17 — the same 13 detections recorded in
`docs/phase-2-reachability-spike.md` — so these tests assert against measured output rather than
against a guess about what PAN-OS emits.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from flabel import panw

#: Six of the thirteen entries from the measured run: the corroborated Realtek detection, two
#: brute-force entries in opposite directions, a scanner detection, and two of the
#: `informational` protocol-conformance observations that must not become labels.
THREAT_XML = """<response status="success">
 <result>
  <job><status>FIN</status></job>
  <log><logs count="6" progress="100">
   <entry logid="1">
    <receive_time>2026/08/17 13:49:43</receive_time>
    <subtype>vulnerability</subtype>
    <src>45.90.163.37</src><dst>216.152.152.123</dst>
    <sport>56406</sport><dport>9034</dport><proto>udp</proto><app>unknown-udp</app>
    <threatid>Realtek Jungle SDK Remote Code Execution Vulnerability(91535)</threatid>
    <severity>critical</severity><category>code-execution</category>
    <direction>client-to-server</direction><action>drop</action>
   </entry>
   <entry logid="2">
    <receive_time>2026/08/17 13:49:47</receive_time>
    <subtype>vulnerability</subtype>
    <src>91.92.40.29</src><dst>216.152.152.123</dst>
    <sport>61968</sport><dport>22</dport><proto>tcp</proto><app>ssh</app>
    <threatid>SSH User Authentication Brute Force Attempt(40015)</threatid>
    <severity>high</severity><category>brute-force</category>
    <direction>client-to-server</direction><action>reset-both</action>
   </entry>
   <entry logid="3">
    <receive_time>2026/08/17 13:49:47</receive_time>
    <subtype>vulnerability</subtype>
    <src>216.152.152.123</src><dst>91.92.40.29</dst>
    <sport>22</sport><dport>22598</dport><proto>tcp</proto><app>ssh</app>
    <threatid>SSH User Authentication Brute Force Attempt(40015)</threatid>
    <severity>high</severity><category>brute-force</category>
    <direction>server-to-client</direction><action>reset-both</action>
   </entry>
   <entry logid="4">
    <receive_time>2026/08/17 13:49:42</receive_time>
    <subtype>vulnerability</subtype>
    <src>205.237.105.154</src><dst>216.152.152.123</dst>
    <sport>5123</sport><dport>5060</dport><proto>udp</proto><app>sip</app>
    <threatid>SIPVicious Scanner Detection(54482)</threatid>
    <severity>medium</severity><category>scan</category>
    <direction>client-to-server</direction><action>drop</action>
   </entry>
   <entry logid="5">
    <receive_time>2026/08/17 13:49:39</receive_time>
    <subtype>vulnerability</subtype>
    <src>115.231.78.11</src><dst>216.152.152.123</dst>
    <sport>61994</sport><dport>7</dport><proto>tcp</proto><app>echo</app>
    <threatid>Non-RFC Compliant ECHO Traffic on Port 7(56796)</threatid>
    <severity>informational</severity><category>protocol-anomaly</category>
    <direction>client-to-server</direction><action>alert</action>
   </entry>
   <entry logid="6">
    <receive_time>2026/08/17 13:49:51</receive_time>
    <subtype>url</subtype>
    <src>144.225.124.188</src><dst>216.152.152.123</dst>
    <sport>5353</sport><dport>1027</dport><proto>udp</proto><app>dns</app>
    <threatid>some-url-category(9999)</threatid>
    <severity>high</severity><category>unknown</category>
    <direction>client-to-server</direction><action>alert</action>
   </entry>
  </logs></log>
 </result>
</response>"""

SYSTEM_INFO_XML = """<response status="success"><result><system>
 <hostname>fl-ngfw</hostname><serial>70E6169251CFCA3</serial>
 <model>PA-VM</model><sw-version>11.1.15</sw-version>
 <app-version>8939-9248</app-version><threat-version>9136-10199</threat-version>
</system></result></response>"""

#: The state the base VM-Series image ships in, and the trap it sets: Applications-only content,
#: where no threat can fire and a run would look clean while being blind.
SYSTEM_INFO_NO_THREAT_XML = SYSTEM_INFO_XML.replace(
    "<threat-version>9136-10199</threat-version>", "<threat-version>0</threat-version>"
)


def entries() -> list[ET.Element]:
    return list(panw.iter_entries(THREAT_XML))


def test_every_entry_in_a_recorded_response_is_found():
    assert len(entries()) == 6


def test_the_device_reports_the_signature_set_that_produced_the_labels():
    info = panw.parse_system_info(ET.fromstring(SYSTEM_INFO_XML))
    assert info.serial == "70E6169251CFCA3"
    assert info.threat_version == "9136-10199"
    assert info.has_threat_content


def test_applications_only_content_is_recognised_as_having_no_threat_signatures():
    """The base image ships this way, and a run against it can produce no tier-1 label at all.

    Detecting it is what stops that being indistinguishable from a quiet capture.
    """
    info = panw.parse_system_info(ET.fromstring(SYSTEM_INFO_NO_THREAT_XML))
    assert not info.has_threat_content


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Realtek Jungle SDK Remote Code Execution Vulnerability(91535)", 91535),
        ("SSH User Authentication Brute Force Attempt(40015)", 40015),
        ("40015", 40015),
    ],
)
def test_the_signature_id_is_read_from_either_spelling(raw, expected):
    entry = ET.fromstring(f"<entry><threatid>{raw}</threatid></entry>")
    assert panw.threat_id(entry) == expected


def test_a_signature_with_no_numeric_id_is_not_attributed_to_signature_zero():
    """Reporting it beats naming the wrong signature (spec §13)."""
    entry = ET.fromstring("<entry><threatid>something unnumbered</threatid></entry>")
    assert panw.threat_id(entry) is None


def test_the_threat_name_does_not_repeat_the_id_it_is_published_beside():
    entry = ET.fromstring("<entry><threatid>SIPVicious Scanner Detection(54482)</threatid></entry>")
    assert panw.threat_name(entry) == "SIPVicious Scanner Detection"


def test_informational_severity_is_not_admitted_as_malicious():
    """The tier-1 analogue of #75.

    "Non-RFC Compliant ECHO Traffic on Port 7" is an observation about protocol conformance. A
    model trained on it as `malicious` learns that non-standard traffic is hostile.
    """
    informational = [e for e in entries() if panw.threat_id(e) == 56796]
    assert informational and not panw.admits(informational[0])


def test_a_url_subtype_is_not_admitted_even_at_high_severity():
    """Severity alone is not the gate: the entry must be a signature match on a threat."""
    url_entry = [e for e in entries() if panw.threat_id(e) == 9999]
    assert url_entry and not panw.admits(url_entry[0])


def test_the_corroborated_detection_survives_the_gate_with_its_tuple_intact():
    """The flow both tiers independently flagged, measured 2026-08-17.

    Suricata labelled 45.90.163.37:56406 -> 216.152.152.123:9034 via ET EXPLOIT Realtek SDK
    (CVE-2021-35394); the firewall flagged the same 5-tuple as signature 91535. The tuple must
    survive this module unchanged or `correlate._place` cannot join them.
    """
    found, _ = panw.detections(entries())
    realtek = [d for d in found if d.sid == 91535]
    assert len(realtek) == 1
    d = realtek[0]
    assert (d.src_ip, d.src_port, d.dst_ip, d.dst_port, d.proto) == (
        "45.90.163.37", 56406, "216.152.152.123", 9034, "udp",
    )
    assert d.tier == 1
    assert d.classtype == "code-execution"
    assert d.threat.startswith("Realtek Jungle SDK")


def test_declined_entries_are_reported_rather_than_dropped():
    """Spec §2.8: a suppressed detection is counted, never silent."""
    found, declined = panw.detections(entries())
    assert len(found) == 4
    assert len(declined) == 2
    assert any("56796" in d or "Non-RFC" in d for d in declined)


def test_both_directions_of_one_signature_are_kept_as_separate_detections():
    """Two entries, same signature, opposite directions, different flows.

    correlate() consolidates by flow; discarding one here would decide that for it, and the
    server-side entry is a different connection rather than a duplicate.
    """
    found, _ = panw.detections(entries())
    ssh = [d for d in found if d.sid == 40015]
    assert len(ssh) == 2
    assert {d.direction for d in ssh} == {"to_server", "to_client"}


def test_the_query_window_is_padded_on_both_sides():
    """A tight window would lose a real label to a one-second clock difference."""
    query = panw.ThreatQuery(start_wall=1786999773.0, end_wall=1786999788.0, pad_seconds=120)
    expression = query.filter_expression()
    assert "receive_time geq" in expression and "receive_time leq" in expression
    tight = panw.ThreatQuery(start_wall=1786999773.0, end_wall=1786999788.0, pad_seconds=0)
    assert expression != tight.filter_expression()


def test_the_written_count_is_summed_over_subtypes_not_read_off_one_counter():
    """Measured 2026-08-17: Vulnerability moved to 13 while Spyware/Anti-virus stayed at 0.

    An earlier version of this check read a single counter name, found 0, and would have
    reported that nothing was logged during a run that logged thirteen things.
    """
    before = {"vulnerability": 0, "spyware": 0, "anti-virus": 0}
    after = {"vulnerability": 13, "spyware": 0, "anti-virus": 0}
    assert panw.counter_delta(before, after) == 13


def test_a_reboot_between_readings_cannot_produce_a_negative_delta():
    before = {"vulnerability": 50}
    after = {"vulnerability": 3}
    assert panw.counter_delta(before, after) == 0


def test_logs_the_device_wrote_but_the_run_did_not_read_are_a_loss_condition():
    lost, message = panw.loss(retrieved=10, written=13)
    assert lost
    assert "3 detection(s) are missing" in message


def test_retrieving_more_than_was_written_is_not_a_loss():
    """The padded window can legitimately include a log from before the replay began."""
    lost, message = panw.loss(retrieved=14, written=13)
    assert not lost and message is None
