"""Tier-1 label decisions, tested against recorded device responses.

Never contacts a firewall (PRD §5: `[LAB]` criteria only). Every field name and value below was
read off a live response on 2026-08-17, so these tests assert against what PAN-OS actually emits
rather than against a guess. That distinction has already earned itself once: an earlier fixture
was modelled on the *CLI* output, where the threat category appears as `category` and the
signature id is bundled into `threatid`. Over the XML API neither is true — `category` is the URL
category and reads `any`, `thr_category` holds the threat category, and the id is in `tid` — and
the fixture agreed with the bug it was supposed to catch.
"""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET

import pytest

from flabel import panw

#: Six entries in the exact shape the device returned on 2026-08-17 — field names verified against
#: a live response, which is why `category` reads `any` and the threat category is `thr_category`.
#: Includes an `informational` observation and a `url` subtype, neither of which may become a label.
THREAT_XML = """<response status="success">
 <result>
  <job><status>FIN</status></job>
  <log><logs count="6" progress="100">
   <entry logid="1">
    <receive_time>2026/08/17 13:49:43</receive_time>
    <subtype>vulnerability</subtype>
    <src>45.90.163.37</src><dst>216.152.152.123</dst>
    <sport>56406</sport><dport>9034</dport><proto>udp</proto><app>unknown-udp</app>
    <threatid>Realtek Jungle SDK Remote Code Execution Vulnerability</threatid>
    <tid>91535</tid><sessionid>70001</sessionid><repeatcnt>1</repeatcnt>
    <severity>critical</severity><category>any</category>
    <thr_category>code-execution</thr_category>
    <contentver>AppThreat-9136-10199</contentver>
    <direction>client-to-server</direction><action>drop</action>
   </entry>
   <entry logid="2">
    <receive_time>2026/08/17 13:49:47</receive_time>
    <subtype>vulnerability</subtype>
    <src>91.92.40.29</src><dst>216.152.152.123</dst>
    <sport>61968</sport><dport>22</dport><proto>tcp</proto><app>ssh</app>
    <threatid>SSH User Authentication Brute Force Attempt</threatid>
    <tid>40015</tid><sessionid>70002</sessionid><repeatcnt>1</repeatcnt>
    <severity>high</severity><category>any</category>
    <thr_category>brute-force</thr_category>
    <contentver>AppThreat-9136-10199</contentver>
    <direction>client-to-server</direction><action>reset-both</action>
   </entry>
   <entry logid="3">
    <receive_time>2026/08/17 13:49:47</receive_time>
    <subtype>vulnerability</subtype>
    <src>216.152.152.123</src><dst>91.92.40.29</dst>
    <sport>22</sport><dport>22598</dport><proto>tcp</proto><app>ssh</app>
    <threatid>SSH User Authentication Brute Force Attempt</threatid>
    <tid>40015</tid><sessionid>70003</sessionid><repeatcnt>1</repeatcnt>
    <severity>high</severity><category>any</category>
    <thr_category>brute-force</thr_category>
    <contentver>AppThreat-9136-10199</contentver>
    <direction>server-to-client</direction><action>reset-both</action>
   </entry>
   <entry logid="4">
    <receive_time>2026/08/17 13:49:42</receive_time>
    <subtype>vulnerability</subtype>
    <src>205.237.105.154</src><dst>216.152.152.123</dst>
    <sport>5123</sport><dport>5060</dport><proto>udp</proto><app>sip</app>
    <threatid>SIPVicious Scanner Detection</threatid>
    <tid>54482</tid><sessionid>70004</sessionid><repeatcnt>1</repeatcnt>
    <severity>medium</severity><category>any</category>
    <thr_category>info-leak</thr_category>
    <contentver>AppThreat-9136-10199</contentver>
    <direction>client-to-server</direction><action>drop</action>
   </entry>
   <entry logid="5">
    <receive_time>2026/08/17 13:49:39</receive_time>
    <subtype>vulnerability</subtype>
    <src>115.231.78.11</src><dst>216.152.152.123</dst>
    <sport>61994</sport><dport>7</dport><proto>tcp</proto><app>echo</app>
    <threatid>Non-RFC Compliant ECHO Traffic on Port 7</threatid>
    <tid>56796</tid><sessionid>70005</sessionid><repeatcnt>1</repeatcnt>
    <severity>informational</severity><category>any</category>
    <thr_category>protocol-anomaly</thr_category>
    <contentver>AppThreat-9136-10199</contentver>
    <direction>client-to-server</direction><action>alert</action>
   </entry>
   <entry logid="6">
    <receive_time>2026/08/17 13:49:51</receive_time>
    <subtype>url</subtype>
    <src>144.225.124.188</src><dst>216.152.152.123</dst>
    <sport>5353</sport><dport>1027</dport><proto>udp</proto><app>dns</app>
    <threatid>some-url-category</threatid>
    <tid>9999</tid><sessionid>70006</sessionid><repeatcnt>1</repeatcnt>
    <severity>high</severity><category>search-engines</category>
    <thr_category>unknown</thr_category>
    <contentver>AppThreat-9136-10199</contentver>
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


def test_severity_is_not_a_gate_because_the_device_owns_that_decision():
    """Decided 2026-08-17: tier-1 admission lives in the firewall's threat exceptions.

    An earlier version excluded `informational` on issue #75's argument. That reasoning holds for
    Suricata, where flabel owns the ruleset; here it would overrule an exception the operator
    configured deliberately and drop a detection they had already chosen to keep. What replaces
    the gate is a recorded basis, not silent trust — see `test_a_tier_1_entry_records_the_policy
    _that_admitted_it`.
    """
    informational = [e for e in entries() if panw.threat_id(e) == 56796]
    assert informational and panw.admits(informational[0])


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
    found, _, _rs = panw.detections(entries())
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
    found, declined, _rs = panw.detections(entries())
    # Five of six admitted: only the `url` subtype is refused, and it is refused structurally.
    assert len(found) == 5
    assert len(declined) == 1
    assert "not a signature match" in declined[0]


def test_both_directions_of_one_signature_are_kept_as_separate_detections():
    """Two entries, same signature, opposite directions, different flows.

    correlate() consolidates by flow; discarding one here would decide that for it, and the
    server-side entry is a different connection rather than a duplicate.
    """
    found, _, _rs = panw.detections(entries())
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


def test_the_query_window_is_written_in_utc():
    """Measured 2026-08-17: this exact bug returned 0 rows for a window holding 13 logs.

    `receive_time` is compared as text, so the filter and the device must render an instant in
    the same zone. Formatting in the *replay host's* local zone silently shifted the window by
    seven hours — the host was UTC, the device PDT — and produced an empty result that read as
    "nothing malicious in this capture".
    """
    # 2026-08-17 22:11:59 UTC exactly.
    query = panw.ThreatQuery(start_wall=1787004719.0, end_wall=1787004719.0, pad_seconds=0)
    assert query.filter_expression() == (
        "(receive_time geq '2026/08/17 22:11:59') and (receive_time leq '2026/08/17 22:11:59')"
    )


def test_a_receive_time_is_read_as_utc_not_as_local_time():
    entry = ET.fromstring("<entry><receive_time>2026/08/17 22:11:59</receive_time></entry>")
    found = panw._receive_epoch(entry)
    assert found == pytest.approx(1787004719.0)


def test_a_clock_within_the_pad_is_accepted():
    ok, message = panw.verify_clock(device_ts=1787004719.0, local_ts=1787004724.0)
    assert ok and message is None


def test_a_timezone_sized_skew_is_refused_and_says_why():
    """Seven hours is what a zone mismatch looks like, and it must not read as an empty capture."""
    ok, message = panw.verify_clock(device_ts=1787004719.0, local_ts=1787004719.0 + 7 * 3600)
    assert not ok
    assert "timezone" in message and "nothing malicious" in message


def test_the_device_clock_is_parsed_from_show_clock_output():
    assert panw._clock_epoch("Mon Aug 17 22:11:59 UTC 2026") == pytest.approx(1787004719.0)


def test_an_unreadable_device_clock_is_an_error_rather_than_a_guess():
    with pytest.raises(Exception, match="clock could not be read"):
        panw._clock_epoch("not a time at all")


def test_the_threat_category_comes_from_thr_category_not_from_category():
    """Measured 2026-08-17: `category` is the URL category and reads `any` on every threat.

    Reading it published `classtype: "any"` on all 915 detections of a run — uniform,
    well-formed, and meaningless in the field a tier-1 admission policy would gate on.
    """
    entry = ET.fromstring(
        "<entry><threatid>SIPVicious Scanner Detection</threatid><tid>54482</tid>"
        "<severity>medium</severity><subtype>vulnerability</subtype>"
        "<category>any</category><thr_category>info-leak</thr_category>"
        "<src>1.2.3.4</src><dst>5.6.7.8</dst><sport>1</sport><dport>2</dport><proto>udp</proto>"
        "<direction>client-to-server</direction></entry>"
    )
    found, _, _rs = panw.detections([entry])
    assert found[0].classtype == "info-leak"


def test_the_numeric_id_is_taken_from_tid_when_the_xml_does_not_embed_it():
    """The XML spells these differently from the CLI: `threatid` is the name, `tid` the number."""
    entry = ET.fromstring("<entry><threatid>SIPVicious Scanner Detection</threatid>"
                          "<tid>54482</tid></entry>")
    assert panw.threat_id(entry) == 54482
    assert panw.threat_name(entry) == "SIPVicious Scanner Detection"


def test_the_content_version_is_read_from_the_entry_itself():
    """Per-entry, so a content update mid-run cannot relabel earlier detections."""
    entry = ET.fromstring("<entry><contentver>AppThreat-9136-10199</contentver></entry>")
    assert panw.content_version(entry) == "AppThreat-9136-10199"


def _det(sid: int, ts: float, sport: int = 5362) -> object:
    entry = ET.fromstring(
        f"<entry><threatid>x</threatid><tid>{sid}</tid><severity>high</severity>"
        f"<subtype>vulnerability</subtype><thr_category>brute-force</thr_category>"
        f"<src>51.178.198.251</src><dst>216.152.152.123</dst>"
        f"<sport>{sport}</sport><dport>5060</dport><proto>udp</proto>"
        f"<receive_time>{time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(ts))}</receive_time>"
        f"<direction>client-to-server</direction></entry>"
    )
    found, _, _rs = panw.detections([entry])
    return found[0]


def test_one_signature_firing_repeatedly_on_one_tuple_collapses_to_one_assertion():
    """Measured: 143 entries on one (signature, tuple) across just 2 sessions, repeatcnt 1.

    `SourceEntry` has no timestamp, session or count field, so keeping all 143 would put 143
    byte-identical provenance rows on one label.
    """
    repeats = [_det(40023, 1787004700.0 + i) for i in range(143)]
    kept, collapsed = panw.deduplicate(repeats)
    assert len(kept) == 1
    assert collapsed == 142


def test_the_earliest_occurrence_is_the_one_kept():
    """Its timestamp sits closest to the flow's own start, which is what `ts_first` holds."""
    later = _det(40023, 1787004900.0)
    earlier = _det(40023, 1787004700.0)
    kept, _ = panw.deduplicate([later, earlier])
    assert kept[0].ts == earlier.ts


def test_the_same_signature_on_a_different_tuple_is_not_collapsed():
    kept, collapsed = panw.deduplicate([_det(40023, 1787004700.0, sport=5362),
                                        _det(40023, 1787004700.0, sport=4040)])
    assert len(kept) == 2 and collapsed == 0


def test_nothing_is_collapsed_when_nothing_repeats():
    kept, collapsed = panw.deduplicate([_det(40023, 1787004700.0), _det(54482, 1787004701.0)])
    assert len(kept) == 2 and collapsed == 0
