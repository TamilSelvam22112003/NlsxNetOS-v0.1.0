"""Regression tests for safe NLS trust lifecycle diagnostics."""
import json

from nls.daemon import NLSDaemon


def test_trust_sequence_failure_merges_diagnostics_without_type_error(monkeypatch):
    daemon = object.__new__(NLSDaemon)
    daemon.reason_counters = {}
    logged = []
    monkeypatch.setattr("nls.ca_client.trust_diagnostics", lambda settings, router_id=None: {
        "stored_directory_seq": 7,
        "stored_record_seq": 4,
        "incoming_directory_seq": -1,
        "incoming_record_seq": -1,
        "bundle_expires_at": 1234,
        "seconds_since_sync": 20,
    })
    monkeypatch.setattr("nls.daemon.LOG.warning", lambda message: logged.append(message))

    daemon._log_trust_sequence_failure(
        "NLS_CA_RECORD_ROLLBACK", object(), "router-a", 4, 5,
        {"directory_seq": 7}, {"directory_seq": 8}, {"expires_at": 5678},
    )

    assert len(logged) == 1
    event = json.loads(logged[0])
    assert event["stored_record_seq"] == 4
    assert event["incoming_record_seq"] == 5
    assert event["stored_directory_seq"] == 7
    assert event["incoming_directory_seq"] == 8
    assert event["bundle_expires_at"] == 5678
    assert event["seconds_since_sync"] == 20
