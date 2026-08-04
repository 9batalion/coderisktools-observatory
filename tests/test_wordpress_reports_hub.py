import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "sync_wordpress_reports_hub.py"
spec = importlib.util.spec_from_file_location("sync_wordpress_reports_hub", SCRIPT)
assert spec is not None
assert spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def sample_report():
    entries = []
    for rank in range(1, 16):
        entries.append({
            "rank": rank,
            "repository": f"owner/repo-{rank}",
            "repository_url": f"https://github.com/owner/repo-{rank}",
            "stars": 100000 - rank,
            "head_sha": f"{rank:040x}",
            "scan_status": "complete",
            "observation_counts": {"critical": 0, "high": 1, "medium": 2, "low": 3, "total": 6},
        })
    return {"entries": entries, "week": "2026-W30"}


def test_combined_report_table_is_single_continuous_english_page():
    rendered = module.render_coverage_block("https://example.test/report", sample_report())
    assert rendered.count("<table>") == 1
    assert rendered.count("<tbody>") == 1
    assert rendered.count("<tr>") == 31  # one header plus reports 1-30
    assert "Reports 1–30" in rendered
    assert "Page 1 contains reports 1–30" in rendered
    assert "limited to 50 rows" in rendered
    assert "moby/moby" in rendered
    assert "ansible/ansible" in rendered
    assert "NOT STARTED" in rendered
    assert "Proponowany" not in rendered
    assert "Raporty" not in rendered
    assert "nie rozpoczęto" not in rendered
    assert "Scanner i zakres" not in rendered


def test_next_cohort_numbers_and_exact_sha_are_rendered_in_same_table():
    rendered = module.render_coverage_block("https://example.test/report", sample_report())
    assert '<tr><td>16</td><td><a href="https://github.com/moby/moby">moby/moby</a>' in rendered
    assert '<code>6719bc3c8d67</code>' in rendered
    assert '<tr><td>30</td><td><a href="https://github.com/ansible/ansible">ansible/ansible</a>' in rendered
    assert '<code>2d8c74aa7ae5</code>' in rendered
