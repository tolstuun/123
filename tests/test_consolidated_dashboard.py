from pathlib import Path

from app.main import CATEGORIES, aggregate_detection


def test_detection_segments_have_fixed_order_and_sum():
    row={"arm":"static","sample_type":"file","cohort_size":8,**{category:1 for category in CATEGORIES}}
    bars=aggregate_detection([row])
    assert list(bars[0]["counts"])==list(CATEGORIES)
    assert bars[0]["total"]==8


def test_dashboard_is_single_page_and_range_selection_is_complete():
    main=Path("app/main.py").read_text(encoding="utf-8")
    base=Path("app/templates/base.html").read_text(encoding="utf-8")
    assert '@app.get("/vtis"' not in main
    assert 'href="/vtis"' not in base
    for days in (7,30,90,365):assert f"days=={days}" in base


def test_only_requested_exports_remain():
    main=Path("app/main.py").read_text(encoding="utf-8")
    for kind in ("analysis-runs","detection-by-arm","duration-lift","new-vtis"):assert f'kind=="{kind}"' in main
    for removed in ("samples","vti-observations","collection-errors","vti-comparisons"):assert f'kind=="{removed}"' not in main
