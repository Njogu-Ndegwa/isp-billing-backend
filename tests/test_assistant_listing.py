"""The assistant narrows any list it reads by the rows' own fields (app/services/assistant/listing.py)."""
from datetime import datetime, timedelta

import pytest

from app.services.assistant.listing import ListingError, anchor_time, find_list, join_pages, narrow, next_page

ROWS = [
    {"id": 1, "name": "Jane", "status": "active", "amount": 1500, "plan": {"name": "Weekly 300"},
     "expiry": (datetime.utcnow() + timedelta(hours=5)).isoformat(), "has_paid": True},
    {"id": 2, "name": "Ken", "status": "inactive", "amount": "300", "plan": {"name": "Daily 50"},
     "expiry": (datetime.utcnow() - timedelta(days=2)).isoformat(), "has_paid": False},
    {"id": 3, "name": "Amina", "status": "active", "amount": 900, "plan": {"name": "weekly 300"},
     "expiry": (datetime.utcnow() + timedelta(days=9)).isoformat(), "has_paid": True},
    {"id": 4, "name": "Otieno", "status": "active", "amount": None, "plan": None, "expiry": None, "has_paid": False},
]


def names(data):
    rows, _ = find_list(data)
    return [r["name"] for r in rows]


def test_nested_field_and_case_insensitive_text():
    out, note = narrow(ROWS, where=[{"field": "plan.name", "op": "eq", "value": "Weekly 300"}])
    assert names(out) == ["Jane", "Amina"]
    assert note == {"rows_read": 4, "rows_kept": 2}


def test_numbers_even_when_sent_as_text():
    out, _ = narrow(ROWS, where=[{"field": "amount", "op": "gte", "value": "900"}])
    assert names(out) == ["Jane", "Amina"]


def test_times_relative_to_now():
    out, _ = narrow(ROWS, where=[{"field": "expiry", "op": "lt", "value": "now+48h"},
                                 {"field": "expiry", "op": "gt", "value": "now"}])
    assert names(out) == ["Jane"]


def test_in_empty_and_booleans():
    assert names(narrow(ROWS, where={"field": "status", "op": "in", "value": ["inactive"]})[0]) == ["Ken"]
    assert names(narrow(ROWS, where=[{"field": "plan", "op": "empty"}])[0]) == ["Otieno"]
    assert names(narrow(ROWS, where=[{"field": "has_paid", "op": "eq", "value": True}])[0]) == ["Jane", "Amina"]


def test_sort_and_limit_make_a_top_n_with_blanks_last():
    out, _ = narrow(ROWS, sort={"field": "amount", "desc": True}, limit=3)
    assert names(out) == ["Jane", "Amina", "Ken"]


def test_an_envelope_keeps_its_shape_and_its_total_follows():
    out, _ = narrow({"customers": ROWS, "total": 4, "total_pages": 1},
                    where=[{"field": "status", "op": "eq", "value": "active"}])
    assert names(out) == ["Jane", "Amina", "Otieno"]
    assert out["total"] == 3 and "total_pages" not in out


def test_a_field_no_row_has_is_an_error_never_ignored():
    with pytest.raises(ListingError) as exc:
        narrow(ROWS, where=[{"field": "colour", "op": "eq", "value": "blue"}])
    assert "colour" in str(exc.value) and "plan.name" in str(exc.value)


def test_one_page_of_many_is_flagged():
    _, note = narrow({"data": ROWS, "page": 1, "total_pages": 3}, where=[{"field": "status", "op": "eq", "value": "active"}])
    assert "more pages" in note["warning"]


def test_not_a_list_is_an_error():
    with pytest.raises(ListingError):
        narrow({"revenue": 100}, limit=3)


def test_nothing_asked_changes_nothing():
    assert narrow(ROWS) == (ROWS, None)


def test_calendar_moments_are_days_in_the_persons_timezone():
    from datetime import timezone
    now = datetime(2026, 1, 15, 22, 0, tzinfo=timezone.utc)   # already 16 Jan, 01:00 in Nairobi
    nbo = "Africa/Nairobi"
    assert anchor_time("today_start", now, nbo) == datetime(2026, 1, 15, 21, 0, tzinfo=timezone.utc)
    assert anchor_time("today_end", now, nbo) == datetime(2026, 1, 16, 21, 0, tzinfo=timezone.utc)
    assert anchor_time("yesterday_start", now, nbo) == datetime(2026, 1, 14, 21, 0, tzinfo=timezone.utc)
    assert anchor_time("month_start", now, nbo) == datetime(2025, 12, 31, 21, 0, tzinfo=timezone.utc)
    assert anchor_time("last_month_start", now, nbo) == datetime(2025, 11, 30, 21, 0, tzinfo=timezone.utc)
    assert anchor_time("week_start", now, nbo) == datetime(2026, 1, 11, 21, 0, tzinfo=timezone.utc)  # Mon 12 Jan


def test_where_takes_calendar_moments_with_offsets():
    from datetime import timezone
    from app.services.assistant import listing
    start = listing.anchor_time("today_start", None, "Africa/Nairobi")
    rows = [{"name": "early", "expiry": (start + timedelta(hours=1)).isoformat()},
            {"name": "tomorrow", "expiry": (start + timedelta(days=1, hours=1)).isoformat()},
            {"name": "yesterday", "expiry": (start - timedelta(hours=1)).isoformat()}]
    today = [{"field": "expiry", "op": "gt", "value": "today_start"}, {"field": "expiry", "op": "lte", "value": "today_end"}]
    out, _ = narrow(rows, where=today, tz_name="Africa/Nairobi")
    assert [r["name"] for r in out] == ["early"]
    out, _ = narrow(rows, where=[{"field": "expiry", "op": "gt", "value": "today_start-1d"},
                                 {"field": "expiry", "op": "lte", "value": "today_start"}], tz_name="Africa/Nairobi")
    assert [r["name"] for r in out] == ["yesterday"]


def test_next_page_follows_both_paging_styles():
    paged = {"page", "per_page"}
    assert next_page(paged, {"page": 1, "per_page": 2}, {"data": [{}, {}], "total_pages": 3, "page": 1}, 2, 2) == {"page": 2, "per_page": 2}
    assert next_page(paged, {"page": 3}, {"data": [{}], "total_pages": 3, "page": 3}, 5, 1) is None
    assert next_page(paged, {}, {"items": [{}, {}], "total": 2}, 2, 2) is None
    assert next_page(paged, {"per_page": 2}, [{}, {}], 2, 2) == {"per_page": 2, "page": 2}
    assert next_page(paged, {}, [{}, {}, {}], 3, 3) is None   # a bare list with no page size is everything
    offset = {"limit", "offset"}
    assert next_page(offset, {"limit": 2}, {"rows": [{}, {}], "has_more": True}, 2, 2) == {"limit": 2, "offset": 2}
    assert next_page(offset, {"limit": 2}, {"rows": [{}], "has_more": False}, 3, 1) is None
    assert next_page(offset, {"limit": 2}, [{}], 1, 1) is None
    assert next_page(set(), {}, {"data": [{}], "total_pages": 9}, 1, 1) is None


def test_joined_pages_keep_the_envelope():
    assert join_pages({"data": [{"a": 1}], "total": 3, "total_pages": 2, "page": 1}, [{"a": 1}, {"a": 2}, {"a": 3}]) ==         {"data": [{"a": 1}, {"a": 2}, {"a": 3}], "total": 3}
    assert join_pages([{"a": 1}], [{"a": 1}, {"a": 2}]) == [{"a": 1}, {"a": 2}]
