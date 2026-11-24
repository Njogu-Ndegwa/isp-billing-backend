"""BD-11: a reseller could not remove a plan's badge through the assistant.

The Update Plan card sent null for an emptied badge (which the API reads as "keep"), and a
card opened to change the badge kept Confirm off while the badge was empty.
"""
from __future__ import annotations

from app.services.assistant.catalog import apply_form_values, form_fields, get_catalog
from app.services.assistant.purpose import mark_purpose, purpose_problem

PLAN = {"name": "1 Day", "price": 42, "speed": "20M/20M", "badge_text": "Best",
        "duration_unit": "DAYS", "duration_value": 1}


def _update_plan():
    import main

    return get_catalog(main.app).get("PUT", "/api/plans/{plan_id}")


def _purpose_card(action, body):
    form = form_fields(action, body, PLAN)
    return next(f for f in mark_purpose(form, "badge_text", PLAN, True, None) if f["purpose"])


def test_an_emptied_badge_clears_it():
    action = _update_plan()
    for proposed in (None, ""):  # the assistant opened the card with either
        base = {"name": "1 Day", "price": 42, "badge_text": proposed}
        body, _, problems = apply_form_values(action, base, {"badge_text": ""}, PLAN)
        assert not problems
        assert body["badge_text"] == ""  # what PUT /api/plans/{id} reads as "no badge"


def test_a_card_opened_to_remove_the_badge_can_be_confirmed_empty():
    action = _update_plan()
    field = _purpose_card(action, {"badge_text": None})
    assert field["clears"] is True and field["original"] == "Best"
    assert purpose_problem(field, {"badge_text": ""}, {"badge_text": None}) is None
    assert purpose_problem(field, {"badge_text": "Best"}, {}) is not None  # unchanged is still refused


def test_only_fields_the_api_clears_may_be_left_empty():
    action = _update_plan()
    name = next(f for f in mark_purpose(form_fields(action, {}, PLAN), "name", PLAN, True, None) if f["purpose"])
    assert not name.get("clears")  # null keeps a plan's name: an empty name is not a change
    assert purpose_problem(name, {"name": ""}, {}) is not None
    # nothing to remove: an empty badge on a plan without one is still not ready
    bare = {**PLAN, "badge_text": None}
    form = form_fields(action, {}, bare)
    field = next(f for f in mark_purpose(form, "badge_text", bare, True, None) if f["purpose"])
    assert purpose_problem(field, {"badge_text": ""}, {}) is not None
