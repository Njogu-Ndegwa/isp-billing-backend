from app.services.messaging.segments import count_segments


def test_empty_message_is_one_segment():
    assert count_segments("") == 1


def test_short_gsm7_is_one_segment():
    assert count_segments("Hello there") == 1


def test_gsm7_160_boundary():
    assert count_segments("a" * 160) == 1
    assert count_segments("a" * 161) == 2
    assert count_segments("a" * 306) == 2
    assert count_segments("a" * 307) == 3


def test_unicode_uses_70_67_boundaries():
    assert count_segments("\U0001F642") == 1            # 🙂 single emoji
    # an emoji is two UTF-16 units: 71 of them are 142 units -> 3 parts of 67
    assert count_segments("\U0001F642" * 71) == 3


def test_ucs2_boundaries_with_one_non_gsm_character():
    # one smart quote turns a plain message into UCS-2: 70 single, 67 per part after
    assert count_segments("’" + "a" * 69) == 1
    assert count_segments("’" + "a" * 70) == 2
    assert count_segments("’" + "a" * 133) == 2
    assert count_segments("’" + "a" * 134) == 3


def test_emoji_counts_two_units_against_the_70():
    assert count_segments("\U0001F4E2" + "a" * 68) == 1   # 2 + 68 = 70
    assert count_segments("\U0001F4E2" + "a" * 69) == 2   # 71


def test_a_message_that_fits_gsm7_but_not_with_a_smart_quote():
    plain = "Hello, your internet time ends today. Buy again to stay online. Thank you - KENJOE"
    assert count_segments(plain) == 1
    assert count_segments((plain + " ") * 2) == 2              # 166 chars of GSM-7
    assert count_segments(plain.replace("'", "") + " don’t") == 2  # 88 chars, UCS-2


def test_encoding_and_the_characters_that_force_ucs2():
    from app.services.messaging.segments import encoding, non_gsm_characters

    assert encoding("Habari! Lipa kwa M-Pesa.") == "GSM-7"
    assert encoding("don’t") == "UCS-2"
    assert non_gsm_characters("“Hi” ⚡📢📢") == ["“", "”", "⚡", "📢"]
    assert non_gsm_characters("plain") == []


def test_gsm7_extension_char_counts_double():
    assert count_segments("€" * 80) == 1           # € weight 2 -> 160 -> single
    assert count_segments("€" * 81) == 2
