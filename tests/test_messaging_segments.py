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
    assert count_segments("\U0001F642" * 71) == 2       # forces UCS-2, >70 -> multipart


def test_gsm7_extension_char_counts_double():
    assert count_segments("€" * 80) == 1           # € weight 2 -> 160 -> single
    assert count_segments("€" * 81) == 2
