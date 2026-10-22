import pytest

from ids.live_normalizer import preserve_native_severity


@pytest.mark.parametrize(
    ("native_value", "expected"),
    [
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        ("2", 2),
        (None, 4),
        ("", 4),
        ("not-a-number", 4),
    ],
)
def test_native_severity_is_not_remapped(native_value, expected):
    assert preserve_native_severity(native_value) == expected
