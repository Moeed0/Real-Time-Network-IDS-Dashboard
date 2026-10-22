from ids.community_id import community_id


def test_tcp_community_id_is_direction_independent():
    forward = community_id(
        "192.168.50.141",
        54230,
        "192.168.50.114",
        80,
        "TCP",
    )

    reverse = community_id(
        "192.168.50.114",
        80,
        "192.168.50.141",
        54230,
        "TCP",
    )

    assert forward == reverse
    assert forward.startswith("1:")


def test_same_flow_is_stable():
    first = community_id(
        "192.168.50.141",
        53186,
        "192.168.50.114",
        445,
        "TCP",
    )

    second = community_id(
        "192.168.50.141",
        53186,
        "192.168.50.114",
        445,
        "TCP",
    )

    assert first == second


def test_different_flow_changes_id():
    first = community_id(
        "192.168.50.141",
        53186,
        "192.168.50.114",
        445,
        "TCP",
    )

    second = community_id(
        "192.168.50.141",
        53187,
        "192.168.50.114",
        445,
        "TCP",
    )

    assert first != second
