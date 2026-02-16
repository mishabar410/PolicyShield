from policyshield.shield.ring_buffer import EventRingBuffer


def test_add_and_retrieve():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    buf.add("write_file", "block")
    assert len(buf) == 2
    assert buf.events[0].tool == "read_file"
    assert buf.events[1].tool == "write_file"


def test_max_size():
    buf = EventRingBuffer(max_size=3)
    for i in range(5):
        buf.add(f"tool_{i}", "allow")
    assert len(buf) == 3
    assert buf.events[0].tool == "tool_2"  # Oldest kept
    assert buf.events[2].tool == "tool_4"  # Newest


def test_find_recent_by_tool():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    buf.add("write_file", "block")
    buf.add("read_file", "allow")

    results = buf.find_recent("read_file")
    assert len(results) == 2


def test_find_recent_by_verdict():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    buf.add("read_file", "block")

    results = buf.find_recent("read_file", verdict="block")
    assert len(results) == 1


def test_has_recent_within_seconds():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    assert buf.has_recent("read_file", within_seconds=5)
    assert not buf.has_recent("write_file", within_seconds=5)


def test_clear():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    buf.clear()
    assert len(buf) == 0


def test_args_truncation():
    buf = EventRingBuffer(max_size=10)
    buf.add("tool", "allow", args_summary="x" * 500)
    assert len(buf.events[0].args_summary) == 200
