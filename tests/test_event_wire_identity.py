import pytest

from instrlib.event import Event
from instrlib.schema import Schema


@pytest.mark.parametrize("content", ["123", "001", "1e3", "NaN", "inf", "-42"])
def test_numeric_looking_message_keeps_string_type_on_monitor_wire(content):
    schema = Schema()
    schema.add("Message", [int, str, str, int])
    event = Event("Message", 1, "user", content, 1)
    schema.validate(event)
    assert str(event) == f'Message(1, "user", "{content}", 1)'


def test_hash_collision_does_not_make_distinct_events_equal():
    class CollisionEvent(Event):
        def __hash__(self):
            return 1

    assert CollisionEvent("Allow", 1) != CollisionEvent("Block", 1)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_numeric_event_argument_is_rejected(value):
    with pytest.raises(ValueError, match="finite"):
        str(Event("Measurement", value))
