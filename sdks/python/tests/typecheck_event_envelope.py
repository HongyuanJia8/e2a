"""Static contract checks for the public event-envelope constructors."""

from e2a.v1 import WebhookEvent, WSEvent


webhook_event = WebhookEvent(
    type="email.received",
    id="evt_1",
    schema_version="1",
    created_at="2026-07-01T10:30:00Z",
    data={},
)
ws_event = WSEvent(
    type="email.received",
    id="evt_1",
    schema_version="1",
    created_at="2026-07-01T10:30:00Z",
    data={},
)

# These ignores are intentional assertions: warn_unused_ignores makes mypy
# fail if the core fields ever become optional again.
WebhookEvent(type="email.received", data={})  # type: ignore[call-arg]
WSEvent(type="email.received", data={})  # type: ignore[call-arg]
