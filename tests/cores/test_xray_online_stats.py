"""Wire-compatibility tests for Xray's newer online-IP statistics RPCs."""
from __future__ import annotations

from xray_api.proto.app.stats.command import command_pb2
from xray_api.stats import (
    Stats,
    _GetAllOnlineUsersResponse,
    _GetStatsOnlineIpListResponse,
)


class _RawChannel:
    def __init__(self):
        self.calls: list[tuple[str, bytes, int | None]] = []

    def unary_unary(self, path, request_serializer, response_deserializer):
        def invoke(request, timeout=None):
            payload = request_serializer(request)
            self.calls.append((path, payload, timeout))
            if path.endswith("/GetAllOnlineUsers"):
                # Xray returns OnlineMap names here, despite the RPC's
                # user-oriented name. The adapter must strip this envelope.
                raw = _GetAllOnlineUsersResponse(
                    users=["user>>>1.alice>>>online",
                           "user>>>2.bob>>>online", ""]
                ).SerializeToString()
            else:
                parsed = command_pb2.GetStatsRequest.FromString(payload)
                assert parsed.name == "user>>>1.alice>>>online"
                assert parsed.reset is False
                raw = _GetStatsOnlineIpListResponse(
                    name=parsed.name,
                    ips={"203.0.113.5": 1700000000,
                         "198.51.100.8": 1700000001},
                ).SerializeToString()
            return response_deserializer(raw)
        return invoke


def _stats(channel: _RawChannel) -> Stats:
    client = object.__new__(Stats)
    client._channel = channel  # noqa: SLF001 - isolated wire-level test
    return client


def test_dynamic_online_protobuf_round_trips_users_and_ip_map() -> None:
    channel = _RawChannel()
    stats = _stats(channel)

    assert stats.get_all_online_users(timeout=7) == ["1.alice", "2.bob"]
    assert stats.get_stats_online_ip_list("1.alice", timeout=9) == {
        "203.0.113.5": 1700000000,
        "198.51.100.8": 1700000001,
    }
    assert channel.calls[0] == (
        "/xray.app.stats.command.StatsService/GetAllOnlineUsers", b"", 7)
    assert channel.calls[1][0].endswith("/GetStatsOnlineIpList")
    assert channel.calls[1][2] == 9


def test_online_snapshot_returns_distinct_source_ip_sets() -> None:
    channel = _RawChannel()
    stats = _stats(channel)
    # Restrict the fake online list so the request assertion remains exact.
    stats.get_all_online_users = lambda timeout=None: ["1.alice"]
    assert stats.get_online_ips(timeout=5) == {
        "1.alice": {"203.0.113.5", "198.51.100.8"}
    }
