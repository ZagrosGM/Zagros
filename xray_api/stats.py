import typing
from dataclasses import dataclass

import grpc
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

from .base import XRayBase
from .exceptions import RelatedError
from .proto.app.stats.command import command_pb2, command_pb2_grpc


def _online_response_types():
    """Build the two newer Xray online-stat responses at runtime.

    Zagros' generated stubs predate Xray's online-IP RPCs.  Their request is
    still the existing ``GetStatsRequest`` and the wire response is tiny, so a
    local descriptor keeps compatibility with protobuf 4.x through 7.x without
    regenerating the entire vendored Xray schema for every upstream release.
    """
    schema = descriptor_pb2.FileDescriptorProto(
        name="zagros_xray_online_compat.proto", package="zagros.xray.compat",
        syntax="proto3")

    all_users = schema.message_type.add()
    all_users.name = "GetAllOnlineUsersResponse"
    field = all_users.field.add()
    field.name, field.number, field.label, field.type = (
        "users", 1, field.LABEL_REPEATED, field.TYPE_STRING)

    ip_list = schema.message_type.add()
    ip_list.name = "GetStatsOnlineIpListResponse"
    field = ip_list.field.add()
    field.name, field.number, field.label, field.type = (
        "name", 1, field.LABEL_OPTIONAL, field.TYPE_STRING)
    entry = ip_list.nested_type.add()
    entry.name = "IpsEntry"
    entry.options.map_entry = True
    key = entry.field.add()
    key.name, key.number, key.label, key.type = (
        "key", 1, key.LABEL_OPTIONAL, key.TYPE_STRING)
    value = entry.field.add()
    value.name, value.number, value.label, value.type = (
        "value", 2, value.LABEL_OPTIONAL, value.TYPE_INT64)
    field = ip_list.field.add()
    field.name, field.number, field.label, field.type = (
        "ips", 2, field.LABEL_REPEATED, field.TYPE_MESSAGE)
    field.type_name = ".zagros.xray.compat.GetStatsOnlineIpListResponse.IpsEntry"

    pool = descriptor_pool.DescriptorPool()
    pool.Add(schema)

    def message(name):
        descriptor = pool.FindMessageTypeByName(f"zagros.xray.compat.{name}")
        getter = getattr(message_factory, "GetMessageClass", None)
        if getter is not None:
            return getter(descriptor)
        return message_factory.MessageFactory(pool).GetPrototype(descriptor)

    return (message("GetAllOnlineUsersResponse"),
            message("GetStatsOnlineIpListResponse"))


_GetAllOnlineUsersResponse, _GetStatsOnlineIpListResponse = _online_response_types()


@dataclass
class SysStatsResponse:
    num_goroutine: int
    num_gc: int
    alloc: int
    total_alloc: int
    sys: int
    mallocs: int
    frees: int
    live_objects: int
    pause_total_ns: int
    uptime: int


@dataclass
class StatResponse:
    name: str
    type: str
    link: str
    value: int


@dataclass
class UserStatsResponse:
    email: str
    uplink: int
    downlink: int


@dataclass
class InboundStatsResponse:
    tag: str
    uplink: int
    downlink: int


@dataclass
class OutboundStatsResponse:
    tag: str
    uplink: int
    downlink: int


class Stats(XRayBase):
    def get_sys_stats(self, timeout: int = None) -> SysStatsResponse:
        try:
            stub = command_pb2_grpc.StatsServiceStub(self._channel)
            r = stub.GetSysStats(command_pb2.SysStatsRequest(), timeout=timeout)

        except grpc.RpcError as e:
            raise RelatedError(e)

        return SysStatsResponse(
            num_goroutine=r.NumGoroutine,
            num_gc=r.NumGC,
            alloc=r.Alloc,
            total_alloc=r.TotalAlloc,
            sys=r.Sys,
            mallocs=r.Mallocs,
            frees=r.Frees,
            live_objects=r.LiveObjects,
            pause_total_ns=r.PauseTotalNs,
            uptime=r.Uptime
        )

    def query_stats(self, pattern: str, reset: bool = False, timeout: int = None) -> typing.Iterable[StatResponse]:
        try:
            stub = command_pb2_grpc.StatsServiceStub(self._channel)
            r = stub.QueryStats(command_pb2.QueryStatsRequest(pattern=pattern, reset=reset), timeout=timeout)

        except grpc.RpcError as e:
            raise RelatedError(e)

        for stat in r.stat:
            type, name, _, link = stat.name.split('>>>')
            yield StatResponse(name, type, link, stat.value)

    def get_users_stats(self, reset: bool = False, timeout: int = None) -> typing.Iterable[StatResponse]:
        return self.query_stats("user>>>", reset=reset, timeout=timeout)

    def get_all_online_users(self, timeout: int = None) -> list[str]:
        """Emails Xray currently tracks as online (Xray >= 25).

        The request message is empty on the wire.  A raw unary call is used so
        old generated stubs can talk to newer Xray binaries without replacing
        unrelated protocol descriptors.
        """
        call = self._channel.unary_unary(
            "/xray.app.stats.command.StatsService/GetAllOnlineUsers",
            request_serializer=lambda _request: b"",
            response_deserializer=_GetAllOnlineUsersResponse.FromString,
        )
        try:
            response = call(None, timeout=timeout)
        except grpc.RpcError as exc:
            raise RelatedError(exc)

        # Despite the RPC name, Xray's manager returns OnlineMap identifiers,
        # not bare emails: ``user>>>{email}>>>online``. Normalize that exact
        # wire value here. Some transitional builds returned the email itself,
        # so retain a conservative passthrough for values without delimiters.
        emails: list[str] = []
        for raw in response.users:
            identity = str(raw or "")
            parts = identity.split(">>>")
            if len(parts) == 3 and parts[0] == "user" and parts[2] == "online":
                identity = parts[1]
            if identity:
                emails.append(identity)
        return emails

    def get_stats_online_ip_list(
        self, email: str, timeout: int = None,
    ) -> dict[str, int]:
        """Active source IPs and their last-seen timestamps for one email."""
        call = self._channel.unary_unary(
            "/xray.app.stats.command.StatsService/GetStatsOnlineIpList",
            request_serializer=command_pb2.GetStatsRequest.SerializeToString,
            response_deserializer=_GetStatsOnlineIpListResponse.FromString,
        )
        request = command_pb2.GetStatsRequest(
            name=f"user>>>{email}>>>online", reset=False)
        try:
            response = call(request, timeout=timeout)
        except grpc.RpcError as exc:
            raise RelatedError(exc)
        return {str(ip): int(last_seen) for ip, last_seen in response.ips.items()
                if ip}

    def get_online_ip_details(self, timeout: int = None) -> dict[str, dict[str, int]]:
        """Current ``email -> {source IP: native last-seen timestamp}`` map."""
        try:
            emails = self.get_all_online_users(timeout=timeout)
        except RelatedError:
            emails = sorted({
                row.name for row in self.get_users_stats(
                    reset=False, timeout=timeout)
                if row.type == "user" and row.link in {"uplink", "downlink"}
            })
        result: dict[str, dict[str, int]] = {}
        for email in emails:
            ips = self.get_stats_online_ip_list(email, timeout=timeout)
            if ips:
                result[email] = ips
        return result

    def get_online_ips(self, timeout: int = None) -> dict[str, set[str]]:
        """One current ``email -> source IPs`` snapshot.

        New Xray releases provide a cheap online-user list followed by one
        local gRPC lookup per online user.  If that list RPC is unavailable,
        traffic-stat emails provide a backward-compatible candidate set; an
        unsupported online-IP RPC is surfaced to the backend, which retains
        its old traffic-delta fallback.
        """
        return {email: set(ips) for email, ips in
                self.get_online_ip_details(timeout=timeout).items()}

    def get_inbounds_stats(self, reset: bool = False, timeout: int = None) -> typing.Iterable[StatResponse]:
        return self.query_stats("inbound>>>", reset=reset, timeout=timeout)

    def get_outbounds_stats(self, reset: bool = False, timeout: int = None) -> typing.Iterable[StatResponse]:
        return self.query_stats("outbound>>>", reset=reset, timeout=timeout)

    def get_user_stats(self, email: str, reset: bool = False, timeout: int = None) -> typing.Iterable[StatResponse]:
        uplink, downlink = 0, 0
        for stat in self.query_stats(f"user>>>{email}>>>", reset=reset, timeout=timeout):
            if stat.link == 'uplink':
                uplink = stat.value
            if stat.link == 'downlink':
                downlink = stat.value

        return UserStatsResponse(email=email, uplink=uplink, downlink=downlink)

    def get_inbound_stats(self, tag: str, reset: bool = False, timeout: int = None) -> typing.Iterable[StatResponse]:
        uplink, downlink = 0, 0
        for stat in self.query_stats(f"inbound>>>{tag}>>>", reset=reset, timeout=timeout):
            if stat.link == 'uplink':
                uplink = stat.value
            if stat.link == 'downlink':
                downlink = stat.value
        return InboundStatsResponse(tag=tag, uplink=uplink, downlink=downlink)

    def get_outbound_stats(self, tag: str, reset: bool = False, timeout: int = None) -> typing.Iterable[StatResponse]:
        uplink, downlink = 0, 0
        for stat in self.query_stats(f"outbound>>>{tag}>>>", reset=reset, timeout=timeout):
            if stat.link == 'uplink':
                uplink = stat.value
            if stat.link == 'downlink':
                downlink = stat.value
        return OutboundStatsResponse(tag=tag, uplink=uplink, downlink=downlink)
