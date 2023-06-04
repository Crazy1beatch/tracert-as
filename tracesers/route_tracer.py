import socket

from typing import List

from structs.icmp_package import IcmpPackage
from structs.whois_data_record import WhoisDataRecord
from tracesers.whois_tracer import WhoisTracer


class Traceroute:
    def __init__(self, host: str, max_ttl: int):
        self._host = socket.gethostbyname(host)
        self.max_ttl = max_ttl
        self.current_ttl = 1
        self.whois_tracer = WhoisTracer()

    def make_trace(self) -> List[WhoisDataRecord]:
        result = []
        while self.current_ttl <= self.max_ttl:
            sender_sock, receiver_sock = self.get_new_sockets()
            icmp_pack = IcmpPackage(8, 0)
            sender_sock.sendto(bytes(icmp_pack), (self._host, 80))
            try:
                data, address = receiver_sock.recvfrom(1024)
            except (socket.timeout, socket.gaierror):
                result.append(None)
                self.current_ttl += 1
                continue
            trace_node = self.whois_tracer.get_whois_data(address[0])
            result.append(trace_node)
            received_icmp = IcmpPackage.from_bytes(data[20:])
            if self.check_icmp(received_icmp):
                sender_sock.close()
                receiver_sock.close()
                break
            self.current_ttl += 1
            sender_sock.close()
            receiver_sock.close()
        return result

    @staticmethod
    def check_icmp(icmp: IcmpPackage) -> bool:
        if icmp.type == icmp.code == 0:
            return True
        return False

    def get_new_sockets(self) -> (socket.socket, socket.socket):
        send_sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM,
                                  socket.IPPROTO_ICMP)
        send_sock.setsockopt(socket.SOL_IP,
                             socket.IP_TTL,
                             self.current_ttl)
        recv_sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_RAW,
                                  socket.IPPROTO_ICMP)
        recv_sock.settimeout(2)
        return send_sock, recv_sock