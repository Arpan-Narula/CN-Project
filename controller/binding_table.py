import time
import threading


def _norm(mac):
    return mac.lower() if isinstance(mac, str) else mac


class Lease(object):
    __slots__ = ("ip", "mac", "port", "expiry")

    def __init__(self, ip, mac, port, expiry):
        self.ip = ip
        self.mac = _norm(mac)
        self.port = port
        self.expiry = expiry

    def is_expired(self, now=None):
        now = now if now is not None else time.time()
        return now >= self.expiry

    def __repr__(self):
        return "Lease(ip=%s, mac=%s, port=%s, expiry=%.0f)" % (
            self.ip, self.mac, self.port, self.expiry
        )


class BindingTable(object):
    def __init__(self, default_lease_seconds=3600, quarantine_seconds=60):
        self._leases = {}
        self._quarantine = {}
        self._lock = threading.Lock()
        self.default_lease_seconds = default_lease_seconds
        self.quarantine_seconds = quarantine_seconds

    def add_lease(self, ip, mac, port, lease_seconds=None):
        lease_seconds = lease_seconds or self.default_lease_seconds
        expiry = time.time() + lease_seconds
        lease = Lease(ip, mac, port, expiry)
        with self._lock:
            self._leases[ip] = lease
        return lease

    def get_lease(self, ip):
        with self._lock:
            return self._leases.get(ip)

    def find_by_mac(self, mac):
        mac = _norm(mac)
        with self._lock:
            return [l for l in self._leases.values()
                    if l.mac == mac and not l.is_expired()]

    def verify_packet(self, ip, mac, port):
        with self._lock:
            lease = self._leases.get(ip)
            if lease is None:
                return False
            if lease.is_expired():
                del self._leases[ip]
                return False
            if lease.mac != _norm(mac):
                return False
            if lease.port is None:
                # first legitimate sighting pins the port
                lease.port = port
                return True
            return lease.port == port

    def quarantine(self, mac, port, seconds=None):
        seconds = seconds or self.quarantine_seconds
        mac = _norm(mac)
        with self._lock:
            self._quarantine[(mac, port)] = time.time() + seconds

    def is_quarantined(self, mac, port):
        mac = _norm(mac)
        with self._lock:
            expiry = self._quarantine.get((mac, port))
            if expiry is None:
                return False
            if time.time() >= expiry:
                del self._quarantine[(mac, port)]
                return False
            return True

    def remove_expired(self):
        now = time.time()
        removed = []
        with self._lock:
            for ip in list(self._leases.keys()):
                if self._leases[ip].is_expired(now):
                    removed.append(self._leases.pop(ip))
            for key in list(self._quarantine.keys()):
                if now >= self._quarantine[key]:
                    del self._quarantine[key]
        return removed

    def dump(self):
        with self._lock:
            return {ip: (l.mac, l.port, l.expiry) for ip, l in self._leases.items()}


if __name__ == "__main__":
    bt = BindingTable(default_lease_seconds=2, quarantine_seconds=1)
    bt.add_lease("10.0.0.1", "00:00:00:00:00:01", 1)
    assert bt.verify_packet("10.0.0.1", "00:00:00:00:00:01", 1) is True
    assert bt.verify_packet("10.0.0.1", "AA:AA:AA:AA:AA:AA", 1) is False
    assert bt.verify_packet("10.0.0.1", "00:00:00:00:00:01", 99) is False
    assert bt.verify_packet("10.0.0.99", "00:00:00:00:00:01", 1) is False
    bt.quarantine("AA:AA:AA:AA:AA:AA", 3)
    assert bt.is_quarantined("AA:AA:AA:AA:AA:AA", 3) is True
    assert bt.verify_packet("10.0.0.1", "00:00:00:00:00:01".upper(), 1) is True
    bt.add_lease("10.0.0.2", "00:00:00:00:00:02", None)
    assert bt.verify_packet("10.0.0.2", "00:00:00:00:00:02", 2) is True
    assert bt.verify_packet("10.0.0.2", "00:00:00:00:00:02", 3) is False
    assert len(bt.find_by_mac("00:00:00:00:00:02")) == 1
    time.sleep(2.1)
    assert bt.verify_packet("10.0.0.1", "00:00:00:00:00:01", 1) is False
    assert len(bt.remove_expired()) >= 1
    print("All binding_table.py smoke tests passed.")
    print("Current table:", bt.dump())
