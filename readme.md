
### About

This project consists of four separate functional modules:

* `tcp_scanner.py`

Used for TCP scanning on a specified IP. It utilizes asynchronous non-blocking sockets to complete scanning of 65k ports on the target IP in a relatively short period of time.

* `banner_grab.py`

Used for grabbing banners from a specified IP and port. It also uses asynchronous non-blocking sockets to efficiently grab banners from multiple target ports in a short time.

* `ssdp_scanner.py`

Used for SSDP scanning on devices within the current broadcast domain. It sends requests to the SSDP multicast address, receives and further parses service messages from other devices in response. Additionally, it can passively listen to messages on the SSDP multicast address.

* `dnssd_scanner.py`

Used for mDNS service discovery on a specified IP. It sends DNS-SD requests to port 5353 on the target IP, discovers and parses the received reply messages.

In addition, `utils.py` provides necessary support, such as logging, for running the modules. `Main.py` integrates the testing functionality.

These modules do not include any code or software outside of Python. They are designed to be simple and easy to use, with the main purpose of allowing people to easily integrate them into other projects. They were primarily developed for the new version of iot-inspector-client.

### Install

Make sure you have python3 on your device, and run `pip install -r requirements.txt`

```
requests
scapy
async_timeout
```

### TCPScanner

Based on the design in https://zhuanlan.zhihu.com/p/162710825

**Usage**

```
TCPScannerInstance = TCPScanner()
TCPScannerInstance.scan(ip_list, scanAll = False)
result = TCPScannerInstance.getResult()
```

**APIs**

* scan

Run tcp scans on target IPs.

| Args           |      |              |                                      |        |
| -------------- | ---- | ------------ | ------------------------------------ | ------ |
| name           | type | if necessary | example                              | notice |
| self           |      |              |                                      |        |
| target_ip_list | list | yes          | [“192.168.87.1”, “192.168.87.2”] |        |
| scanAll        | bool | no           | scanAll = True                       |        |

* getResult

Fetch the result from the previous scan

| **Args** |      |              |         |        |
| -------------- | ---- | ------------ | ------- | ------ |
| name           | type | if necessary | example | notice |
| self           |      |              |         |        |

| Return Values       |      |                                                    |
| ------------------- | ---- | -------------------------------------------------- |
| name                | type | example                                            |
| self.result_collect | list | [(“192.168.87.1”, 80), (“192.168.87.1”, 8080)] |

* clearResult

Delete the previous scan result

| Args |      |              |         |        |
| ---- | ---- | ------------ | ------- | ------ |
| name | type | if necessary | example | notice |
| self |      |              |         |        |

---

### BannerGrab

**Usage**

```
BannerGrabInstance = BannerGrab()
BannerGrabInstance.banner_grab(ip_port_list)
result = BannerGrabInstance.getResult()
```

**APIs**

Run banner grab on target IP and ports.

| Args        |                  |              |                                                    |              |
| ----------- | ---------------- | ------------ | -------------------------------------------------- | ------------ |
| name        | type             | if necessary | example                                            | notice       |
| self        |                  |              |                                                    |              |
| target_list | list[(str, int)] | yes          | [(“192.168.87.1”, 80), (“192.168.87.1”, 8080)] | length < 500 |

- getResult

Fetch the result from the previous banner grab

| Return Values       |                                                                           |                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| name                | type                                                                      | example                                                                                                                       |
| self.result_collect | list[dict{'ip': str, 'port': int, 'service': str, 'banner': [(int, str)]}] | [{'ip': '192.168.38.129', 'port': 80, 'service': 'null', 'banner': [(-1, “error”), (0, “bad request”), (1, “timeout”)]}] |

- clearResult

Delete the previous result

| Args |      |              |         |        |
| ---- | ---- | ------------ | ------- | ------ |
| name | type | if necessary | example | notice |
| self |      |              |         |        |

---

### SSDPScanner

Based on the code from https://github.com/tenable/upnp_info and https://paper.seebug.org/1727/#0x03-ssdp

**Usage**

```
SSDPScannerInstance = SSDPScanner()
SSDPScannerInstance.scan()
SSDPScannerInstance.sniff(sniff_time = 10)
result = SSDPScannerInstance.getResult()
```

**APIs**

- scan

Run SSDP scan in the multicast range

| Args |      |              |         |        |
| ---- | ---- | ------------ | ------- | ------ |
| name | type | if necessary | example | notice |
| self |      |              |         |        |

- sniff

Listen SSDP Notify broadcast. Some system does not support this.

| Args       |       |              |                 |        |
| ---------- | ----- | ------------ | --------------- | ------ |
| name       | type  | if necessary | example         | notice |
| self       |       |              |                 |        |
| sniff_time | float | no           | sniff_time = 10 |        |

- getResult

Fetch the result from the previous scan & sniff

| Args |      |              |         |        |
| ---- | ---- | ------------ | ------- | ------ |
| name | type | if necessary | example | notice |
| self |      |              |         |        |

| Return Values       |                       |         |
| ------------------- | --------------------- | ------- |
| name                | type                  | example |
| self.result_collect | list[class(SSDPInfo)] |         |

- clearResult

Delete the previous result

| Args |      |              |         |        |
| ---- | ---- | ------------ | ------- | ------ |
| name | type | if necessary | example | notice |
| self |      |              |         |        |

---

### DNSSDScanner

Based on the code from: https://paper.seebug.org/1727/#0x02-dns-sd

**Usage**

```
DNSSDScannerInstance = DNSSDScanner()
DNSSDScannerInstance.scan(ip_list)
result = DNSSDScannerInstance.getResult()
```

**APIs**

- scan

Run DNS-SD scans on target IPs.

| Args           |      |              |                                      |        |
| -------------- | ---- | ------------ | ------------------------------------ | ------ |
| name           | type | if necessary | example                              | notice |
| self           |      |              |                                      |        |
| target_ip_list | list | yes          | [“192.168.87.1”, “192.168.87.2”] |        |

- getResult

Fetch the result from the previous scan

| Args |      |              |         |        |
| ---- | ---- | ------------ | ------- | ------ |
| name | type | if necessary | example | notice |
| self |      |              |         |        |

| Return Values       |                                                                                   |                                                                                                                                                             |
| ------------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| name                | type                                                                              | example                                                                                                                                                     |
| self.result_collect | list[dict{"ip":str, "scan_time":time.time(), "status":bool, "services":list[str}] | [{'ip': '192.168.87.48', 'scan_time': 1689693429.229996, 'status': True, 'services': ['Philips Hue - 9BF262._hue._tcp.local. 443', 'ecb5fa9bf262.local.']}] |

- clearResult

Delete the previous scan result

| Args |      |              |         |        |
| ---- | ---- | ------------ | ------- | ------ |
| name | type | if necessary | example | notice |
| self |      |              |         |        |
