from tcp_scanner import TCPScanner
from banner_grab import BannerGrab
from ssdp_scanner import SSDPScanner
from dnssd_scanner import DNSSDScanner

import utils

TCPScannerInstance = TCPScanner()
TCPScannerInstance.scan(["192.168.38.129"], scanAll = False)
result = TCPScannerInstance.getResult()
print("############################ result of tcp scan: ")
print(result)

BannerGrabInst = BannerGrab()
BannerGrabInst.banner_grab([("192.168.38.129", 80)])
result = BannerGrabInst.getResult()
print("############################ result of banner grab: ")
print(result)

SSDPScannerInstance = SSDPScanner()
SSDPScannerInstance.scan()
SSDPScannerInstance.sniff(sniff_time = 10)
result = SSDPScannerInstance.getResult()
print("############################ result of ssdp scan: ")
print(result)

DNSSDScannerInstance = DNSSDScanner()
DNSSDScannerInstance.scan(["192.168.38.129"])
result = DNSSDScannerInstance.getResult()
print("############################ result of mdns scan: ")
print(result)