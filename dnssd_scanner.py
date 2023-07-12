#/usr/bin/python3
#!coding=utf-8

import socket
import sys
from scapy.all import raw, DNS, DNSQR
import utils
import time

import xml.etree.ElementTree as ET

class DNSSDScanner():

    def __init__(self):
        self.known_mdns_info_list = []

    def get_service_info(self, sock, target_ip, resp):
        service = (resp.an.rdata).decode()

        # query each service detail informations
        req = DNS(id=0x0001, rd=1, qd=DNSQR(qtype="PTR", qname=service))
        #req.show()

        try:
            sock.sendto(raw(req), (target_ip, 5353))
            data, _ = sock.recvfrom(1024)
            resp = DNS(data)
        except:
            self.known_mdns_info_list.append({"ip":target_ip, "scan_time":time.time(), "status":True, "services":['error']})
            return
        #resp.show()

        # parse additional records
        repeat = {}
        services = []
        for i in range(0, resp.arcount):
            rrname = (resp.ar[i].rrname).decode()
            rdata  = resp.ar[i].rdata

            if rrname in repeat:
                continue
            repeat[rrname] = rdata

            if hasattr(resp.ar[i], "port"):
                rrname += (" " + str(resp.ar[i].port))

            if rrname.find("._device-info._tcp.local.") > 0:
                print(" "*4, rrname, rdata)
            else:
                print(" "*4, rrname)
            services.append(rrname)
            
        self.known_mdns_info_list.append({"ip":target_ip, "scan_time":time.time(), "status":True, "services":services})
    # end get_service_info()

    # 这个就先不搞异步并发了
    def scan(self, target_ip_list): #只传ip不传端口，因为默认是5353
        print('[DNS-SD Scanning] Start')
        print('[DNS-SD Scanning] Scanning %d locations: %s' % (len(target_ip_list), target_ip_list))
        utils.log('[DNS-SD Scanning] Start')
        utils.log('[DNS-SD Scanning] Scanning %d locations: %s' % (len(target_ip_list), target_ip_list))
        for i in range(0, len(target_ip_list)):
            target_ip = target_ip_list[i]
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            # query all service name
            req = DNS(id=0x0001, rd=1, qd=DNSQR(qtype="PTR", qname="_services._dns-sd._udp.local")) #这里有效性可能待检验
            #req.show()

            try:
                sock.sendto(raw(req), (target_ip, 5353))
                data, _ = sock.recvfrom(1024)

                resp = DNS(data)
                #resp.show()

                print("[DNS-SD Scanning] No.%d %s ONLINE" % (i, target_ip))
                utils.log("[DNS-SD Scanning] No.%d %s ONLINE" % (i, target_ip))
                for i in range(0, resp.ancount):
                    self.get_service_info(sock, target_ip, resp) #在这里面再写known_mdns_info_list

            except KeyboardInterrupt:
                exit(0)
            except:
                print("[DNS-SD Scanning] No.%d %s OFFLINE" % (i, target_ip))
                utils.log("[DNS-SD Scanning] No.%d %s OFFLINE" % (i, target_ip))
                self.known_mdns_info_list.append({"ip":target_ip, "scan_time":time.time(), "status":False, "services":[]})

        print('[DNS-SD Scanning] Finish')
        utils.log('[DNS-SD Scanning] Finish')

    # end dnssd_scan()

def getIPs():

    IPs = []

    tree = ET.parse('scan_results.xml')
    root = tree.getroot()

    # 遍历每个host元素
    for host in root.findall('host'):
        # 获取address元素中的addr属性值
        address = host.find('address')
        ip_address = address.get('addr')
        
        # 打印IP地址
        IPs.append(ip_address)

    print(len(IPs))

    return IPs

def genIPs(IP):

    IPs = []
    base = IP.rstrip("0")

    for i in range(1,256):
        IPs.append(base+str(i))

    return IPs

if __name__ == "__main__":
    DNSSDScannerInstance = DNSSDScanner()
    target_ip_list = getIPs()
    DNSSDScannerInstance.scan(target_ip_list)
# end main()