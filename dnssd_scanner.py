import socket
import sys
from scapy.all import raw, DNS, DNSQR
import utils
import time

import xml.etree.ElementTree as ET

class DNSSDScanner():

    def __init__(self):
        self.result_collect = []

    def get_service_info(self, sock, target_ip, service):
        

        # query each service detail informations
        req = DNS(id=0x0001, rd=1, qd=DNSQR(qtype="PTR", qname=service))
        #req.show()

        try:
            sock.sendto(raw(req), (target_ip, 5353))
            data, _ = sock.recvfrom(1024)
            resp = DNS(data)
        except:
            return []
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

        return services
    # end get_service_info()

    # no concurrent operations here
    def scan(self, target_ip_list): # we don't need to specify port here, because we know mDNS uses 5353

        print('[DNS-SD Scanning] Start')
        print('[DNS-SD Scanning] Scanning %d locations: %s' % (len(target_ip_list), target_ip_list))
        utils.log('[DNS-SD Scanning] Start')
        utils.log('[DNS-SD Scanning] Scanning %d locations: %s' % (len(target_ip_list), target_ip_list))

        for i in range(0, len(target_ip_list)):
            target_ip = target_ip_list[i]
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)

            # query all service name
            req = DNS(id=0x0001, rd=1, qd=DNSQR(qtype="PTR", qname="_services._dns-sd._udp.local")) 
            #req.show()

            try:
                sock.sendto(raw(req), (target_ip, 5353))
                data, _ = sock.recvfrom(1024)

                resp = DNS(data)
                #resp.show()

                print("[DNS-SD Scanning] No.%d %s ONLINE" % (i, target_ip))
                utils.log("[DNS-SD Scanning] No.%d %s ONLINE" % (i, target_ip))

                services = []
                for i in range(0, resp.ancount):
                    service = (resp.an[i].rdata).decode()
                    this_services = self.get_service_info(sock, target_ip, service)
                    services.append(this_services)
                self.result_collect.append({"ip":target_ip, "scan_time":time.time(), "status":"ONLINE", "services":services})


            except KeyboardInterrupt:
                exit(0)
            except:
                print("[DNS-SD Scanning] No.%d %s OFFLINE" % (i, target_ip))
                utils.log("[DNS-SD Scanning] No.%d %s OFFLINE" % (i, target_ip))
                self.result_collect.append({"ip":target_ip, "scan_time":time.time(), "status":"OFFLINE", "services":[]})

        print('[DNS-SD Scanning] Finish')
        utils.log('[DNS-SD Scanning] Finish')

    # end dnssd_scan()

    def getResult(self):
        return self.result_collect
    
    def clearResult(self):
        self.result_collect = []

def genIPs(IP):

    IPs = []
    base = IP.rstrip("0")

    for i in range(1,256):
        IPs.append(base+str(i))

    return IPs

if __name__ == "__main__":
    DNSSDScannerInstance = DNSSDScanner()
    target_ip_list = genIPs("192.168.87.0")
    #DNSSDScannerInstance.scan(target_ip_list)
    DNSSDScannerInstance.scan(['192.168.87.48'])
    print(DNSSDScannerInstance.getResult())
# end main()