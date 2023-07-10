import re
import sys
import time
import base64
import struct
import socket
import requests
import xml.etree.ElementTree as ET
import utils

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

#现在能正常工作，但不知道该把哪些记到log里

class SSDPInfo():

    def __init__(self):

        self.scan_time = None

        self.location = None
        self.ip = None
        self.port = None
        self.outer_file_name = None

        self.server_string = None
        self.device_type = None
        self.friendly_name = None
        self.manufacturer = None
        self.manufacturer_url = None
        self.model_description = None
        self.model_name = None
        self.model_number = None

        self.services_list = []


class SSDPScanner():

    def __init__(self):
        self.known_ssdp_info_list = []
        #要把ip-port-具体服务串起来 要把这个代码给我列出的各种属性都放一起
        #具体的服务就不管了
        #find-mapping这个就不管了

    ###
    # Send a multicast message tell all the pnp services that we are looking
    # For them. Keep listening for responses until we hit a 3 second timeout (yes,
    # this could technically cause an infinite loop). Parse the URL out of the
    # 'location' field in the HTTP header and store for later analysis.
    #
    # @return the set of advertised upnp locations, and IPs
    ###
    def discover_pnp_locations(self):
        print('[SSDP Scanning] Discovering UPnP locations')
        utils.log('[SSDP Scanning] Discovering UPnP locations')
        locations = set() # 自动避免了重复
        ip_ports = set()
        location_regex = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)
        ip_port_regex = r"http://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)"
        ssdpDiscover = ('M-SEARCH * HTTP/1.1\r\n' +
                        'HOST: 239.255.255.250:1900\r\n' +
                        'MAN: "ssdp:discover"\r\n' +
                        'MX: 1\r\n' +
                        'ST: ssdp:all\r\n' +
                        '\r\n')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(ssdpDiscover.encode('ASCII'), ("239.255.255.250", 1900))
        sock.settimeout(5)
        try:
            while True:
                data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
                #print(data, addr)
                location_result = location_regex.search(data.decode('ASCII'))
                if location_result and (location_result.group(1) in locations) == False:
                    locations.add(location_result.group(1))

                    match = re.search(ip_port_regex, location_result.group(1))
                    ip = match.group(1)
                    port = match.group(2)       
                    ip_port = ip + "_" + port
                    ip_ports.add(ip_port)

        except socket.error:
            sock.close()

        print('[SSDP Scanning] Discovery complete')
        print('[SSDP Scanning] %d locations found:' % len(locations))
        utils.log('[SSDP Scanning] %d locations found:' % len(locations))
        return list(locations), list(ip_ports)

    ##
    # Tries to print an element extracted from the XML.
    # @param xml the xml tree we are working on
    # @param xml_name the name of the node we want to pull text from
    # @param print_name the name we want to appear in stdout
    ##
    def print_attribute(self, xml, xml_name, print_name):
        try:
            temp = xml.find(xml_name).text
            print('\t-> %s: %s' % (print_name, temp))
            return temp
        except AttributeError:
            return None

    ###
    # Loads the XML at each location and prints out the API along with some other
    # interesting data.
    #
    # @param locations a collection of URLs
    # @return igd_ctr (the control address) and igd_service (the service type)
    ###
    def parse_locations(self, locations):
        if len(locations) < 1:
            print('[SSDP Scanning] No location to parse')
            utils.log('[SSDP Scanning] No location to parse')
            return
        if len(locations) > 0:
            print('[SSDP Scanning] Start parse %d locations:' % len(locations))
            utils.log('[SSDP Scanning] Start parse %d locations:' % len(locations))
            for location in locations:
                print('[SSDP Scanning] Loading %s...' % location)
                ssdp_info = SSDPInfo()
                try:
                    resp = requests.get(location, timeout=3)
                    #能运行到这里说明获取到回复了
                    ssdp_info.scan_time = time.time()
                    ssdp_info.location = location
                    match = re.search(r"http://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)/(.*)", location)
                    ssdp_info.ip = match.group(1)
                    ssdp_info.port = match.group(2)
                    ssdp_info.outer_file_name = match.group(3) 

                    if resp.headers.get('server'):
                        server_string = resp.headers.get('server')
                        print('\t-> Server String: %s' % server_string)
                        ssdp_info.server_string = server_string
                    else:
                        print('\t-> No server string')

                    parsed = urlparse(location)

                    print('\t==== XML Attributes ===')
                    try:
                        xmlRoot = ET.fromstring(resp.text)
                    except:
                        print('\t[SSDP Scanning] Failed XML parsing of %s' % location)
                        continue

                    ssdp_info.device_type = self.print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}deviceType", "Device Type")
                    ssdp_info.device_type = self.print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}friendlyName", "Friendly Name")
                    ssdp_info.manufacturer = self.print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}manufacturer", "Manufacturer")
                    ssdp_info.manufacturer_url = self.print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}manufacturerURL", "Manufacturer URL")
                    ssdp_info.model_description = self.print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}modelDescription", "Model Description")
                    ssdp_info.model_name = self.print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}modelName", "Model Name")
                    ssdp_info.model_number = self.print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}modelNumber", "Model Number")

                    print('\t-> Services:')
                    services = xmlRoot.findall(".//*{urn:schemas-upnp-org:device-1-0}serviceList/")
                    for service in services:
                        service_type = service.find('./{urn:schemas-upnp-org:device-1-0}serviceType').text
                        control = service.find('./{urn:schemas-upnp-org:device-1-0}controlURL').text
                        events = service.find('./{urn:schemas-upnp-org:device-1-0}eventSubURL').text
                        print('\t\t=> Service Type: %s' % service_type)
                        print('\t\t=> Control: %s' % control)
                        print('\t\t=> Events: %s' % events)

                        this_service = {"service_url":None, "service_type":service_type, "control":control, "events":events, "actions":[]}

                        # Add a lead in '/' if it doesn't exist
                        scp = service.find('./{urn:schemas-upnp-org:device-1-0}SCPDURL').text
                        if scp[0] != '/':
                            scp = '/' + scp
                        serviceURL = parsed.scheme + "://" + parsed.netloc + scp
                        print('\t\t=> API: %s' % serviceURL)

                        this_service['service_url'] = serviceURL

                        # read in the SCP XML
                        resp = requests.get(serviceURL, timeout=2)
                        try:
                            serviceXML = ET.fromstring(resp.text)
                        except:
                            print('\t\t\t[!] Failed to parse the response XML')
                            continue

                        actions = serviceXML.findall(".//*{urn:schemas-upnp-org:service-1-0}action")
                        for action in actions:
                            action_name = action.find('./{urn:schemas-upnp-org:service-1-0}name').text
                            print('\t\t\t- ' + action_name)
                            this_service["actions"].append(action_name)
                        
                        ssdp_info.services_list.append(this_service)

                except requests.exceptions.ConnectionError:
                    print('[SSDP Scanning] Could not load %s' % location)
                except requests.exceptions.ReadTimeout:
                    print('[SSDP Scanning] Timeout reading from %s' % location)

                self.known_ssdp_info_list.append(ssdp_info) #应该就是一堆字符串，不会占太多空间吧
            print("[SSDP Scanning] Done Parsing")
            utils.log("[SSDP Scanning] Done Parsing")
        return

    def scan(self):
        print("[SSDP Scanning] Start.")
        locations, ip_ports = self.discover_pnp_locations()
        self.parse_locations(locations)
        print("[SSDP Scanning] Finish.")

    def getResult(self):
        for ssdp_info in self.known_ssdp_info_list:
            print(ssdp_info.location)

if __name__ == "__main__":
    SSDPScannerInstance = SSDPScanner()
    SSDPScannerInstance.scan()