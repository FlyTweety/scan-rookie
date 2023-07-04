# Original Copy; See Change in things_I_modified.txt

"""
Global shared state about the host.

"""
import sys

import threading
import time

import utils


class HostState:

    def __init__(self):

        ##### These are new
        self.received_ip_port_info = [] # info received from syn scan. Every entry is {ip:xx, port:xx, info:xx} info is useless for now
        self.last_syn_scan_time = {} # ip->time
        self.banner_grab_info = [] # every entry is {ip:xx, port:xx, serive:xx, banner:xx}  banner_info is the banner we get
        self.last_banner_grab_time = {} # ip_port->time
        self.known_ip_list = [
            '192.168.87.1',
            '192.168.87.20',
            '192.168.87.22',
            '192.168.87.26',
            '192.168.87.27',
            '192.168.87.29',
            '192.168.87.30',
            '192.168.87.31',
            '192.168.87.32',
            '192.168.87.35',
            '192.168.87.36',
            '192.168.87.46',
            '192.168.87.47',
            '192.168.87.48',
            '192.168.87.49',
            '192.168.87.73',
            '192.168.87.75',
            '192.168.87.76'
        ]
        self.known_ip_list = ["192.168.38.1"]
        
        self.known_ip_list = ["127.0.0.1"]
        self.known_ip_list = ["192.168.0.14","192.168.0.10","192.168.0.11","192.168.0.1","192.168.0.2"]
        self.known_ip_list = ["192.168.0.14"]
        self.known_ip_list = ["10.181.250.245"]
        #self.known_ip_list = ["192.168.0.14", "127.0.0.1"]




        ##### This were copied, they are used in test framework
        self.host_ip = None
        self.host_mac = None
        self.lock = threading.Lock()
        self.quit = False

    def is_inspecting(self):
        return True
