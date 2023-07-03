"""
Continuously sends out SYN packets.

"""
import itertools
import random
import scapy.all as sc
import threading
import time
import asyncio
import async_timeout
from async_timeout import timeout
from asyncio import Queue, TimeoutError, gather
from socket import socket, AF_INET, SOCK_STREAM
import sys

##### ↓ Add Line: Used to compute time difference between last scan time
from datetime import datetime 

from host_state import HostState
from parse_available_ports import get_port_list
import utils

from syn_fast_scanner import SynFastScanner

SYN_SCAN_SOURCE_PORT = 44444
SYN_SCAN_SEQ_NUM = 44444


class SynScan(object):

    ##### ↓ Add new arg "scanAllPorts": Decide if we need scan 65k ports
    def __init__(self, host_state, scanAllPorts = False): 

        assert isinstance(host_state, HostState)
        self._host_state = host_state

        self._lock = threading.Lock()
        self._active = False

        self._thread = threading.Thread(target=self._syn_scan_thread)
        self._thread.daemon = True

        ##### ↓ Add Line
        self._scanAllPorts = scanAllPorts

    def start(self):

        with self._lock:
            self._active = True

        utils.log('[SYN Scanning] Starting.')
        self._thread.start()

    def _syn_scan_thread(self):

        utils.restart_upon_crash(self._syn_scan_thread_helper)

    def _syn_scan_thread_helper(self):

        while True:

            time.sleep(1)

            if not self._host_state.is_inspecting():
                continue

            ##### This is Original Part of preparing target ip & port
            """ 

            # Build a random list of (ip, port).
            port_list = get_port_list()
            ip_list = self._host_state.ip_mac_dict.keys()
            ip_port_list = list(itertools.product(ip_list, port_list))
            random.shuffle(ip_port_list)

            if len(ip_list) == 0:
                continue

            utils.log('[SYN Scanning] Start scanning {} ports over IPs: {}'.format(
                len(port_list),
                ', '.join(ip_list)
            ))
            """

            ##### This is my solution for preparing target ip & port

            # [Step 1] Get known IP list
            # This would have been obtained from the host_state( from arp scan)
            # For now we directly assign IPs we already known
            ip_list = self._host_state.known_ip_list

            # [Step 2] Get target IP list for this round ( remove those IPs we have scanned within 60 seconds) 
            target_ip_list = []
            for ip in ip_list:
                if ip in self._host_state.last_syn_scan_time:
                    time_difference = datetime.now()-self._host_state.last_syn_scan_time[ip]
                    if time_difference.total_seconds() < 60:  # next scan must after 60s
                        print("[SYN Scanning] give up too frequent TCP-SYN scan on ip = ", ip)
                        utils.log("[SYN Scanning] give up too frequent TCP-SYN scan on ip = ", ip)
                        continue
                target_ip_list.append(ip)

            if len(target_ip_list) == 0:
                time.sleep(2)
                continue

            # [Step 3] Get target Port List 
            if not self._scanAllPorts:
                target_port_list = get_port_list()   # Scan Popular ports on target IPs First
                utils.log('[SYN Scanning] Start scanning {} popular ports over IPs: {}'.format(
                    len(target_port_list),
                    ', '.join(target_ip_list)
                ))
            else:
                target_port_list = list(range(1, 65000)) # Scan All ports on target IPs 
                utils.log('[SYN Scanning] Start scanning All 65K popular over IPs: {}'.format(
                    ', '.join(target_ip_list)
                ))

            # [Step 4] Assemble the final IP & port list
            ip_port_list = list(itertools.product(target_ip_list, target_port_list))
            random.shuffle(ip_port_list)

            # Main Scan Process
            scanner = SynFastScanner(ip_port = ip_port_list)
            scanner.loop.run_until_complete(scanner.start())
            result = scanner.result
            print(result)
            del scanner

            #现在这个不会被包捕获，所以要自己写结果到hoststate
            for ip, port in result:
                self._host_state.received_ip_port_info.append({"ip": ip, "port": port, "info": "null"})
                utils.log("[SYN Scanning] Find Open on ip = ", ip, " port = ", port)
                print("[SYN Scanning] Find Open on ip = ", ip, " port = ", port)

            print("[SYN Scanning] Done Scan For this Round")
            utils.log("[SYN Scanning] Done Scan For this Round")
            for ip in target_ip_list:
                self._host_state.last_syn_scan_time[ip] = datetime.now()

    def stop(self):

        with self._lock:
            self._active = False

        self._thread.join()

        utils.log('[SYN Scanning] Stopped.')
