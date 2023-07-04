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
                time.sleep(5)
                continue

            # [Step 3] Get target Port List 
            if not self._scanAllPorts:
                target_port_list = get_port_list()   # Scan Popular ports on target IPs First
                utils.log('[SYN Scanning] Start scanning {} popular ports over IPs: {}'.format(
                    len(target_port_list),
                    ', '.join(target_ip_list)
                ))
            else:
                target_port_list = list(range(1, 65536)) # Scan All ports on target IPs 
                utils.log('[SYN Scanning] Start scanning All 65K popular over IPs: {}'.format(
                    ', '.join(target_ip_list)
                ))

            # [Step 4] Assemble the final IP & port list
            ip_port_list = list(itertools.product(target_ip_list, target_port_list))
            #random.shuffle(ip_port_list)

            # Main Scan Process
            result = []
            split_ip_port_list = self.split_array(ip_port_list, 5000)
            for batch_ip_port_list in split_ip_port_list:
                start = time.time()
                batch_result = []
                

                """
                scanner = SynFastScanner(time_out = 3.0, ip_port = batch_ip_port_list, concurrency = 300)
                scanner.loop.run_until_complete(scanner.start())
                batch_result = scanner.result
                #print(batch_result)
                result += (batch_result)
                del scanner
                """

                host_ip = "192.168.38.129"
                for ip_port in batch_ip_port_list:
                    ip, port = ip_port
                    syn_pkt = sc.IP(src=host_ip, dst=ip) / \
                        sc.TCP(dport=port, sport=SYN_SCAN_SOURCE_PORT, flags="S", seq=SYN_SCAN_SEQ_NUM)
                    sc.send(syn_pkt, iface=sc.conf.iface, verbose=0)
                print("本批最后一个是", batch_ip_port_list[-1])
                print(f'本批扫描所用时间为：{time.time() - start:.2f}')
                for ip, port in batch_result:
                    self._host_state.received_ip_port_info.append({"ip": ip, "port": port, "info": "null"})
                    utils.log("[SYN Scanning] Find Open on ip =", ip, " port =", port)
                    print("[SYN Scanning] Find Open on ip =", ip, " port =", port)

            #现在这个不会被包捕获，所以要自己写结果到hoststate

        
            print("[SYN Scanning] Done Scan For this Round")
            utils.log("[SYN Scanning] Done Scan For this Round")
            for ip in target_ip_list:
                self._host_state.last_syn_scan_time[ip] = datetime.now()

    def split_array(self, array, chunk_size):
        result = []
        for i in range(0, len(array), chunk_size):
            result.append(array[i:i+chunk_size])
        return result

    def stop(self):

        with self._lock:
            self._active = False

        self._thread.join()

        utils.log('[SYN Scanning] Stopped.')
