import sys
from socket import socket, AF_INET, SOCK_STREAM
import time
import asyncio
from asyncio import Queue, TimeoutError, gather
from typing import List
import random


import scapy.all as sc

from async_timeout import timeout

import utils

class TCPScanner():

    def __init__(self, time_out = 5.0, concurrency = 500):

        self.result = []
        self.error = []

        self.timeout = time_out
        self.concurrency = concurrency
        
        self.result_collect = []

    async def scan_task(self):
        while True:
            t1 = time.time()
            ip_port = await self.queue.get()
            ip, port = ip_port
            #print(ip, port)
            sock = socket(AF_INET, SOCK_STREAM)
            #sock.setblocking(False) #有时能大幅加速，有时不能
            try:
                if sys.version_info.major == 3 and sys.version_info.minor >= 7:
                    async with timeout(self.timeout):
                        # 这里windows和Linux返回值不一样
                        # windows返回sock对象，Linux返回None
                        await asyncio.get_event_loop().sock_connect(sock, (ip, port))
                        t2 = time.time()
                        # 所以这里直接直接判断sock
                        if sock:
                            self.result_collect.append((ip, port))
                            print(time.strftime('%Y-%m-%d %H:%M:%S'), ip, port, 'open', round(t2 - t1, 2))
                else:
                    with timeout(self.timeout):
                        await asyncio.get_event_loop().sock_connect(sock, (ip, port))
                        t2 = time.time()
                        if sock:
                            self.result_collect.append((ip, port))
                            print(time.strftime('%Y-%m-%d %H:%M:%S'), ip, port, 'open', round(t2 - t1, 2))
            # we have to deal with the exception, otherwise it will stopp
            except:
                #self.error.append((ip, port))
                #print("exception")
                sock.close()
            sock.close()
            self.queue.task_done()
            #print("done")

    async def async_scan_tasks(self, target_ip, target_port_list):

        self.queue = Queue()
        #print("new queue")

        for port in target_port_list:
            self.queue.put_nowait((target_ip, port))

        tasks = [asyncio.get_event_loop().create_task(self.scan_task()) for _ in range(self.concurrency)]
        # If the queue is not empty, it will always block here
        await self.queue.join()
        # Exit one by one
        for task in tasks:
            task.cancel()
        # Wait until all worker tasks are cancelled.
        await gather(*tasks, return_exceptions=True)

    def scan(self, target_ip_list, scanAll = False):
        

        if len(target_ip_list) == 0:
            print("[TCP Scanning] No target to scan")
            utils.log("[TCP Scanning] No target to scan")
            return
        
        print('[TCP Scanning] Start scanning {} IPs: {}'.format(
            len(target_ip_list),
            ', '.join(target_ip_list)
        ))
        utils.log('[TCP Scanning] Start scanning {} IPs: {}'.format(
            len(target_ip_list),
            ', '.join(target_ip_list)
        ))

        if scanAll == True:
            print("[TCP Scanning] Scan 65K ports")
            utils.log("[TCP Scanning] Scan 65K ports")
        else:
            print("[TCP Scanning] Scan popular ports")
            utils.log("[TCP Scanning] Scan popular ports")

        if scanAll == True:
            all_port_list = [i for i in range(1, 65536)]
            split_ip_port_list = utils.split_array(all_port_list, 5000) #python垃圾回收机制会自动处理all_port_list？
        else:
            split_ip_port_list = [utils.get_port_list()]

        for ip in target_ip_list:
            print("[TCP Scanning] Start scan on ip =", ip)
            
    
            for batch_port_list in split_ip_port_list:

                random.shuffle(batch_port_list)
                
                last_one = batch_port_list[-1]
                start_time = time.time()

                if sys.version_info.major == 3 and sys.version_info.minor >= 7:
                    asyncio.run(self.async_scan_tasks(ip, batch_port_list))
                else:
                    asyncio.get_event_loop().run_until_complete(self.async_scan_tasks(ip, batch_port_list))
                
                print("Last one of this batch:", ip, str(last_one))
                print(f'Time for this batch: {time.time() - start_time:.2f}')

    def getResult(self):
        return self.result_collect
            
    def clearResult(self):
        self.result_collect = []

if __name__ == '__main__':
    TCPScannerInstance = TCPScanner()
    TCPScannerInstance.scan(["127.0.0.1"], scanAll = True)
