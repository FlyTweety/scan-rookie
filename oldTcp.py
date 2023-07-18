
import sys
from socket import socket, AF_INET, SOCK_STREAM
import time
import asyncio
from asyncio import Queue, TimeoutError, gather
from typing import List

import scapy.all as sc

from async_timeout import timeout

import utils

class TCPScanner():

    def __init__(self, time_out = 5.0, concurrency = 500):
        self.loop = self.get_event_loop()
        self.result = []
        self.error = []
        # 队列的事件循环需要用同一个，如果不用同一个会报错，这里还有一点不明白
        self.queue = Queue(loop=self.loop)
        self.timeout = time_out
        # 并发数
        self.concurrency = concurrency
        
        #存储结果
        self.result_collect = []
        
    
    def __del__(self):
        self.loop.close()

    @staticmethod
    def get_event_loop():
        """
        判断不同平台使用不同的事件循环实现

        :return:
        """
        if sys.platform == 'win32':
            from asyncio import ProactorEventLoop
            # 用 "I/O Completion Ports" (I O C P) 构建的专为Windows 的事件循环
            return ProactorEventLoop()
        else:
            from asyncio import SelectorEventLoop
            return SelectorEventLoop()

    async def scan_task(self):
        while True:
            t1 = time.time()
            ip_port = await self.queue.get()
            ip, port = ip_port
            #print(ip, port)
            sock = socket(AF_INET, SOCK_STREAM)
            #sock.setblocking(False)
            try:
                with timeout(self.timeout):
                    # 这里windows和Linux返回值不一样
                    # windows返回sock对象，Linux返回None
                    await self.loop.sock_connect(sock, (ip, port))
                    t2 = time.time()
                    # 所以这里直接直接判断sock
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

        #start = time.time()
        # Add target to queue
        for port in target_port_list:
            self.queue.put_nowait((target_ip, port))

        tasks = [self.loop.create_task(self.scan_task()) for _ in range(self.concurrency)]
        # If the queue is not empty, it will always block here
        await self.queue.join()
        # Exit one by one
        for task in tasks:
            task.cancel()
        # Wait until all worker tasks are cancelled.
        await gather(*tasks, return_exceptions=True)
        #print(f'扫描所用时间为：{time.time() - start:.2f}')

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

        #一下把所有ip传进去感觉有点难控制，要不逐个ip来操作
        #那现在怎么做到5000输出以下

        if scanAll == True:
            all_port_list = [i for i in range(1, 65536)]
            split_ip_port_list = utils.split_array(all_port_list, 5000) #python垃圾回收机制会自动处理all_port_list？
        else:
            split_ip_port_list = [utils.get_port_list()]

        for ip in target_ip_list:
            print("[TCP Scanning] Start scan on ip =", ip)
            
    
            for batch_port_list in split_ip_port_list:

                start_time = time.time()
                self.loop.run_until_complete(self.async_scan_tasks(ip, batch_port_list))
                print("本批最后一个是", ip, str(batch_port_list[-1]))
                print(f'本批扫描所用时间为：{time.time() - start_time:.2f}')

    def getResult(self):
        return self.result_collect
            
    def clearResult(self):
        self.result_collect = []

if __name__ == '__main__':
    TCPScannerInstance = TCPScanner()
    TCPScannerInstance.scan(["127.0.0.1"], scanAll = True)
    #TCPScannerInstance.scan(utils.getDannyIPs(), scanAll = True)