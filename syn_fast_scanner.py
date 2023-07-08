
import sys
from socket import socket, AF_INET, SOCK_STREAM
import time
import asyncio
from asyncio import Queue, TimeoutError, gather
from typing import List

import scapy.all as sc

from async_timeout import timeout


class SynFastScanner(object):
    def __init__(self, time_out = 0.1, ip_port = None, concurrency = 500):
        self.ip_port = ip_port
        self.result = []
        self.loop = self.get_event_loop()
        self.error = []
        # 队列的事件循环需要用同一个，如果不用同一个会报错，这里还有一点不明白
        self.queue = Queue(loop=self.loop)
        self.timeout = time_out
        # 并发数
        self.concurrency = concurrency

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

    async def scan(self):
        while True:
            t1 = time.time()
            ip_port = await self.queue.get()
            ip, port = ip_port
            #print(ip, port)
            sock = socket(AF_INET, SOCK_STREAM)
            sock.setblocking(False)
            try:
                with timeout(self.timeout):
                    # 这里windows和Linux返回值不一样
                    # windows返回sock对象，Linux返回None
                    await self.loop.sock_connect(sock, (ip, port))
                    t2 = time.time()
                    # 所以这里直接直接判断sock
                    if sock:
                        self.result.append((ip, port))
                        print(time.strftime('%Y-%m-%d %H:%M:%S'), ip, port, 'open', round(t2 - t1, 2))
            # we have to deal with the exception, otherwise it will stopp
            except:
                #self.error.append((ip, port))
                #print("exception")
                sock.close()
            sock.close()
            self.queue.task_done()
            #print("done")



    async def scan_by_send(self):
        while True:
            ip_port = await self.queue.get()
            ip, port = ip_port
            SYN_SCAN_SOURCE_PORT = 44444
            SYN_SCAN_SEQ_NUM = 44444
            host_ip = "192.168.38.129"
            syn_pkt = sc.IP(src=host_ip, dst=ip) / \
                sc.TCP(dport=port, sport=SYN_SCAN_SOURCE_PORT, flags="S", seq=SYN_SCAN_SEQ_NUM)
            sc.send(syn_pkt, iface=sc.conf.iface, verbose=0)
            self.queue.task_done()



    async def start(self):

        #start = time.time()
        # Add target to queue
        if self.ip_port:
            for a in self.ip_port:
                self.queue.put_nowait(a)
        else:
            for a in range(1, 65536):
                self.queue.put_nowait(a)
        task = [self.loop.create_task(self.scan()) for _ in range(self.concurrency)]
        # If the queue is not empty, it will always block here
        await self.queue.join()
        # Exit one by one
        for a in task:
            a.cancel()
        # Wait until all worker tasks are cancelled.
        await gather(*task, return_exceptions=True)
        #print(f'扫描所用时间为：{time.time() - start:.2f}')

if __name__ == '__main__':
    scan = SynFastScanner('127.0.0.1')
    scan.loop.run_until_complete(scan.start())