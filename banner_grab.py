import scapy.all as sc
import threading
import time
from datetime import datetime
import socket
import asyncio
from typing import List
import random
import string
import sys

import utils

class BannerGrab:

    def __init__(self, max_concurrency = 500):

        self.banner_grab_task_send_message = [
            self.generate_random_string(2), 
            self.generate_random_string(32), 
            self.generate_random_string(128), 
            self.generate_random_string(2048),
            b"GET / HTTP/1.1\r\n\r\n",
            b"HELO example.com\r\n",
            b"USER username\r\n",
            b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.1\r\n"
        ]

        self.max_concurrency = max_concurrency

        #存储结果
        self.result_collect = []


    #核心改了名和参数target，其他一点没动
    async def async_banner_grab_task(self, target, loop, timeout=3.0):
        banner_collect = []
        ip, port = target

        # STEP 1  Build TCP Connection
        try:
            # Create a socket object and connect to an IP  and Port.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            await asyncio.wait_for(
                loop.sock_connect(sock, (ip, port)), 
                timeout=3.0
            )
        except asyncio.TimeoutError:
            utils.log(f"[Banner Grab] IP {ip}, Port {port},  Timeout")
            print(f"[Banner Grab] IP {ip}, Port {port},  Timeout")
            return {"ip":ip, "port":port, "serive":"null", "banner":["connection build timeout"]}
        except OSError:
            utils.log(f"[Banner Grab] IP {ip}, Port {port},  Connection refused")
            print(f"[Banner Grab] IP {ip}, Port {port},  Connection refused")
            return {"ip":ip, "port":port, "serive":"null", "banner":["connection build refuse"]}
            

        # STEP 2  Wait for server to send banner
        # 诶，什么时候开始不给我报错说我异常没处理了
        try:     
            data = await asyncio.wait_for(
                asyncio.gather(
                    asyncio.sleep(2),
                    loop.sock_recv(sock, 1024),
                    return_exceptions=False,
                ), 
                timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError) as e:  
            print(f"[Banner Grab] IP {ip}, Port {port}, fail to get inital data")
            banner_collect.append((-1, "Grab Initial Error"))
        except Exception as e:
            print("[Banner Grab] Grab error:", str(e))
            banner_collect.append((-1, "Grab Initial Error"))
        else:
            if isinstance(data, List) and isinstance(data[1], bytes): # data[0]:result of asyncio.sleep(3)  data[1]:result of loop.sock_recv(sock, 1024)
                initial_data = data[1]
                utils.log(f"[Banner Grab] IP {ip}, Port {port}, Get Initial Data:\n {initial_data.decode('utf-8', errors='ignore').strip()}")
                print(f"[Banner Grab] IP {ip}, Port {port}, Get Initial Data:\n {initial_data.decode('utf-8', errors='ignore').strip()}")
                banner_collect.append((-1, initial_data.decode('utf-8', errors='ignore').strip()))
                #return {"ip":ip, "port":port, "serive":"null", "banner":initial_data.decode('utf-8', errors='ignore').strip()} # No need for take initiative to send data
            else:
                print("[Banner Grab] Get wrong inital data = ", data)
                banner_collect.append((-1, "Get wrong inital data"))


        # STEP 3  Send different bytes to server

        # 0704改动 原先只发一个HTTP GET，现在发多个。原先banner是一个字符串，现在改成返回列表。
        # 多次发送会不会导致连接失败的可能性上升？
        # 现在似乎就是太频繁了，导致往往只有前一两个成功

        grab_msg_list = self.banner_grab_task_send_message
        for i in range(0, len(grab_msg_list)):
            grab_msg = grab_msg_list[i]
            await asyncio.sleep(1.0)
            try:
                #await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=5) # bad idea, destory connections
                await asyncio.wait_for(loop.sock_sendall(sock, grab_msg), timeout=5)  
                banner = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=5) 
                utils.log(f"[Banner Grab] IP {ip}, Port {port}, Content:\n {banner.decode('utf-8', errors='ignore').strip()}")
                print(f"[Banner Grab] IP {ip}, Port {port}, Content:\n {banner.decode('utf-8', errors='ignore').strip()}")
                banner_collect.append((i, banner.decode('utf-8', errors='ignore').strip()))
            except asyncio.TimeoutError:
                utils.log(f"[Banner Grab] IP {ip}, Port {port}, Timeout Error")
                print(f"[Banner Grab] IP {ip}, Port {port}, Timeout Error")
                banner_collect.append((i, "Timeout Error"))
            except:
                utils.log(f"[Banner Grab] IP {ip}, Port {port},  Grab Error")
                print(f"[Banner Grab] IP {ip}, Port {port},  Grab Error")
                banner_collect.append((i, "Grab Error"))
            
        sock.close()
        return {"ip":ip, "port":port, "serive":"null", "banner":banner_collect}
    

    async def async_banner_grab_tasks(self, target_list, loop):

        # Create a list of coroutines for banner grabbing from the given IP and Port lists
        coroutines = []
        for i in range(0, len(target_list)): # here is one-to-one, not double loop!
            coro = self.async_banner_grab_task(target_list[i], loop)
            coroutines.append(coro)

        # Wait for all coroutines to complete and get the results
        results = await asyncio.gather(*coroutines, loop=loop)

        # Update the banner grab info for each IP and Port into _host_state.banner_grab_task_info.append
        self.result_collect += results
                
       
    def generate_random_string(self, length):
        letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
        return ''.join(random.choice(letters) for _ in range(length)).encode() # encode!

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

    def banner_grab(self, target_list):

            if(len(target_list) == 0):
                print("[Banner Grab] No target to grab")
                utils.log("[Banner Grab] No target to grab")
                return 

            if(len(target_list) > self.max_concurrency):
                print("[Banner Grab] Too much target")
                utils.log("[Banner Grab] Too much target")
                return 

            utils.log('[Banner Grab] Start Banner Grab on {} target {}'.format(
                len(target_list), 
                ', '.join(str(target) for target in target_list)
            ))
            print('[Banner Grab] Start Banner Grab on {} target {}'.format(
                len(target_list), 
                ', '.join(str(target) for target in target_list)
            ))

            loop = self.get_event_loop() #在banner里这个loop是每次运行才创建的…… 哦tcp扫描里是因为要用queue
            asyncio.set_event_loop(loop)
            
            loop.run_until_complete(self.async_banner_grab_tasks(target_list, loop))

            loop.close()

            print(self.result_collect)

            print("[Banner Grab] Done")
            utils.log("[Banner Grab] Done")


            #记录运行时间的被我给删了

    def getResult(self):
        return self.result_collect
            
    def clearResult(self):
        self.result_collect = []

if __name__ == "__main__":

    BannerGrabInst = BannerGrab()
    #BannerGrabInst.banner_grab(utils.getDannyIPandPorts())
    BannerGrabInst.banner_grab(utils.getNyuIPandPorts()[:500])

