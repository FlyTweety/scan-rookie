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

from async_timeout import timeout

class BannerGrab:

    def __init__(self):

        self.banner_grab_probes = [
            b'',
            b"GET / HTTP/1.1\r\n\r\n",
            b"HELO example.com\r\n",
            b"USER username\r\n",
            b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.1\r\n"
        ]

        self.result_collect = []



    """
    async def async_banner_grab_task(self, target, timeout=3.0):
        banner_collect = []
        ip, port = target

        # STEP 1  Build TCP Connection
        try:
            # Create a socket object and connect to an IP  and Port.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_connect(sock, (ip, port)), 
                timeout=3.0
            )
        except asyncio.TimeoutError:
            utils.log(f"[Banner Grab] IP {ip}, Port {port},  Timeout")
            print(f"[Banner Grab] IP {ip}, Port {port},  Timeout")
            return {"ip":ip, "port":port, "service":"null", "banner":[(-2, "connection build timeout")]}
        except OSError:
            utils.log(f"[Banner Grab] IP {ip}, Port {port},  Connection refused")
            print(f"[Banner Grab] IP {ip}, Port {port},  Connection refused")
            return {"ip":ip, "port":port, "service":"null", "banner":[(-2, "connection build refuse")]}
            

        # STEP 2  Wait for server to send banner
        try:     
            data = await asyncio.wait_for(
                asyncio.gather(
                    asyncio.sleep(3),
                    asyncio.get_running_loop().sock_recv(sock, 1024),
                    return_exceptions=False,
                ), 
                timeout=6.0)
        except (asyncio.TimeoutError, asyncio.CancelledError) as e:  #seems to be useless……
            print("[Banner Grab] fail to get inital data")
            banner_collect.append((-1, "Grab Initial Error"))
        except Exception as e:
            print("[Banner Grab] gather error:", str(e))
            banner_collect.append((-1, "Grab Initial Error"))
        else:
            if isinstance(data, List) and isinstance(data[1], bytes): # data[0]:result of asyncio.sleep(3)  data[1]:result of loop.sock_recv(sock, 1024)
                initial_data = data[1]
                utils.log(f"[Banner Grab] IP {ip}, Port {port}, Get Initial Data:\n {initial_data.decode('utf-8', errors='ignore').strip()}")
                print(f"[Banner Grab] IP {ip}, Port {port}, Get Initial Data:\n {initial_data.decode('utf-8', errors='ignore').strip()}")
                banner_collect.append((-1, initial_data.decode('utf-8', errors='ignore').strip()))
                #return {"ip":ip, "port":port, "service":"null", "banner":initial_data.decode('utf-8', errors='ignore').strip()} # No need for take initiative to send data
            else:
                print("[Banner Grab] get wrong inital data = ", data)
                banner_collect.append((-1, "Grab Initial Error"))


        # STEP 3  Send different bytes to server

        # 多次频繁发送容易导致失败

        grab_msg_list = [self.generate_random_string(2), self.generate_random_string(32), self.generate_random_string(128), self.generate_random_string(2048)] + self.banner_grab_probes
        for i in range(0, len(grab_msg_list)):
            grab_msg = grab_msg_list[i]
            await asyncio.sleep(1.0)
            try:
                #await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=5) bad idea
                await asyncio.wait_for(asyncio.get_running_loop().sock_sendall(sock, grab_msg), timeout=5)  
                banner = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(sock, 1024), timeout=5) 
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
        return {"ip":ip, "port":port, "service":"null", "banner":banner_collect}
    
    
    async def async_banner_grab_tasks(self, target_list):

        # Create a list of coroutines for banner grabbing from the given IP and Port lists
        coroutines = []
        for i in range(0, len(target_list)): # here is one-to-one, not double loop!
            coro = self.async_banner_grab_task(target_list[i])
            coroutines.append(coro)

        # Wait for all coroutines to complete and get the results
        results = await asyncio.gather(*coroutines)

        # Update the banner grab info for each IP and Port into _host_state.banner_grab_task_info.append
        self.result_collect += results
    """

    async def async_banner_grab_task(self, ip, port, probe_msg, sem, timeout_value=5.0):
        async with sem:
            try:
                # 设置整个get_banner函数的超时时间默认为5秒
                async with timeout(timeout_value):
                    
                    reader, writer = await asyncio.open_connection(ip, port)
                    if probe_msg != "":
                        writer.write(probe_msg)
                        await writer.drain()
                    
                    banner = await reader.read(1024)
                    
                    print(f"[Banner Grab] IP {ip}, Port {port}: {banner.decode()}")
                    writer.close()

                    return banner.decode()
            
            except asyncio.TimeoutError as e:
                print(f"[Banner Grab] IP {ip}, Port {port}: time_out") 
                return f"{type(e).__name__}"

            except Exception as e:
                print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} - {str(e)}")
                return f"{type(e).__name__}"


    async def async_banner_grab_tasks(self, target_ip_port_list):

        sem = asyncio.Semaphore(300)
    
        for ip_port in target_ip_port_list:
            ip, port = ip_port
            self.result_collect.append({"ip":ip, "port":port, "service":"null", "banner":[]})
        
        #轮次还是在这里控制。以端口为单位建立任务

        #Round 1: NULL probe
        tasks = []
        for i in range(0, len(target_ip_port_list)): # here is one-to-one, not double loop!
            ip, port = target_ip_port_list[i]
            task = self.async_banner_grab_task(ip, port, "", sem)
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        for i in range(0, len(results)):
            self.result_collect[i]['banner'].append(results[i])

        #await asyncio.sleep(3)

        #Round 2: random string probe
        random_probe_list = [self.generate_random_string(2), self.generate_random_string(32), self.generate_random_string(128), self.generate_random_string(2048)]
        for random_probe in random_probe_list:
            
            tasks = []
            for i in range(0, len(target_ip_port_list)): # here is one-to-one, not double loop!
                ip, port = target_ip_port_list[i]
                task = self.async_banner_grab_task(ip, port, random_probe, sem)
                tasks.append(task)

            results = await asyncio.gather(*tasks)

            for i in range(0, len(results)):
                self.result_collect[i]['banner'].append(results[i])

            #await asyncio.sleep(3)
        
        for probe in self.banner_grab_probes:
            tasks = []
            for i in range(0, len(target_ip_port_list)): # here is one-to-one, not double loop!
                ip, port = target_ip_port_list[i]
                task = self.async_banner_grab_task(ip, port, probe, sem)
                tasks.append(task)

            results = await asyncio.gather(*tasks)

            for i in range(0, len(results)):
                self.result_collect[i]['banner'].append(results[i])


    def generate_random_string(self, length):
        letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
        return ''.join(random.choice(letters) for _ in range(length)).encode()

    def banner_grab(self, target_ip_port_list):

        if(len(target_ip_port_list) == 0):
            print("[Banner Grab] No target to grab")
            utils.log("[Banner Grab] No target to grab")
            return 

        utils.log('[Banner Grab] Start Banner Grab on {} target {}'.format(
            len(target_ip_port_list), 
            ', '.join(str(target) for target in target_ip_port_list)
        ))
        print('[Banner Grab] Start Banner Grab on {} target {}'.format(
            len(target_ip_port_list), 
            ', '.join(str(target) for target in target_ip_port_list)
        ))        
    
        if sys.version_info.major == 3 and sys.version_info.minor >= 7:
            asyncio.run(self.async_banner_grab_tasks(target_ip_port_list))

        else:
            loop = asyncio.get_event_loop()
            asyncio.set_event_loop(loop)
            asyncio.get_event_loop().run_until_complete(self.async_banner_grab_tasks(target_ip_port_list))
            loop.close()

        print("[Banner Grab] Done")
        utils.log("[Banner Grab] Done")
    

    def getResult(self):
        return self.result_collect
            
    def clearResult(self):
        self.result_collect = []

if __name__ == "__main__":

    BannerGrabInst = BannerGrab()
    BannerGrabInst.banner_grab(utils.getDannyIPandPorts())
    results = BannerGrabInst.getResult()
    print(results)

