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

    def __init__(self):

        self.banner_grab_task_send_message = [
            b"GET / HTTP/1.1\r\n\r\n",
            b"HELO example.com\r\n",
            b"USER username\r\n",
            b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.1\r\n",
            b"\r\n\r\n",
            b"GET / HTTP/1.0\r\n\r\n",
            b"HELP\r\n"

            """
            # copy from nmap rarity<=4 TCP Probe
            b"OPTIONS / HTTP/1.0\r\n\r\n",
            b"OPTIONS / RTSP/1.0\r\n\r\n",
            b"\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"\0\x1E\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03",
            b"\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0",
            b"\x16\x03\0\0\x69\x01\0\0\x65\x03\x03U\x1c\xa7\xe4random1random2random3random4\0\0\x0c\0/\0\x0a\0\x13\x009\0\x04\0\xff\x01\0\0\x30\0\x0d\0,\0*\0\x01\0\x03\0\x02\x06\x01\x06\x03\x06\x02\x02\x01\x02\x03\x02\x02\x03\x01\x03\x03\x03\x02\x04\x01\x04\x03\x04\x02\x01\x01\x01\x03\x01\x02\x05\x01\x05\x03\x05\x02",
            b"\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0",
            b"\x6C\0\x0B\0\0\0\0\0\0\0\0\0",
            """
        ]

        self.result_collect = []

    async def async_banner_grab_task(self, target, timeout=3.0):
        banner_collect = []
        ip, port = target

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)

        # STEP 1  Build TCP Connection
        try:
            # Create a socket object and connect to an IP  and Port.
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_connect(sock, (ip, port)), 
                timeout=3.0
            )
        except Exception as e:
            if isinstance(e, ConnectionResetError) or isinstance(e, BrokenPipeError):
                try:
                    await asyncio.sleep(3.0)
                    await asyncio.wait_for(
                        asyncio.get_running_loop().sock_connect(sock, (ip, port)), 
                        timeout=3.0
                    )
                    print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} reconnect success")
                    utils.log(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__}  reconnect success")
                except:
                    print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} - {str(e)}")
                    utils.log(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} - {str(e)}")
                    return {"ip":ip, "port":port, "serive":"null", "banner":[(-2, f"{type(e).__name__}")]}
            else:
                print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} - {str(e)}")
                utils.log(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} - {str(e)}")
                return {"ip":ip, "port":port, "serive":"null", "banner":[(-2, f"{type(e).__name__}")]}


        # STEP 2  Wait for server to send banner
        try:     
            data = await asyncio.wait_for(
                asyncio.get_running_loop().sock_recv(sock, 1024), 
                timeout=5.0
            )
        except Exception as e:
            if isinstance(e, ConnectionResetError) or isinstance(e, BrokenPipeError):
                try:
                    await asyncio.sleep(3.0)
                    await asyncio.wait_for(
                        asyncio.get_running_loop().sock_connect(sock, (ip, port)), 
                        timeout=3.0
                    )
                    print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} reconnect success")
                    utils.log(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__}  reconnect success")
                    banner_collect.append((-1, f"{type(e).__name__} reconnect success"))
                except:
                    print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} reconnect fail")
                    utils.log(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} reconnect fail")
                    banner_collect.append((-1, f"{type(e).__name__} reconnect fail"))
            else:
                print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} - {str(e)}")
                utils.log(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} - {str(e)}")
                banner_collect.append((-1, f"{type(e).__name__}"))
        else:
            if isinstance(data, bytes): # data[0]:result of asyncio.sleep(3)  data[1]:result of loop.sock_recv(sock, 1024)
                initial_data = data
                utils.log(f"[Banner Grab] IP {ip}, Port {port}, Get Initial Data:\n {initial_data.decode('utf-8', errors='ignore') }")
                print(f"[Banner Grab] IP {ip}, Port {port}, Get Initial Data:\n {initial_data.decode('utf-8', errors='ignore') }")
                banner_collect.append((-1, initial_data.decode('utf-8', errors='ignore') ))
                #return {"ip":ip, "port":port, "serive":"null", "banner":initial_data.decode('utf-8', errors='ignore') } # No need for take initiative to send data
            else:
                print(f"[Banner Grab] IP {ip}, Port {port}, get wrong inital data = {data}")
                banner_collect.append((-1, "Wrong Initial Data"))


        # STEP 3  Send different bytes to server

        grab_msg_list = [self.generate_random_string(2), self.generate_random_string(32), self.generate_random_string(128), self.generate_random_string(2048)] + self.banner_grab_task_send_message
        for i in range(0, len(grab_msg_list)):
            grab_msg = grab_msg_list[i]
            await asyncio.sleep(1.0)
            try:
                #await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=5) bad idea
                await asyncio.wait_for(asyncio.get_running_loop().sock_sendall(sock, grab_msg), timeout=5)  
                banner = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(sock, 1024), timeout=5) 
                utils.log(f"[Banner Grab] IP {ip}, Port {port}, Content:\n {banner.decode('utf-8', errors='ignore') }")
                print(f"[Banner Grab] IP {ip}, Port {port}, Content:\n {banner.decode('utf-8', errors='ignore') }")
                banner_collect.append((i, banner.decode('utf-8', errors='ignore') ))
            except Exception as e:
                if isinstance(e, ConnectionResetError) or isinstance(e, BrokenPipeError):
                    try:
                        await asyncio.sleep(3.0)
                        await asyncio.wait_for(
                            asyncio.get_running_loop().sock_connect(sock, (ip, port)), 
                            timeout=3.0
                        )
                        print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} reconnect success")
                        utils.log(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__}  reconnect success")
                        banner_collect.append((i, f"{type(e).__name__} reconnect success"))
                    except:
                        print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} reconnect fail")
                        utils.log(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} reconnect fail")
                        banner_collect.append((i, f"{type(e).__name__} reconnect fail"))
                else:
                    print(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} - {str(e)}")
                    utils.log(f"[Banner Grab] IP {ip}, Port {port}: {type(e).__name__} - {str(e)}")
                    banner_collect.append((i, f"{type(e).__name__}"))
            
        sock.close()
        return {"ip":ip, "port":port, "serive":"null", "banner":banner_collect}
    

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


    def generate_random_string(self, length):
        letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
        return ''.join(random.choice(letters) for _ in range(length)).encode()


    def banner_grab(self, target_list):

            if(len(target_list) == 0):
                print("[Banner Grab] No target to grab")
                utils.log("[Banner Grab] No target to grab")
                return 

            utils.log('[Banner Grab] Start Banner Grab on {} target {}'.format(
                len(target_list), 
                ', '.join(str(target) for target in target_list)
            ))
            print('[Banner Grab] Start Banner Grab on {} target {}'.format(
                len(target_list), 
                ', '.join(str(target) for target in target_list)
            ))

            if sys.version_info.major == 3 and sys.version_info.minor >= 7:
                asyncio.run(self.async_banner_grab_tasks(target_list))
            else:
                loop = asyncio.get_event_loop()
                asyncio.set_event_loop(loop)
                asyncio.get_event_loop().run_until_complete(self.async_banner_grab_tasks(target_list))
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
    print(BannerGrabInst.getResult())

