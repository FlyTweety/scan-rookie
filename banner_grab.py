import scapy.all as sc
import threading
import time
from datetime import datetime
import socket
import asyncio
from typing import List

import utils

class BannerGrab:

    def __init__(self, host_state):

        self._host_state = host_state

        self._lock = threading.Lock()
        self._active = False

        self._thread = threading.Thread(target=self._banner_grab_thread)
        self._thread.daemon = True

    def start(self):

        with self._lock:
            self._active = True

        utils.log('[Banner Grab] Starting.')
        self._thread.start()

    def _banner_grab_thread(self):

        utils.restart_upon_crash(self._banner_grab_thread_helper)

    def _banner_grab_thread_helper(self):

        while True:

            time.sleep(1)

            if not self._host_state.is_inspecting():
                continue

            ip_port_info_list = self._host_state.received_ip_port_info 
            target_ip_port_list = []
            for entry in ip_port_info_list:
                ip_port = str(entry['ip']) + "_" + str(entry['port'])
                if ip_port in self._host_state.last_banner_grab_time:
                    continue # no matter last attempt time, only grab once
                target_ip_port_list.append(ip_port)

            if(len(target_ip_port_list) == 0): # no new target to do banner grab
                time.sleep(5)
                continue

            utils.log('[Banner Grab] Start Banner Grab on {}'.format(
                ', '.join(target_ip_port_list)
            ))
            print('[Banner Grab] Start Banner Grab on {}'.format(
                ', '.join(target_ip_port_list)
            ))

            self._banner_grab_process(target_ip_port_list)

            print("Done Banner Grab")
            for ip_port in target_ip_port_list:
                self._host_state.last_banner_grab_time[ip_port] = datetime.now()
            print("Banner Info Now = ", self._host_state.banner_grab_info)


    async def banner_grab(self, ip, port, loop, timeout=3.0):
        try:
            # Create a socket object and connect to an IP  and Port.
            #print(f"try socket step 1 for {ip}_{port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            await asyncio.wait_for(
                loop.sock_connect(sock, (ip, port)), 
                timeout=3.0
            )

            #print(f"try socket step 2 for {ip}_{port}")
            try:     
                data = await asyncio.wait_for(
                    asyncio.gather(
                        asyncio.sleep(3),
                        loop.sock_recv(sock, 1024),
                        return_exceptions=False,
                    ), 
                    timeout=6.0)
            except (asyncio.TimeoutError, asyncio.CancelledError) as e:  #seems to be useless……
                print("Banner Grab] fail to get inital data")
            except Exception as e:
                print("[Banner Grab] gather error:", str(e))
            else:
                if isinstance(data, List) and isinstance(data[1], bytes): # data[0]:result of asyncio.sleep(3)  data[1]:result of loop.sock_recv(sock, 1024)
                    initial_data = data[1]
                    utils.log(f"[Banner Grab] IP {ip}, Port {port}, Get Initial Data:\n {initial_data.decode('utf-8', errors='ignore').strip()}")
                    print(f"[Banner Grab] IP {ip}, Port {port}, Get Initial Data:\n {initial_data.decode('utf-8', errors='ignore').strip()}")
                    return {"ip":ip, "port":port, "serive":"null", "banner":initial_data.decode('utf-8', errors='ignore').strip()} # No need for take initiative to send data
                else:
                    print("Banner Grab] get wrong inital data = ", data)

            #print(f"try socket step 3 for {ip}_{port}")
            # take initiative to send data to trigger a banner response.
            await loop.sock_sendall(sock, b"GET / HTTP/1.1\r\n\r\n")

            # get banner (1024 bytes at most)
            banner = await loop.sock_recv(sock, 1024)
            
            utils.log(f"[Banner Grab] IP {ip}, Port {port}, Content:\n {banner.decode('utf-8', errors='ignore').strip()}")
            print(f"[Banner Grab] IP {ip}, Port {port}, Content:\n {banner.decode('utf-8', errors='ignore').strip()}")
            return {"ip":ip, "port":port, "serive":"null", "banner":banner.decode('utf-8', errors='ignore').strip()}

        except asyncio.TimeoutError:
            utils.log(f"[Banner Grab] IP {ip}, Port {port},  Timeout")
            print(f"[Banner Grab] IP {ip}, Port {port},  Timeout")
            return {"ip":ip, "port":port, "serive":"null", "banner":"timeout"}
        except OSError:
            utils.log(f"[Banner Grab] IP {ip}, Port {port},  Connection refused")
            print(f"[Banner Grab] IP {ip}, Port {port},  Connection refused")
            return {"ip":ip, "port":port, "serive":"null", "banner":"refused"}
        finally:
            sock.close()

    async def all_banner_grab(self, ip_list, port_list, loop=None):

        # Create a list of coroutines for banner grabbing from the given IP and Port lists
        coroutines = []
        for i in range(0, len(ip_list)): # here is one-to-one, not double loop!
            coro = self.banner_grab(ip_list[i], port_list[i], loop)
            coroutines.append(coro)

        if loop is None:
            loop = asyncio.get_event_loop()
       
        # Wait for all coroutines to complete and get the results
        results = await asyncio.gather(*coroutines, loop=loop)

         # Update the banner grab info for each IP and Port into _host_state.banner_grab_info.append
        for result in results:
            ip_port = str(result['ip']) + "_" + str(result['port'])
            if ip_port in self._host_state.last_banner_grab_time: # second time get banner from it
                for i in range(0, len(self._host_state.banner_grab_info)): # find its original entry in banner_grab_info
                    if((self._host_state.banner_grab_info[i]['ip'] == result['ip']) and (self._host_state.banner_grab_info[i]['port'] == result['port'])):
                        self._host_state.banner_grab_info[i] = result
            else:
                self._host_state.banner_grab_info.append(result)
                
                

    def _banner_grab_process(self, target_ip_port_list):
        ip_list = []
        port_list = []
        for ip_port in target_ip_port_list:
            ip, port = ip_port.split("_")
            ip_list.append(ip)
            port_list.append(int(port))

        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)

        loop = asyncio.get_event_loop()
        
        loop.run_until_complete(self.all_banner_grab(ip_list, port_list, loop))

        loop.close()


    def stop(self):

        with self._lock:
            self._active = False

        self._thread.join()

        utils.log('[Banner Grab] Stopped.')
