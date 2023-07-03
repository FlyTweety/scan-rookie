# Original Copy; See Change in things_I_modified.txt

"""
Misc functions.

"""
import ipaddress

import datetime
import hashlib
import json
import netaddr
import netifaces
import os
import re
import requests
import scapy.all as sc
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
import webbrowser
import ipaddress


def get_port_list():

    # Ports collected from common IoT services and protocols
    # from redhat scans, captured traffic, and home IoT scans.
    port_set = set([2121, 11111, 1137, 123, 137, 139, 1443, 1698, 1743, 18181, 1843,
                    1923, 19531, 22, 25454, 2869, 32768, 32769, 35518, 35682,
                    36866, 3689, 37199, 38576, 41432, 42758, 443, 445, 45363,
                    4548, 46355, 46995, 47391, 48569, 49152, 49153, 49154,
                    49451, 53, 5353, 548, 554, 56167, 56278, 56789, 56928,
                    59815, 6466, 6467, 655, 7676, 7678, 7681, 7685, 7777, 81,
                    8181, 8187, 8222, 8443, 88, 8842, 8883, 8886, 8888, 8889,
                    911, 9119, 9197, 9295, 9999, 443, 80, 993, 5228, 4070,
                    5223, 9543, 1, 2, 4, 5, 6, 7, 9, 11, 13, 15, 17, 18, 19,
                    20, 21, 22, 23, 25, 37, 39, 42, 43, 49, 50, 53, 63, 67, 68,
                    69, 70, 71, 72, 73, 79, 80, 81, 88, 95, 98, 101, 102, 105,
                    106, 107, 109, 110, 111, 113, 115, 117, 119, 123, 137, 138,
                    139, 143, 161, 162, 163, 164, 174, 177, 178, 179, 191, 194,
                    199, 201, 202, 204, 206, 209, 210, 213, 220, 245, 347, 363,
                    369, 370, 372, 389, 427, 434, 435, 443, 444, 445, 464, 465,
                    468, 487, 488, 496, 500, 512, 513, 514, 515, 517, 518, 519,
                    520, 521, 525, 526, 530, 531, 532, 533, 535, 538, 540, 543,
                    544, 546, 547, 548, 554, 556, 563, 565, 587, 610, 611, 612,
                    616, 631, 636, 655, 674, 694, 749, 750, 751, 752, 754, 760,
                    765, 767, 808, 871, 873, 901, 911, 953, 992, 993, 994, 995,
                    1080, 1109, 1127, 1137, 1178, 1236, 1300, 1313, 1433, 1434,
                    1443, 1494, 1512, 1524, 1525, 1529, 1645, 1646, 1649, 1698,
                    1701, 1718, 1719, 1720, 1743, 1758, 1759, 1789, 1812, 1813,
                    1843, 1911, 1923, 1985, 1986, 1997, 2003, 2049, 2053, 2102,
                    2103, 2104, 2105, 2121, 2150, 2401, 2430, 2431, 2432, 2433,
                    2600, 2601, 2602, 2603, 2604, 2605, 2606, 2809, 2869, 2988,
                    3128, 3130, 3306, 3346, 3455, 3689, 4011, 4070, 4321, 4444,
                    4548, 4557, 4559, 5002, 5223, 5228, 5232, 5308, 5353, 5354,
                    5355, 5432, 5680, 5999, 6000, 6010, 6466, 6467, 6667, 7000,
                    7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7100,
                    7666, 7676, 7678, 7681, 7685, 7777, 8008, 8080, 8081, 8181,
                    8187, 8222, 8443, 8842, 8883, 8886, 8888, 8889, 9100, 9119,
                    9197, 9295, 9359, 9543, 9876, 9999, 10080, 10081, 10082,
                    10083, 11111, 11371, 11720, 13720, 13721, 13722, 13724,
                    13782, 13783, 18181, 19531, 20011, 20012, 22273, 22289,
                    22305, 22321, 24554, 25454, 26000, 26208, 27374, 32768,
                    32769, 33434, 35518, 35682, 36866, 37199, 38576, 41432,
                    42758, 45363, 46355, 46995, 47391, 48569, 49152, 49153,
                    49154, 49451, 56167, 56278, 56789, 56928, 59815, 60177,
                    8060, # Roku
                    60179])
    return sorted(port_set)

_lock = threading.Lock()


def log(*args):

    log_str = '[%s] ' % datetime.datetime.today()
    log_str += ' '.join([str(v) for v in args])

    log_file_path = "./log.txt" #!!!!!!!!!!!!!!!!!!!! Modified

    with open(log_file_path, 'a') as fp:
        fp.write(log_str + '\n')

def get_gateway_ip(timeout=10):
    """Returns the IP address of the gateway."""

    return get_default_route(timeout)[0]


def get_host_ip(timeout=10):
    """Returns the host's local IP (where IoT Inspector client runs)."""

    return get_default_route(timeout)[2]


def _get_routes(timeout=10):

    while True:

        sc.conf.route.resync()
        routes = sc.conf.route.routes
        if routes:
            return routes

        time.sleep(1)


def get_default_route(timeout=10):
    """Returns (gateway_ip, iface, host_ip)."""
    # Discover the active/preferred network interface 
    # by connecting to Google's public DNS server
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            iface_ip = s.getsockname()[0]
    except socket.error:
        sys.stderr.write('IoT Inspector cannot run without network connectivity.\n')
        sys.exit(1)

    while True:
        routes = _get_routes()
        default_route = None
        for route in routes:
            if route[4] == iface_ip:
                # Reassign scapy's default interface to the one we selected
                sc.conf.iface = route[3]
                default_route = route[2:5]
                break
        if default_route:
            break

        log('get_default_route: retrying')
        time.sleep(1)
    

    # If we are using windows, conf.route.routes table doesn't update.
    # We have to update routing table manually for packets
    # to pick the correct route. 
    if sys.platform.startswith('win'):
        for i, route in enumerate(routes):
            # if we see our selected iface, update the metrics to 0
            if route[3] == default_route[1]:
                routes[i] = (*route[:-1], 0)

    return default_route


def get_net_and_mask():
    iface = get_default_route()[1]
    routes = _get_routes()
    net = mask = None
    for route in routes:
        if route[3] == iface:
            net = ipaddress.IPv4Address(route[0])
            mask = ipaddress.IPv4Address(route[1])
            break
    return net, mask


def check_pkt_in_network(ip, net, mask):
    full_net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    return full_net.network_address == net


def get_network_ip_range_windows():
    default_iface = get_default_route()
    iface_filter = default_iface[1]

    ip_set = set()
    iface_ip = iface_filter.ip
    iface_guid = iface_filter.guid
    for k, v in netifaces.ifaddresses(iface_guid).items():
        if v[0]['addr'] == iface_ip:
            netmask = v[0]['netmask']
            break
  
    network = netaddr.IPAddress(iface_ip)
    cidr = netaddr.IPAddress(netmask).netmask_bits()
    subnet = netaddr.IPNetwork('{}/{}'.format(network, cidr))
  
    return ip_set

def check_ethernet_network():
    """
        Check presence of non-Ethernet network adapters (e.g., VPN).
        VPNs use TUN interfaces which don't have a hardware address.
    """
    default_iface = get_default_route()

    assert default_iface[1] == sc.conf.iface, "incorrect sc.conf.iface"
    iface_str = ''
    if sys.platform.startswith('win'):
        iface_info = sc.conf.iface
        iface_str = iface_info.guid
    else:
        iface_str = sc.conf.iface

    ifaddresses = netifaces.ifaddresses(str(iface_str))
    try:
        iface_mac = ifaddresses[netifaces.AF_LINK][0]['addr']
    except KeyError:
        return False
    return iface_mac != ''



def get_network_ip_range():
    """
        Gets network IP range for the default interface.
    """
    ip_set = set()
    default_route = get_default_route()

    assert default_route[1] == sc.conf.iface, "incorrect sc.conf.iface"

    iface_str = ''
    if sys.platform.startswith('win'):
        iface_info = sc.conf.iface
        iface_str = iface_info.guid
    else:
        iface_str = sc.conf.iface

    netmask = None
    for k, v in netifaces.ifaddresses(str(iface_str)).items():
        if v[0]['addr'] == default_route[2]:
            netmask = v[0]['netmask']
            break

    if netmask is None:
        return set()

    gateway_ip = netaddr.IPAddress(default_route[0])
    cidr = netaddr.IPAddress(netmask).netmask_bits()
    subnet = netaddr.IPNetwork('{}/{}'.format(gateway_ip, cidr))

    for ip in subnet:
        ip_set.add(str(ip))

    return ip_set


def get_my_mac():
    """Returns the MAC addr of the default route interface."""

    mac_set = get_my_mac_set(iface_filter=get_default_route()[1])
    return mac_set.pop()


def get_my_mac_set(iface_filter=None):
    """Returns a set of MAC addresses of the current host."""

    out_set = set()
    if sys.platform.startswith("win"):
        from scapy.arch.windows import NetworkInterface
        if type(iface_filter) == NetworkInterface:
            out_set.add(iface_filter.mac)

    for iface in sc.get_if_list():
        if iface_filter is not None and iface != iface_filter:
            continue
        try:
            mac = sc.get_if_hwaddr(iface)
        except Exception as e:
            continue
        else:
            out_set.add(mac)

    return out_set


class _SafeRunError(object):
    """Used privately to denote error state in safe_run()."""

    def __init__(self):
        pass


def restart_upon_crash(func, args=[], kwargs={}):
    """Restarts func upon unexpected exception and logs stack trace."""

    while True:

        result = safe_run(func, args, kwargs)

        if isinstance(result, _SafeRunError):
            time.sleep(1)
            continue

        return result


def safe_run(func, args=[], kwargs={}):
    """Returns _SafeRunError() upon failure and logs stack trace."""

    try:
        return func(*args, **kwargs)

    except Exception as e:

        err_msg = '=' * 80 + '\n'
        err_msg += 'Time: %s\n' % datetime.datetime.today()
        err_msg += 'Function: %s %s %s\n' % (func, args, kwargs)
        err_msg += 'Exception: %s\n' % e
        err_msg += str(traceback.format_exc()) + '\n\n\n'

        with _lock:
            sys.stderr.write(err_msg + '\n')
            log(err_msg)

        return _SafeRunError()


def get_device_id(device_mac, host_state):

    device_mac = str(device_mac).lower().replace(':', '')
    s = device_mac + str(host_state.secret_salt)

    return 's' + hashlib.sha256(s.encode('utf-8')).hexdigest()[0:10]

def smart_max(v1, v2):
    """
        Returns max value even if one value is None.

        Python cannot compare None and int, so build a wrapper
        around it.
    """
    if v1 is None:
        return v2

    if v2 is None:
        return v1

    return max(v1, v2)


def smart_min(v1, v2):
    """
    Returns min value even if one of the value is None.

    By default min(None, x) == None per Python default behavior.

    """

    if v1 is None:
        return v2

    if v2 is None:
        return v1

    return min(v1, v2)


def get_min_max_tuple(min_max_tuple, value):
    """
    Returns a new min_max_tuple with value considered.

    For example:

        min_max_tuple = (2, 3)
        print get_min_max_tuple(min_max_tuple, 4)

    We get back (2, 4).

    """
    min_v, max_v = min_max_tuple

    min_v = smart_min(min_v, value)
    max_v = smart_max(max_v, value)

    return (min_v, max_v)


def get_oui(mac):

    return mac.replace(':', '').lower()[0:6]


def get_os():
    """Returns 'mac', 'linux', or 'windows'. Raises RuntimeError otherwise."""

    os_platform = sys.platform

    if os_platform.startswith('darwin'):
        return 'mac'

    if os_platform.startswith('linux'):
        return 'linux'

    if os_platform.startswith('win'):
        return 'windows'

    raise RuntimeError('Unsupported operating system.')


def open_browser(url):
    try:
        try:
            webbrowser.get('chrome').open(url, new=2)
        except webbrowser.Error:
            webbrowser.open(url, new=2)
    except Exception:
        pass


def test():
    # check_ethernet_network()
    print(get_default_route())
if __name__ == '__main__':
    test()
    print(get_host_ip())
