
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
import xml.etree.ElementTree as ET
import pandas

#按照我的新版，只要留get_port_list和log和get_subnet_addresses和两个getIP就够了

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

def log(*args):

    log_str = '[%s] ' % datetime.datetime.today()
    log_str += ' '.join([str(v) for v in args])

    log_file_path = "./log.txt" #!!!!!!!!!!!!!!!!!!!! Modified

    with open(log_file_path, 'a') as fp:
        fp.write(log_str + '\n')

def get_subnet_addresses(ip_address, subnet_mask_length):
    ip_parts = ip_address.split('.')
    subnet_mask = ['0'] * 4
    
    # 将子网掩码转换为二进制字符串
    for i in range(subnet_mask_length):
        subnet_mask[i // 8] = str(int(subnet_mask[i // 8]) + 2 ** (7 - i % 8))
    
    network_address = []
    
    # 计算网络地址
    for i in range(4):
        network_address.append(str(int(ip_parts[i]) & int(subnet_mask[i])))

    # 获得子网下的所有地址
    addresses = []
    for i in range(1, 2**(32-subnet_mask_length)-1):
        address_parts = []
        
        # 计算每个地址的四个部分
        for j in range(4):
            address_parts.append(str((int(network_address[j]) & int(subnet_mask[j])) + ((i >> (3-j)*8) & 255)))
        
        addresses.append('.'.join(address_parts))
    
    return addresses
"""
# 示例用法
ip = '192.168.0.0'  # 输入您的IPv4地址
subnet_mask = 21  # 输入子网掩码长度

addresses = get_subnet_addresses(ip, subnet_mask)
print(addresses)
"""

def getDannyIPs():
    danny_ip_list = [
        '192.168.87.1',
        '192.168.87.20',
        '192.168.87.22',
        '192.168.87.26',
        '192.168.87.27',
        '192.168.87.29',
        '192.168.87.30',
        '192.168.87.31',
        '192.168.87.32',
        '192.168.87.35',
        '192.168.87.36',
        '192.168.87.46',
        '192.168.87.47',
        '192.168.87.48',
        '192.168.87.49',
        '192.168.87.73',
        '192.168.87.75',
        '192.168.87.76'
    ]
    return danny_ip_list


def getDannyIPandPorts():
    DannyIPandPorts = [
        ('192.168.87.1', 53), 
        ('192.168.87.1', 80), 
        ('192.168.87.1', 5000), 
        ('192.168.87.1', 8080), 
        ('192.168.87.1', 8081), 
        ('192.168.87.1', 8443), 
        ('192.168.87.20', 6668), 
        ('192.168.87.22', 6668), 
        ('192.168.87.26', 6668), 
        ('192.168.87.27', 6668), 
        ('192.168.87.28', 6668), 
        ('192.168.87.29', 22), 
        ('192.168.87.29', 51760), 
        ('192.168.87.30', 80), 
        ('192.168.87.31', 80), 
        ('192.168.87.35', 6668), 
        ('192.168.87.36', 6668), 
        ('192.168.87.41', 6668), 
        ('192.168.87.42', 6668), 
        ('192.168.87.46', 80), 
        ('192.168.87.46', 8080), 
        ('192.168.87.46', 8081), 
        ('192.168.87.46', 8443), 
        ('192.168.87.47', 80), 
        ('192.168.87.47', 8080), 
        ('192.168.87.47', 8081), 
        ('192.168.87.47', 8443), 
        ('192.168.87.48', 8080)]
    return DannyIPandPorts

def getNyuIPs():

    IPs = []

    tree = ET.parse('./TestData/scan_results.xml')
    root = tree.getroot()

    for host in root.findall('host'):

        address = host.find('address')
        ip_address = address.get('addr')
        
        IPs.append(ip_address)

    return IPs

def getNyuIPandPorts():
    data = pandas.read_excel('./TestData/logNyuDorm0-300.xlsx')
    result = [tuple(x) for x in data.values]  
    return result

def split_array(array, chunk_size):
    result = []
    for i in range(0, len(array), chunk_size):
        result.append(array[i:i+chunk_size])
    return result

