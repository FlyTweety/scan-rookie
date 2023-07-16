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

# 示例用法
ip = '192.168.6.0'  # 输入您的IPv4地址
subnet_mask = 23  # 输入子网掩码长度

addresses = get_subnet_addresses(ip, subnet_mask)
print(addresses)
