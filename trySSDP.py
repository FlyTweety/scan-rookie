import socket

# 创建一个UDP套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 绑定到固定的IP和端口上
sock.bind(('0.0.0.0', 1900))

# 设置套接字选项，以便能够接收广播消息
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# 搜索全部设备
search_target = 'ssdp:all'

# 发送M-SEARCH广播消息
message = 'M-SEARCH * HTTP/1.1\r\n' \
          'HOST: 255.255.255.255:1900\r\n' \
          'MAN: "ssdp:discover"\r\n' \
          'MX: 5\r\n' \
          'ST: {}\r\n'.format(search_target).encode('utf-8')
sock.sendto(message, ('255.255.255.255', 1900))

# 接收响应消息，并解析出设备的信息
while True:
    try:
        data, addr = sock.recvfrom(1024)
        print("收到消息来自:", addr)
        print(data.decode())
    except KeyboardInterrupt:
        break

# 关闭套接字
sock.close()
