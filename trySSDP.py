import socket

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind to a fixed IP and port
sock.bind(('0.0.0.0', 1900))

# Set socket options to be able to receive broadcast messages
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# Search for all devices
search_target = 'ssdp:all'

# Send M-SEARCH broadcast message
message = 'M-SEARCH * HTTP/1.1\r\n' \
          'HOST: 255.255.255.255:1900\r\n' \
          'MAN: "ssdp:discover"\r\n' \
          'MX: 5\r\n' \
          'ST: {}\r\n'.format(search_target).encode('utf-8')
sock.sendto(message, ('255.255.255.255', 1900))

# Receive response messages and parse device information
while True:
    try:
        data, addr = sock.recvfrom(1024)
        print("Received message from:", addr)
        print(data.decode())
    except KeyboardInterrupt:
        break

# Close the socket
sock.close()
