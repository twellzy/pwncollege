import socket
HOST, PORT = "hacker.localhost", 8081
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #initialization


sock.bind((HOST, PORT)) #linking socket to host and port
sock.listen(1)
connection, client_address = sock.accept()
print("connected")
data = connection.recv(1024).decode("UTF-8")

print(data)

sock.close()
print("\n")

print(data)

