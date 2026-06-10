import socket
import threading
import sys

def proxy_connection(client_sock):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect(('127.0.0.1', 27979))
        
        # Read client request
        client_data = client_sock.recv(65536)
        print("--- REQUEST FROM CLIENT ---", flush=True)
        print(client_data.decode('utf-8', errors='ignore'), flush=True)
        print("---------------------------", flush=True)
        
        # Forward to server
        server_sock.sendall(client_data)
        
        # Read server response
        server_data = server_sock.recv(65536)
        print("--- RESPONSE FROM SERVER ---", flush=True)
        print(server_data.decode('utf-8', errors='ignore'), flush=True)
        print("----------------------------", flush=True)
        
        client_sock.sendall(server_data)
        client_sock.close()
        server_sock.close()
    except Exception as e:
        print(f"Error: {e}", flush=True)

def main():
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(('127.0.0.1', 27978))
    proxy.listen(5)
    print("Proxy listening on port 27978...", flush=True)
    try:
        while True:
            client, addr = proxy.accept()
            t = threading.Thread(target=proxy_connection, args=(client,))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()
