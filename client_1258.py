import socket

HOST = '127.0.0.1'
PORT = 50258

def send_msg(s, text):
    payload = text.encode()
    frame = f"LEN:{len(payload)}\n".encode() + payload
    s.sendall(frame)

def recv_msg(s):
    data = b""
    while b"\n" not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode().strip()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("Connected to server")

    while True:
        cmd = input("cmd> ").strip()
        if not cmd:
            continue
        send_msg(s, cmd)
        response = recv_msg(s)
        print(response)
        if cmd.upper().startswith("LOGOUT"):
            break

    s.close()

if __name__ == "__main__":
    main()
