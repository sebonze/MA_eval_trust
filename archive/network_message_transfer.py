import socket


def send_udp_message(message, ip="127.0.0.1", port=12345):
    """Send a UDP message."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message.encode(), (ip, port))
        print(f"Sent message: {message} to {ip}:{port}")


def receive_udp_message(port=12345):
    """Receive a UDP message."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", port))
        data, addr = sock.recvfrom(1024)
        print(f"Received message: {data.decode()} from {addr[0]}:{addr[1]}")


if __name__ == "__main__":
    choice = input("Choose action (send/receive): ").strip().lower()
    if choice == "send":
        msg = input("Enter message to send: ")
        send_udp_message(msg)
    elif choice == "receive":
        receive_udp_message()
    else:
        print("Invalid choice. Exiting.")
