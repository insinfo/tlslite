# Python TLS Server for integration testing with Dart client
# This server uses tlslite-ng and logs all handshake details

import sys
import os
import socket
import threading
import time

# Add tlslite-ng to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tlslite-ng'))

from tlslite import TLSConnection, HandshakeSettings
from tlslite.constants import CipherSuite, AlertDescription
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.utils import keyfactory

# Server certificate and key (self-signed for testing)
SERVER_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P2pHNDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o5e7irA5Fr0axRiHpR8v9DdKl1FkBB5cWUf0MZe4PDmLcWfMC0aT+9P6nj8lmXsv
OgLvJhIxDWJhsH8qZ9ILwPw5yE4V8sD8P4lQDFJIrcKL2ULR9v1r8/7ZnSH8Pf3E
aJM1f0dvVklzo0pH7P+U+Y8RmF+q9JHrDXVCl3/V0bE1hJKp5R3D8wqXlR8anR4r
HjFDBVPv7MKv6U/KpHFJDtYfrdi9uNfbGLvVcr+Hgq+T5WXmjKn9mjGEfCQ8GHIR
qGk7VAdb7geh0T1MbG/5CwTns8k6jHd1bMJl+7PmSsQ0O5BBgV1EpGzHCgR/wCnV
wSXw0LkArwP5TN2FkJNvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGt0YA2wQl8h
n6w2gl6lSdRJQprjwWFTwGx2HvqHvpFGBSwR2SF1HdAF0qWH0kNWMCsU9J8EF0FD
5FkLrmJSyFCO1B6EUaIF8sVgDhAu2iW2hJvebjBqMcwHxp7mmEIN6/fYblfpUKUW
9XLOHIwPv/fmdAE/GXSqKHEnHb+D7fLkvgbW0CHYjQr0s/nvFprGeCy0UDgfCP3T
bvpNK9lOHiYPbT65pLMUFHO8jPrg7XL/RB1dVFMd0zFvdoD9qB1f1D5o5FpX0M4C
HaSqfMlf9VNdp6s56R3R6IlBn7tJVBFQFrxRhxEW8v+kvmKnMY8GYEv4BTDU6rOn
1c/S/yqwzLM=
-----END CERTIFICATE-----"""

SERVER_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu6OXu4qwORa9GsUYh6UfL/Q3SpdRZAQeXFlH9DGXuDw5i3Fn
zAtGk/vT+p4/JZl7LzoC7yYSMQ1iYbB/KmfSC8D8OchOFfLA/D+JUAxSSK3Ci9lC
0fb9a/P+2Z0h/D39xGiTNX9Hb1ZJc6NKR+z/lPmPEZhfqvSR6w11Qpd/1dGxNYSS
qeUdw/MKl5UfGp0eKx4xQwVT7+zCr+lPyqRxSQ7WH63YvbjX2xi71XK/h4Kvk+Vl
5oyp/ZoxhHwkPBhyEahpO1QHW+4HodE9TGxv+QsE57PJOox3dWzCZfuz5krENDuQ
QYFdRKRsxwoEf8Ap1cEl8NC5AK8D+UzdhZCTbwIDAQABAoIBAFe1/7y7gP/s7Vli
GdZ/L2kCQi0lD4vJfMYNPbR0ZNHrcf+HMCjV7WBPfSNsQ+D8cR3Y8B2aBzAHJwUW
E7cGGZ3xbN0wCjJhOo4OLbMLSx0MWDKL4r5qMP3LkVAB5VJf5JZNvXedpLYkJGmL
HL8RSnVWopr7G5S3LPE7xDqqthhmHVOSQkLPT2HBsBvoN7Ev9wvevqEz3hXPWSOl
Q6jW+dnBi8LnOZbjKrJaQHNI+RLP4Y4rKwz+lhJ5PBPXjfK3mgJHl4mE1lkJH/Hi
AKTpBKa4/DZKpvGC2VlqEBo/sc9COKKL5UAi1Nkfu0hMJZDT0CFPcMz+pN8AXW9s
/XDRCkECgYEA3bqslJJLlEaQ2V+U1BWAx0FnhALHwLD3k8OgzWBGLnb+KDnYWm6Q
kM8sF4d2t1yPaL8oP0PzK5KFHqE9bU+R5ULjG6IbHlBdmK+NbqxfpPAX/K99t3m3
VfnCaqd4R/lx0O1ynJa7mXOqwqlBJrej9pL0MhAGl/s7wrCkfX+e2XECgYEA2NC+
CdQYwBT6wJLgVp1m5O/yRxKDF3UbBfZi7GCXbdG9umJYdL5Tf4E6DKRI0zy0XSHK
eL8Ij3QHWZ6x7l0V2KNJjL2kfJ3L8EbCJNrN5jzVGX8xEiPnKFVB1LBX4v3AZBM4
VTf6YjzfMhtN3YDEU9v8xPPt0l8wPqRhBCpwz28CgYEApV5GqLKLUeJ6MzS2J3HZ
qFNBLRj3B8O/tSmQn5DkwU0/7r2X0xkNlKHlZ0rEzVHB0i3I2cHDj5Qk0xgGmvQL
qUiXe5dRlH9KnRnBeK8i1Tf3NZZBJLXP2bLnyWU5nL0pmvOp/kLA3v8rCmFWZR5G
Ln/a9nBLnUB8yX6QrK0F9RECgYBRHqIr7I5+6hP5ZvB3+e4s/PVxPm8Za9x4bUmX
yBNAhPLYV3N8R1KGmS1ry8i9T8v0mqhHl0BNszB3r0qPBu+q7kfvIJSSv1y8LWaT
Q+H4jTPwGMFTT8a1tvzxV1bfPbA0Y5b0E5TgEQ+EKfR9hCgLmJeKLZdL3c4Q7YQq
YB+L7wKBgG6Z4fAW0R+9R0T7lSs4qVLBwFz0a2nx0pnKnPTFPPKh+cFHFSMrYXKY
l/NU6C0rN0fHvPKHFq1k/dvFf2mU8vh9fh0j8F0n4bJjlp2e8hJYVCPdyaj8b1qo
+sYglyLnlJ6lC5M2h8zKn8RMpJe5N6vpdsCK9sGCfPb5bZMdxz9G
-----END RSA PRIVATE KEY-----"""


def load_credentials():
    """Load server certificate and private key"""
    cert_path = os.path.join(os.path.dirname(__file__), 'nginx', 'server.crt')
    key_path = os.path.join(os.path.dirname(__file__), 'nginx', 'server.key')

    if os.path.exists(cert_path) and os.path.exists(key_path):
        cert_pem = open(cert_path, 'r', encoding='utf-8').read()
        key_pem = open(key_path, 'r', encoding='utf-8').read()
    else:
        cert_pem = SERVER_CERT_PEM
        key_pem = SERVER_KEY_PEM

    cert = X509().parse(cert_pem)
    chain = X509CertChain([cert])

    # Use pure-Python RSA implementation (avoids backend mismatches)
    key = keyfactory.parsePrivateKey(key_pem)

    return chain, key


class TLSTestServer:
    def __init__(self, host='127.0.0.1', port=4433, cipher_suite='chacha20'):
        self.host = host
        self.port = port
        self.cipher_suite = cipher_suite
        self.server_socket = None
        self.running = False
        self.thread = None
        self.last_error = None
        self.handshake_complete = False
        self.received_data = []
        
    def start(self):
        """Start the server in a background thread"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        self.server_socket.settimeout(30)
        self.running = True
        
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()
        
        # Give server time to start
        time.sleep(0.5)
        print(f"Server started on {self.host}:{self.port}")
        
    def _run(self):
        """Server main loop"""
        try:
            print("Waiting for connection...")
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr}")
            
            # Wrap in TLS
            tls_conn = TLSConnection(client_socket)
            
            # Configure settings
            settings = HandshakeSettings()
            settings.minVersion = (3, 3)  # TLS 1.2 minimum
            settings.maxVersion = (3, 3)  # TLS 1.2 maximum
            settings.rsaSigHashes = ["sha256"]
            settings.rsaSchemes = ["pkcs1"]
            
            # Select cipher suite
            if self.cipher_suite == 'chacha20':
                settings.cipherNames = ["chacha20-poly1305"]
            elif self.cipher_suite == 'aes128gcm':
                settings.cipherNames = ["aes128gcm"]
            elif self.cipher_suite == 'aes256gcm':
                settings.cipherNames = ["aes256gcm"]
            
            # Load credentials
            chain, key = load_credentials()
            
            print("Starting TLS handshake...")
            print(f"  Cipher: {self.cipher_suite}")
            print(f"  Version: TLS 1.2")
            
            try:
                # Perform handshake
                tls_conn.handshakeServer(certChain=chain, privateKey=key, settings=settings)
                self.handshake_complete = True
                print("Handshake completed successfully!")
                print(f"  Negotiated cipher: {tls_conn.session.cipherSuite}")
                print(f"  Version: {tls_conn.version}")
                
                # Try to read some data
                print("Waiting for data from client...")
                try:
                    data = tls_conn.recv(4096)
                    if data:
                        self.received_data.append(data)
                        print(f"Received: {data}")
                        
                        # Echo back
                        tls_conn.send(data)
                        print(f"Sent echo: {data}")
                except Exception as e:
                    print(f"Error receiving data: {e}")
                    self.last_error = str(e)
                    
            except Exception as e:
                print(f"Handshake failed: {e}")
                self.last_error = str(e)
                import traceback
                traceback.print_exc()
                
            finally:
                tls_conn.close()
                
        except socket.timeout:
            print("Server timeout waiting for connection")
            self.last_error = "Timeout"
        except Exception as e:
            print(f"Server error: {e}")
            self.last_error = str(e)
            import traceback
            traceback.print_exc()
            
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.thread:
            self.thread.join(timeout=2)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='TLS Test Server')
    parser.add_argument('--port', type=int, default=4433, help='Port to listen on')
    parser.add_argument('--cipher', choices=['chacha20', 'aes128gcm', 'aes256gcm'], 
                        default='chacha20', help='Cipher suite to use')
    args = parser.parse_args()
    
    server = TLSTestServer(port=args.port, cipher_suite=args.cipher)
    server.start()
    
    # Keep server running
    try:
        while server.running and server.thread.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        
    server.stop()
    
    # Print results
    print("\n=== Results ===")
    print(f"Handshake complete: {server.handshake_complete}")
    print(f"Last error: {server.last_error}")
    print(f"Received data: {server.received_data}")
    
    # Exit with appropriate code
    sys.exit(0 if server.handshake_complete else 1)


if __name__ == '__main__':
    main()
