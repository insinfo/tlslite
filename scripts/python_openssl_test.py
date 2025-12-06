#!/usr/bin/env python3
"""
Test Python tlslite-ng client against OpenSSL s_server
to verify the same setup works in Python
"""

import sys
import socket
import subprocess
import time
import tempfile
import os

sys.path.insert(0, 'tlslite-ng')

from tlslite.tlsconnection import TLSConnection
from tlslite.handshakesettings import HandshakeSettings

def test_python_vs_openssl():
    # Create temp certificate
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = os.path.join(tmpdir, 'server.key')
        cert_file = os.path.join(tmpdir, 'server.crt')
        
        # Generate certificate
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', key_file, '-out', cert_file,
            '-days', '1', '-nodes', '-subj', '/CN=localhost'
        ], check=True, capture_output=True)
        
        # Start OpenSSL server
        server = subprocess.Popen([
            'openssl', 's_server',
            '-accept', '14440',
            '-key', key_file,
            '-cert', cert_file,
            '-tls1_2',
            '-cipher', 'ECDHE-RSA-CHACHA20-POLY1305',
            '-no_dhe'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        time.sleep(1)  # Wait for server to start
        
        try:
            print("=== Python tlslite-ng client vs OpenSSL server ===")
            
            # Connect with Python client
            sock = socket.create_connection(('127.0.0.1', 14440))
            tls = TLSConnection(sock)
            
            settings = HandshakeSettings()
            settings.minVersion = (3, 3)
            settings.maxVersion = (3, 3)
            settings.cipherNames = ['chacha20-poly1305']
            
            print("Starting TLS handshake...")
            tls.handshakeClientCert(settings=settings)
            
            print("Handshake SUCCESSFUL!")
            print(f"Cipher: {tls.getCipherName()}")
            print(f"Version: {tls.version}")
            
            # Send test message
            tls.send(b"Hello from Python!\n")
            
            # Close
            tls.close()
            
        except Exception as e:
            print(f"Handshake FAILED: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            server.terminate()
            server.wait()
            
            # Print server output
            stdout, stderr = server.communicate(timeout=2)
            print("\n=== Server stdout ===")
            print(stdout.decode('utf-8', errors='replace'))
            print("\n=== Server stderr ===")
            print(stderr.decode('utf-8', errors='replace'))

if __name__ == '__main__':
    test_python_vs_openssl()
