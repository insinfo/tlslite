#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test script to replicate the Dart TLS integration tests using tlslite-ng.
This script will help debug the TLS handshake by comparing Python and Dart implementations.
"""

import sys
import os
import socket
import io

# Fix encoding issues on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add tlslite-ng to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tlslite-ng'))

from tlslite.tlsconnection import TLSConnection
from tlslite.handshakesettings import HandshakeSettings
from tlslite.constants import CipherSuite


def test_google_com():
    """Test TLS 1.2 connection to google.com"""
    print("\n" + "=" * 70)
    print("TEST: TLS 1.2 connection to www.google.com")
    print("=" * 70)
    
    try:
        # Create TCP socket
        print("[1] Creating TCP connection to www.google.com:443...")
        sock = socket.create_connection(('www.google.com', 443), timeout=30)
        print(f"    ✓ TCP connected: {sock.getpeername()}")
        
        # Wrap with TLS
        print("[2] Wrapping socket with TLSConnection...")
        tls = TLSConnection(sock)
        
        # Create settings for TLS 1.2
        settings = HandshakeSettings()
        settings.minVersion = (3, 3)  # TLS 1.2
        settings.maxVersion = (3, 3)  # TLS 1.2
        
        print(f"    Settings: minVersion={(3,3)}, maxVersion={(3,3)}")
        print(f"    (TLS 1.2 = version (3, 3))")
        
        # Perform handshake
        print("[3] Starting TLS handshake (handshakeClientCert)...")
        tls.handshakeClientCert(
            settings=settings,
            serverName='www.google.com'
        )
        print("    ✓ TLS handshake completed successfully!")
        
        # Print connection info
        print(f"\n[4] Connection details:")
        print(f"    Negotiated version: {tls.version}")
        print(f"    Cipher suite: 0x{tls.session.cipherSuite:04x}")
        print(f"    Server name: {tls.session.serverName}")
        
        # Send HTTP request
        print("\n[5] Sending HTTP GET request...")
        http_request = (
            "GET / HTTP/1.1\r\n"
            "Host: www.google.com\r\n"
            "User-Agent: TlsLite-Python-Test/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        tls.send(http_request.encode('ascii'))
        print("    ✓ HTTP request sent")
        
        # Receive response
        print("\n[6] Receiving HTTP response...")
        response = b''
        while True:
            try:
                data = tls.recv(4096)
                if not data:
                    break
                response += data
            except Exception as e:
                print(f"    (recv ended: {e})")
                break
        
        print(f"    ✓ Received {len(response)} bytes")
        
        # Parse response
        if response:
            # Get first line (status)
            first_line = response.split(b'\r\n')[0].decode('ascii', errors='replace')
            print(f"    Status: {first_line}")
        
        # Close connection
        print("\n[7] Closing connection...")
        tls.close()
        print("    ✓ Connection closed")
        
        print("\n✓✓✓ TEST PASSED ✓✓✓")
        return True
        
    except Exception as e:
        print(f"\n✗✗✗ TEST FAILED ✗✗✗")
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cloudflare_com():
    """Test TLS connection to cloudflare.com"""
    print("\n" + "=" * 70)
    print("TEST: TLS 1.2 connection to www.cloudflare.com")
    print("=" * 70)
    
    try:
        # Create TCP socket
        print("[1] Creating TCP connection to www.cloudflare.com:443...")
        sock = socket.create_connection(('www.cloudflare.com', 443), timeout=30)
        print(f"    ✓ TCP connected: {sock.getpeername()}")
        
        # Wrap with TLS
        print("[2] Wrapping socket with TLSConnection...")
        tls = TLSConnection(sock)
        
        # Create settings for TLS 1.2
        settings = HandshakeSettings()
        settings.minVersion = (3, 3)  # TLS 1.2
        settings.maxVersion = (3, 3)  # TLS 1.2
        
        print(f"    Settings: minVersion={(3,3)}, maxVersion={(3,3)}")
        
        # Perform handshake
        print("[3] Starting TLS handshake...")
        tls.handshakeClientCert(
            settings=settings,
            serverName='www.cloudflare.com'
        )
        print("    ✓ TLS handshake completed successfully!")
        
        # Print connection info
        print(f"\n[4] Connection details:")
        print(f"    Negotiated version: {tls.version}")
        print(f"    Cipher suite: 0x{tls.session.cipherSuite:04x}")
        
        # Send HTTP request
        print("\n[5] Sending HTTP GET request...")
        http_request = (
            "GET / HTTP/1.1\r\n"
            "Host: www.cloudflare.com\r\n"
            "User-Agent: TlsLite-Python-Test/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        tls.send(http_request.encode('ascii'))
        print("    ✓ HTTP request sent")
        
        # Receive response
        print("\n[6] Receiving HTTP response...")
        response = b''
        while True:
            try:
                data = tls.recv(4096)
                if not data:
                    break
                response += data
            except:
                break
        
        print(f"    ✓ Received {len(response)} bytes")
        
        # Parse response
        if response:
            first_line = response.split(b'\r\n')[0].decode('ascii', errors='replace')
            print(f"    Status: {first_line}")
        
        # Close connection
        print("\n[7] Closing connection...")
        tls.close()
        print("    ✓ Connection closed")
        
        print("\n✓✓✓ TEST PASSED ✓✓✓")
        return True
        
    except Exception as e:
        print(f"\n✗✗✗ TEST FAILED ✗✗✗")
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_github_api():
    """Test TLS connection to api.github.com"""
    print("\n" + "=" * 70)
    print("TEST: TLS 1.2 connection to api.github.com")
    print("=" * 70)
    
    try:
        # Create TCP socket
        print("[1] Creating TCP connection to api.github.com:443...")
        sock = socket.create_connection(('api.github.com', 443), timeout=30)
        print(f"    ✓ TCP connected: {sock.getpeername()}")
        
        # Wrap with TLS
        print("[2] Wrapping socket with TLSConnection...")
        tls = TLSConnection(sock)
        
        # Create settings for TLS 1.2
        settings = HandshakeSettings()
        settings.minVersion = (3, 3)  # TLS 1.2
        settings.maxVersion = (3, 3)  # TLS 1.2
        
        print(f"    Settings: minVersion={(3,3)}, maxVersion={(3,3)}")
        
        # Perform handshake
        print("[3] Starting TLS handshake...")
        tls.handshakeClientCert(
            settings=settings,
            serverName='api.github.com'
        )
        print("    ✓ TLS handshake completed successfully!")
        
        # Print connection info
        print(f"\n[4] Connection details:")
        print(f"    Negotiated version: {tls.version}")
        print(f"    Cipher suite: 0x{tls.session.cipherSuite:04x}")
        
        # Send HTTP request
        print("\n[5] Sending HTTP GET request to /zen...")
        http_request = (
            "GET /zen HTTP/1.1\r\n"
            "Host: api.github.com\r\n"
            "User-Agent: TlsLite-Python-Test/1.0\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        tls.send(http_request.encode('ascii'))
        print("    ✓ HTTP request sent")
        
        # Receive response
        print("\n[6] Receiving HTTP response...")
        response = b''
        while True:
            try:
                data = tls.recv(4096)
                if not data:
                    break
                response += data
            except:
                break
        
        print(f"    ✓ Received {len(response)} bytes")
        
        # Parse response
        if response:
            first_line = response.split(b'\r\n')[0].decode('ascii', errors='replace')
            print(f"    Status: {first_line}")
            # Try to get body
            if b'\r\n\r\n' in response:
                body = response.split(b'\r\n\r\n', 1)[1]
                print(f"    Body: {body.decode('utf-8', errors='replace')[:200]}")
        
        # Close connection
        print("\n[7] Closing connection...")
        tls.close()
        print("    ✓ Connection closed")
        
        print("\n✓✓✓ TEST PASSED ✓✓✓")
        return True
        
    except Exception as e:
        print(f"\n✗✗✗ TEST FAILED ✗✗✗")
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_with_verbose_debug():
    """Test with verbose debugging to see handshake messages"""
    print("\n" + "=" * 70)
    print("TEST: VERBOSE DEBUG - TLS 1.2 connection to www.google.com")
    print("=" * 70)
    
    # Patch tlslite to add debug output
    from tlslite import messages
    from tlslite import tlsrecordlayer
    
    # Store original methods
    original_parseFragment = messages.TlsHandshakeMessage.parseFragment if hasattr(messages, 'TlsHandshakeMessage') else None
    
    try:
        # Create TCP socket
        print("[1] Creating TCP connection to www.google.com:443...")
        sock = socket.create_connection(('www.google.com', 443), timeout=30)
        print(f"    ✓ TCP connected: {sock.getpeername()}")
        
        # Wrap with TLS
        print("[2] Wrapping socket with TLSConnection...")
        tls = TLSConnection(sock)
        
        # Create settings for TLS 1.2
        settings = HandshakeSettings()
        settings.minVersion = (3, 3)
        settings.maxVersion = (3, 3)
        
        print("[3] Starting TLS handshake with verbose debug...")
        print("    Messages will be printed during handshake...")
        print("-" * 50)
        
        tls.handshakeClientCert(
            settings=settings,
            serverName='www.google.com'
        )
        
        print("-" * 50)
        print("    ✓ TLS handshake completed successfully!")
        
        print(f"\n[4] Final connection details:")
        print(f"    Negotiated version: {tls.version}")
        print(f"    Cipher suite: 0x{tls.session.cipherSuite:04x}")
        
        tls.close()
        
        print("\n✓✓✓ TEST PASSED ✓✓✓")
        return True
        
    except Exception as e:
        print(f"\n✗✗✗ TEST FAILED ✗✗✗")
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    print("=" * 70)
    print("TLS Integration Tests - Python (tlslite-ng)")
    print("This script tests the original Python implementation")
    print("to compare with the Dart port")
    print("=" * 70)
    
    results = []
    
    # Run tests
    results.append(("google.com TLS 1.2", test_google_com()))
    results.append(("cloudflare.com TLS 1.2", test_cloudflare_com()))
    results.append(("api.github.com TLS 1.2", test_github_api()))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, r in results if r)
    failed = sum(1 for _, r in results if not r)
    
    for name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {name}: {status}")
    
    print("-" * 70)
    print(f"Total: {passed} passed, {failed} failed")
    
    if failed > 0:
        sys.exit(1)
