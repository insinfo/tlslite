#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Detailed TLS handshake debug script to compare Python tlslite-ng with Dart port.
This script adds extensive logging to understand the handshake flow.
"""

import sys
import os
import socket

# Add tlslite-ng to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tlslite-ng'))

from tlslite.tlsconnection import TLSConnection
from tlslite.handshakesettings import HandshakeSettings
from tlslite.constants import *


def format_bytes(data, max_len=64):
    """Format bytes as hex string"""
    if len(data) > max_len:
        return data[:max_len].hex() + f"... ({len(data)} bytes)"
    return data.hex()


def test_with_debug():
    """Test with detailed debugging of handshake messages"""
    print("=" * 70)
    print("DETAILED TLS HANDSHAKE DEBUG")
    print("=" * 70)
    
    # Patch the tlslite modules to add debug logging
    import tlslite.tlsrecordlayer as recordlayer
    import tlslite.messages as messages
    
    # Store originals
    orig_sendMsg = recordlayer.TLSRecordLayer._sendMsg
    orig_getMsg = recordlayer.TLSRecordLayer._getMsg
    
    def debug_sendMsg(self, msg, padding=0):
        """Debug wrapper for _sendMsg"""
        msg_type = type(msg).__name__
        print(f"\n>>> SENDING: {msg_type}")
        if hasattr(msg, 'contentType'):
            ct = msg.contentType
            ct_name = {
                20: 'change_cipher_spec',
                21: 'alert',
                22: 'handshake',
                23: 'application_data'
            }.get(ct, str(ct))
            print(f"    Content-Type: {ct_name} ({ct})")
        if hasattr(msg, 'handshakeType'):
            ht = msg.handshakeType if hasattr(msg, 'handshakeType') else getattr(msg, 'type', None)
            ht_name = {
                0: 'hello_request',
                1: 'client_hello',
                2: 'server_hello',
                4: 'new_session_ticket',
                11: 'certificate',
                12: 'server_key_exchange',
                13: 'certificate_request',
                14: 'server_hello_done',
                15: 'certificate_verify',
                16: 'client_key_exchange',
                20: 'finished',
            }.get(ht, str(ht))
            print(f"    Handshake-Type: {ht_name} ({ht})")
        return orig_sendMsg(self, msg, padding)
    
    # Patch
    recordlayer.TLSRecordLayer._sendMsg = debug_sendMsg
    
    try:
        # Create TCP socket
        print("\n[1] Creating TCP connection to www.google.com:443...")
        sock = socket.create_connection(('www.google.com', 443), timeout=30)
        print(f"    ✓ TCP connected: {sock.getpeername()}")
        
        # Wrap with TLS
        print("\n[2] Creating TLSConnection...")
        tls = TLSConnection(sock)
        
        # Create settings for TLS 1.2
        settings = HandshakeSettings()
        settings.minVersion = (3, 3)
        settings.maxVersion = (3, 3)
        
        print("\n[3] Starting TLS handshake...")
        print("-" * 50)
        
        # Use the generator interface to see each step
        handshaker = tls._handshakeClientAsync(
            certParams=(None, None),
            session=None,
            settings=settings,
            serverName='www.google.com'
        )
        
        for result in handshaker:
            pass
        
        print("-" * 50)
        print("\n[4] Handshake completed!")
        print(f"    Version: {tls.version}")
        print(f"    Cipher: 0x{tls.session.cipherSuite:04x}")
        
        # Clean up
        tls.close()
        
    finally:
        # Restore originals
        recordlayer.TLSRecordLayer._sendMsg = orig_sendMsg


def test_trace_messages():
    """Test that traces all handshake messages received"""
    print("\n" + "=" * 70)
    print("TRACE ALL HANDSHAKE MESSAGES")
    print("=" * 70)
    
    import tlslite.tlsrecordlayer as recordlayer
    import tlslite.defragmenter as defragmenter
    import tlslite.messages as messages
    
    # Message type names
    handshake_types = {
        0: 'HelloRequest',
        1: 'ClientHello',
        2: 'ServerHello',
        4: 'NewSessionTicket',
        11: 'Certificate',
        12: 'ServerKeyExchange',
        13: 'CertificateRequest',
        14: 'ServerHelloDone',
        15: 'CertificateVerify',
        16: 'ClientKeyExchange',
        20: 'Finished',
    }
    
    content_types = {
        20: 'ChangeCipherSpec',
        21: 'Alert',
        22: 'Handshake',
        23: 'ApplicationData'
    }
    
    # Patch _recvMsg to log received messages
    orig_recvMsg = recordlayer.TLSRecordLayer._recvMsg
    
    def debug_recvMsg(self, *args, **kwargs):
        result = orig_recvMsg(self, *args, **kwargs)
        if result is not None:
            for item in result:
                if isinstance(item, int):
                    continue
                msg = item
                ct = getattr(msg, 'contentType', None)
                ct_name = content_types.get(ct, str(ct))
                
                if ct == 22:  # Handshake
                    # Get handshake type from first byte of write() output
                    ht = None
                    if hasattr(msg, 'msg_type'):
                        ht = msg.msg_type
                    elif hasattr(msg, 'handshakeType'):
                        ht = msg.handshakeType
                    ht_name = handshake_types.get(ht, str(ht))
                    print(f"<<< RECEIVED: {ct_name} / {ht_name}")
                else:
                    print(f"<<< RECEIVED: {ct_name}")
        return result
    
    recordlayer.TLSRecordLayer._recvMsg = debug_recvMsg
    
    try:
        print("\n[1] Connecting to www.google.com:443...")
        sock = socket.create_connection(('www.google.com', 443), timeout=30)
        tls = TLSConnection(sock)
        
        settings = HandshakeSettings()
        settings.minVersion = (3, 3)
        settings.maxVersion = (3, 3)
        
        print("\n[2] Performing handshake...")
        print("-" * 50)
        
        tls.handshakeClientCert(
            settings=settings,
            serverName='www.google.com'
        )
        
        print("-" * 50)
        print("\n[3] Handshake completed!")
        print(f"    Version: {tls.version}")
        print(f"    Cipher: 0x{tls.session.cipherSuite:04x}")
        
        tls.close()
        
    finally:
        recordlayer.TLSRecordLayer._recvMsg = orig_recvMsg


def test_key_exchange_details():
    """Test that shows key exchange algorithm details"""
    print("\n" + "=" * 70)
    print("KEY EXCHANGE ALGORITHM DETAILS")
    print("=" * 70)
    
    import tlslite.tlsconnection as tlsconn
    import tlslite.keyexchange as keyexchange
    
    # Patch _clientKeyExchange to see details
    orig_clientKeyExchange = tlsconn.TLSConnection._clientKeyExchange
    
    def debug_clientKeyExchange(self, settings, cipherSuite, clientCertChain,
                                 privateKey, certificateType, tackExt,
                                 clientRandom, serverRandom, keyExchange):
        print(f"\n[KEY EXCHANGE]")
        print(f"    Cipher suite: 0x{cipherSuite:04x}")
        print(f"    Key exchange type: {type(keyExchange).__name__}")
        
        # Call original
        gen = orig_clientKeyExchange(self, settings, cipherSuite, clientCertChain,
                                     privateKey, certificateType, tackExt,
                                     clientRandom, serverRandom, keyExchange)
        for result in gen:
            yield result
    
    tlsconn.TLSConnection._clientKeyExchange = debug_clientKeyExchange
    
    try:
        print("\n[1] Connecting to www.google.com:443...")
        sock = socket.create_connection(('www.google.com', 443), timeout=30)
        tls = TLSConnection(sock)
        
        settings = HandshakeSettings()
        settings.minVersion = (3, 3)
        settings.maxVersion = (3, 3)
        
        print("\n[2] Performing handshake...")
        print("-" * 50)
        
        tls.handshakeClientCert(
            settings=settings,
            serverName='www.google.com'
        )
        
        print("-" * 50)
        print("\n[3] Handshake completed!")
        print(f"    Version: {tls.version}")
        print(f"    Cipher: 0x{tls.session.cipherSuite:04x}")
        
        # Print cipher suite info
        cs = tls.session.cipherSuite
        if cs in CipherSuite.ecdhAllSuites:
            print(f"    Type: ECDH key exchange")
        elif cs in CipherSuite.dhAllSuites:
            print(f"    Type: DH key exchange")
        elif cs in CipherSuite.certAllSuites:
            print(f"    Type: RSA key exchange")
        
        tls.close()
        
    finally:
        tlsconn.TLSConnection._clientKeyExchange = orig_clientKeyExchange


def test_handshake_step_by_step():
    """Test that shows step by step handshake processing"""
    print("\n" + "=" * 70)
    print("STEP BY STEP HANDSHAKE")
    print("=" * 70)
    
    import tlslite.tlsconnection as tlsconn
    
    # Patch _clientGetServerHello
    orig_getServerHello = tlsconn.TLSConnection._clientGetServerHello
    
    def debug_getServerHello(self, settings, session, clientHello):
        print("\n[STEP] _clientGetServerHello")
        print(f"    Waiting for ServerHello...")
        gen = orig_getServerHello(self, settings, session, clientHello)
        for result in gen:
            if isinstance(result, int):
                yield result
            else:
                serverHello = result
                print(f"    ServerHello received:")
                print(f"      - Version: {serverHello.server_version}")
                print(f"      - Cipher: 0x{serverHello.cipher_suite:04x}")
                print(f"      - Session ID: {serverHello.session_id.hex()[:32]}...")
                print(f"      - Random: {serverHello.random.hex()[:32]}...")
                yield result
    
    tlsconn.TLSConnection._clientGetServerHello = debug_getServerHello
    
    try:
        print("\n[1] Connecting to www.google.com:443...")
        sock = socket.create_connection(('www.google.com', 443), timeout=30)
        tls = TLSConnection(sock)
        
        settings = HandshakeSettings()
        settings.minVersion = (3, 3)
        settings.maxVersion = (3, 3)
        
        print("\n[2] Starting handshake...")
        print("-" * 50)
        
        tls.handshakeClientCert(
            settings=settings,
            serverName='www.google.com'
        )
        
        print("-" * 50)
        print("\n[3] Handshake completed successfully!")
        
        tls.close()
        
    finally:
        tlsconn.TLSConnection._clientGetServerHello = orig_getServerHello


def test_show_all_messages():
    """Most comprehensive test - shows all messages in handshake"""
    print("\n" + "=" * 70)
    print("COMPREHENSIVE MESSAGE TRACE")
    print("(Compare this output with Dart implementation)")
    print("=" * 70)
    
    import tlslite.tlsconnection as tlsconn
    import tlslite.tlsrecordlayer as rl
    
    handshake_types = {
        0: 'HelloRequest',
        1: 'ClientHello',
        2: 'ServerHello',
        4: 'NewSessionTicket',
        8: 'EncryptedExtensions',
        11: 'Certificate',
        12: 'ServerKeyExchange',
        13: 'CertificateRequest',
        14: 'ServerHelloDone',
        15: 'CertificateVerify',
        16: 'ClientKeyExchange',
        20: 'Finished',
    }
    
    # Patch _handshakeClientAsyncHelper to trace flow
    orig_helper = tlsconn.TLSConnection._handshakeClientAsyncHelper
    
    def trace_helper(self, srpParams, certParams, anonParams,
                     session, settings, serverName, nextProtos,
                     reqTack, alpn):
        print(f"\n>>> Starting handshake with serverName={serverName}")
        print(f"    Settings: minVersion={settings.minVersion}, maxVersion={settings.maxVersion}")
        
        gen = orig_helper(self, srpParams, certParams, anonParams,
                          session, settings, serverName, nextProtos,
                          reqTack, alpn)
        for result in gen:
            yield result
    
    tlsconn.TLSConnection._handshakeClientAsyncHelper = trace_helper
    
    # Also patch _getNextRecord to see raw records
    orig_getMsg = rl.TLSRecordLayer._getMsg
    message_counter = [0]
    
    def trace_getMsg(self, expectedType, secondaryType=None, constructorType=None):
        gen = orig_getMsg(self, expectedType, secondaryType, constructorType)
        for result in gen:
            if isinstance(result, int):
                yield result
            else:
                message_counter[0] += 1
                msg = result
                msg_type = type(msg).__name__
                
                # Try to get handshake type
                ht = getattr(msg, 'msg_type', getattr(msg, 'handshakeType', None))
                ht_name = handshake_types.get(ht, str(ht)) if ht else ''
                
                print(f"\n<<< [{message_counter[0]}] RECEIVED: {msg_type}")
                if ht_name:
                    print(f"    Handshake type: {ht_name} ({ht})")
                    
                # Print specific message details
                if msg_type == 'ServerHello':
                    print(f"    Version: {msg.server_version}")
                    print(f"    Cipher: 0x{msg.cipher_suite:04x}")
                    # Check for cipher suite type
                    cs = msg.cipher_suite
                    if cs in CipherSuite.ecdhAllSuites:
                        print(f"    >>> This is ECDHE cipher - expect ServerKeyExchange!")
                    elif cs in CipherSuite.dhAllSuites:
                        print(f"    >>> This is DHE cipher - expect ServerKeyExchange!")
                    elif cs in CipherSuite.certAllSuites:
                        print(f"    >>> This is RSA cipher - NO ServerKeyExchange expected!")
                elif msg_type == 'Certificate':
                    print(f"    Certificate chain length: {len(msg.cert_chain.x509List) if hasattr(msg, 'cert_chain') else 'N/A'}")
                elif msg_type == 'ServerKeyExchange':
                    print(f"    >>> ServerKeyExchange received (expected for DHE/ECDHE)")
                elif msg_type == 'ServerHelloDone':
                    print(f"    >>> Server finished sending (ServerHelloDone)")
                    
                yield result
    
    rl.TLSRecordLayer._getMsg = trace_getMsg
    
    try:
        print("\n[1] Connecting to www.google.com:443...")
        sock = socket.create_connection(('www.google.com', 443), timeout=30)
        tls = TLSConnection(sock)
        
        settings = HandshakeSettings()
        settings.minVersion = (3, 3)
        settings.maxVersion = (3, 3)
        
        print("\n[2] Performing full handshake...")
        print("=" * 50)
        
        tls.handshakeClientCert(
            settings=settings,
            serverName='www.google.com'
        )
        
        print("=" * 50)
        print("\n[3] HANDSHAKE COMPLETED SUCCESSFULLY!")
        print(f"    Final version: {tls.version}")
        print(f"    Final cipher: 0x{tls.session.cipherSuite:04x}")
        
        # Analyze cipher
        cs = tls.session.cipherSuite
        print(f"\n[4] Cipher suite analysis:")
        if cs in CipherSuite.ecdhAllSuites:
            print(f"    Type: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)")
            print(f"    ServerKeyExchange WAS required and received")
        elif cs in CipherSuite.dhAllSuites:
            print(f"    Type: DHE (Diffie-Hellman Ephemeral)")
            print(f"    ServerKeyExchange WAS required and received")
        elif cs in CipherSuite.certAllSuites:
            print(f"    Type: RSA key exchange")
            print(f"    ServerKeyExchange NOT required")
        
        tls.close()
        
    finally:
        tlsconn.TLSConnection._handshakeClientAsyncHelper = orig_helper
        rl.TLSRecordLayer._getMsg = orig_getMsg


if __name__ == '__main__':
    print("=" * 70)
    print("DETAILED TLS DEBUG - Compare with Dart port")
    print("=" * 70)
    
    # Run the comprehensive test
    test_show_all_messages()
