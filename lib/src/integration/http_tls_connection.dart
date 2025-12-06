import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

import '../tlsconnection.dart';
import '../handshake_settings.dart';
import '../checker.dart';
import '../utils/rsakey.dart';
import '../x509certchain.dart';
import '../constants.dart';
import '../recordlayer.dart';
import '../errors.dart';

/// This class mimics Python's httplib.HTTPConnection but with TLS support via TlsConnection.
///
/// It is a basic implementation for integration testing purposes.
class HttpTlsConnection {
  final String host;
  final int port;
  final String? username;
  final String? password;
  final X509CertChain? certChain;
  final RSAKey? privateKey;
  final Checker? checker;
  final HandshakeSettings? settings;
  final bool ignoreAbruptClose;
  final bool anon;

  TlsConnection? _connection;
  Socket? _socket;

  HttpTlsConnection(
    this.host, {
    this.port = 443,
    this.username,
    this.password,
    this.certChain,
    this.privateKey,
    this.checker,
    this.settings,
    this.ignoreAbruptClose = false,
    this.anon = false,
  });

  Future<void> connect() async {
    _socket = await Socket.connect(host, port);
    _connection = TlsConnection(_socket!);

    // Perform handshake
    if (username != null && password != null) {
      await _connection!.handshakeClient(
        settings: settings,
        srpUsername: username!,
        srpParams: (username, password),
        serverName: host,
      );
    } else if (anon) {
      await _connection!.handshakeClient(
        settings: settings,
        anonParams: true,
        serverName: host,
      );
    } else {
      // Certificate based (or just server auth)
      // FUTURE: Add client certificate support via certParams when needed
      await _connection!.handshakeClient(
        settings: settings,
        serverName: host,
        // certParams: ...
      );
    }

    if (checker != null) {
      checker!(_connection);
    }
  }

  Future<void> request(String method, String url,
      {Map<String, String>? headers, List<int>? body}) async {
    if (_connection == null) {
      await connect();
    }

    final buf = StringBuffer();
    buf.write('$method $url HTTP/1.1\r\n');
    buf.write('Host: $host\r\n');
    if (headers != null) {
      headers.forEach((k, v) {
        buf.write('$k: $v\r\n');
      });
    }
    if (body != null && body.isNotEmpty) {
      buf.write('Content-Length: ${body.length}\r\n');
    }
    buf.write('\r\n');

    await _write(Uint8List.fromList(utf8.encode(buf.toString())));
    if (body != null && body.isNotEmpty) {
      await _write(Uint8List.fromList(body));
    }
  }

  Future<HttpResponseMock> getResponse() async {
    if (_connection == null) {
      throw StateError('Not connected');
    }
    
    // Very basic HTTP parsing
    final buffer = <int>[];
    while (true) {
      final chunk = await _read(1024);
      if (chunk.isEmpty) break; // EOF
      buffer.addAll(chunk);
      
      // Check for header end
      final headerEnd = _findHeaderEnd(buffer);
      if (headerEnd != -1) {
        // Parse headers...
        // For now just return the raw body
        return HttpResponseMock(200, 'OK', Uint8List.fromList(buffer));
      }
    }
    return HttpResponseMock(500, 'Error', Uint8List(0));
  }

  int _findHeaderEnd(List<int> data) {
    for (var i = 0; i < data.length - 3; i++) {
      if (data[i] == 13 && data[i+1] == 10 && data[i+2] == 13 && data[i+3] == 10) {
        return i + 4;
      }
    }
    return -1;
  }

  Future<void> close() async {
    await _connection?.sock?.close();
    await _socket?.close();
  }

  // Helper methods
  Future<void> _write(Uint8List data) async {
    int offset = 0;
    const int maxRecordSize = 16384;
    while (offset < data.length) {
      int end = offset + maxRecordSize;
      if (end > data.length) end = data.length;
      final chunk = data.sublist(offset, end);
      await _connection!
          .sendRecord(Message(ContentType.application_data, chunk));
      offset = end;
    }
  }

  final List<int> _readBuffer = [];

  Future<List<int>> _read(int max) async {
    while (_readBuffer.length < max) {
      try {
        final (header, parser) = await _connection!.recvMessage();

        int type;
        if (header is RecordHeader3) {
          type = header.type;
        } else {
          // Fallback for SSLv2 or unknown
          continue;
        }

        final payload = parser.getFixBytes(parser.getRemainingLength());

        if (type == ContentType.application_data) {
          _readBuffer.addAll(payload);
        } else if (type == ContentType.alert) {
          if (payload.isNotEmpty) {
            // Alert: Level, Description
            if (payload[0] == 1 && payload[1] == 0) {
              break; // close_notify
            }
            if (payload[0] == 2) {
              throw TLSRemoteAlert(payload[1], payload[0]);
            }
          }
        }
      } catch (e) {
        break;
      }
    }

    int len = max;
    if (_readBuffer.length < len) len = _readBuffer.length;
    if (len == 0) return [];

    final result = _readBuffer.sublist(0, len);
    _readBuffer.removeRange(0, len);
    return result;
  }
}

class HttpResponseMock {
  final int status;
  final String reason;
  final Uint8List body;
  HttpResponseMock(this.status, this.reason, this.body);
}
