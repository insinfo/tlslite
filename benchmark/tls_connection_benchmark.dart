// ignore_for_file: avoid_print
/// Benchmark comparing TLS implementations:
/// 1. TlsConnection (pure Dart TLS implementation)
/// 2. SecureSocketOpenSSLAsync (FFI-based OpenSSL wrapper)
/// 3. SecureSocket from dart:io (Dart's native secure socket)
///
/// This benchmark measures:
/// - Handshake latency
/// - Data throughput (send/receive)
/// - Connection establishment time
/// - Large file download performance (using Hetzner speed test servers)

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

import 'package:tlslite/src/tls_connection.dart';
import 'package:tlslite/src/handshake_settings.dart';
import 'package:tlslite/src/constants.dart';
import 'package:tlslite/src/recordlayer.dart';
import 'package:tlslite/src/net/secure_socket_openssl_async.dart';

/// Hetzner Speed Test Servers
class HetznerServer {
  final String name;
  final String host;
  final String region;

  const HetznerServer(this.name, this.host, this.region);

  static const ash = HetznerServer('ASH', 'ash-speed.hetzner.com', 'USA (Ashburn)');
  static const fsn1 = HetznerServer('FSN1', 'fsn1-speed.hetzner.com', 'Germany (Falkenstein)');
  static const nbg1 = HetznerServer('NBG1', 'nbg1-speed.hetzner.com', 'Germany (Nuremberg)');
  static const hel1 = HetznerServer('HEL1', 'hel1-speed.hetzner.com', 'Finland (Helsinki)');
  static const sin = HetznerServer('SIN', 'sin-speed.hetzner.com', 'Singapore');

  static const all = [ash, fsn1, nbg1, hel1, sin];
}

/// Download file sizes available on Hetzner
enum DownloadSize {
  mb100('100MB.bin', 100 * 1024 * 1024),
  gb1('1GB.bin', 1024 * 1024 * 1024),
  gb10('10GB.bin', 10 * 1024 * 1024 * 1024);

  final String filename;
  final int expectedBytes;

  const DownloadSize(this.filename, this.expectedBytes);
}

/// Configuration for benchmark runs
class BenchmarkConfig {
  final String host;
  final int port;
  final int iterations;
  final int dataSizeKb;
  final bool verbose;
  final String? downloadPath;
  final int? downloadLimitBytes;
  final Duration timeout;

  const BenchmarkConfig({
    this.host = 'www.google.com',
    this.port = 443,
    this.iterations = 5,
    this.dataSizeKb = 16,
    this.verbose = true,
    this.downloadPath,
    this.downloadLimitBytes,
    this.timeout = const Duration(seconds: 60),
  });

  BenchmarkConfig copyWith({
    String? host,
    int? port,
    int? iterations,
    int? dataSizeKb,
    bool? verbose,
    String? downloadPath,
    int? downloadLimitBytes,
    Duration? timeout,
  }) =>
      BenchmarkConfig(
        host: host ?? this.host,
        port: port ?? this.port,
        iterations: iterations ?? this.iterations,
        dataSizeKb: dataSizeKb ?? this.dataSizeKb,
        verbose: verbose ?? this.verbose,
        downloadPath: downloadPath ?? this.downloadPath,
        downloadLimitBytes: downloadLimitBytes ?? this.downloadLimitBytes,
        timeout: timeout ?? this.timeout,
      );
}

/// Results from a single benchmark run
class BenchmarkResult {
  final String name;
  final Duration connectTime;
  final Duration handshakeTime;
  final Duration requestTime;
  final Duration totalTime;
  final int bytesReceived;
  final String? error;

  BenchmarkResult({
    required this.name,
    required this.connectTime,
    required this.handshakeTime,
    required this.requestTime,
    required this.totalTime,
    required this.bytesReceived,
    this.error,
  });

  factory BenchmarkResult.error(String name, String error) => BenchmarkResult(
        name: name,
        connectTime: Duration.zero,
        handshakeTime: Duration.zero,
        requestTime: Duration.zero,
        totalTime: Duration.zero,
        bytesReceived: 0,
        error: error,
      );

  double get throughputKbps =>
      totalTime.inMicroseconds > 0
          ? (bytesReceived / 1024) / (totalTime.inMicroseconds / 1000000)
          : 0;

  double get throughputMbps => throughputKbps / 1024;

  String get throughputFormatted {
    if (throughputMbps >= 1) {
      return '${throughputMbps.toStringAsFixed(2)} MB/s';
    }
    return '${throughputKbps.toStringAsFixed(2)} KB/s';
  }

  String get bytesFormatted {
    if (bytesReceived >= 1024 * 1024 * 1024) {
      return '${(bytesReceived / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
    } else if (bytesReceived >= 1024 * 1024) {
      return '${(bytesReceived / (1024 * 1024)).toStringAsFixed(2)} MB';
    } else if (bytesReceived >= 1024) {
      return '${(bytesReceived / 1024).toStringAsFixed(2)} KB';
    }
    return '$bytesReceived bytes';
  }

  @override
  String toString() {
    if (error != null) {
      return '$name: ERROR - $error';
    }
    return '$name: '
        'connect=${connectTime.inMilliseconds}ms, '
        'handshake=${handshakeTime.inMilliseconds}ms, '
        'request=${requestTime.inMilliseconds}ms, '
        'total=${totalTime.inMilliseconds}ms, '
        'received=$bytesFormatted, '
        'throughput=$throughputFormatted';
  }
}

/// Aggregate benchmark results
class AggregateResult {
  final String name;
  final List<BenchmarkResult> results;

  AggregateResult(this.name, this.results);

  List<BenchmarkResult> get successfulResults =>
      results.where((r) => r.error == null).toList();

  double get avgConnectMs =>
      successfulResults.isEmpty
          ? 0
          : successfulResults.map((r) => r.connectTime.inMilliseconds).reduce((a, b) => a + b) / successfulResults.length;

  double get avgHandshakeMs =>
      successfulResults.isEmpty
          ? 0
          : successfulResults.map((r) => r.handshakeTime.inMilliseconds).reduce((a, b) => a + b) / successfulResults.length;

  double get avgRequestMs =>
      successfulResults.isEmpty
          ? 0
          : successfulResults.map((r) => r.requestTime.inMilliseconds).reduce((a, b) => a + b) / successfulResults.length;

  double get avgTotalMs =>
      successfulResults.isEmpty
          ? 0
          : successfulResults.map((r) => r.totalTime.inMilliseconds).reduce((a, b) => a + b) / successfulResults.length;

  double get avgThroughputKbps =>
      successfulResults.isEmpty
          ? 0
          : successfulResults.map((r) => r.throughputKbps).reduce((a, b) => a + b) / successfulResults.length;

  double get avgThroughputMbps => avgThroughputKbps / 1024;

  int get totalBytesReceived =>
      successfulResults.isEmpty
          ? 0
          : successfulResults.map((r) => r.bytesReceived).reduce((a, b) => a + b);

  int get successCount => successfulResults.length;

  String get throughputFormatted {
    if (avgThroughputMbps >= 1) {
      return '${avgThroughputMbps.toStringAsFixed(2)} MB/s';
    }
    return '${avgThroughputKbps.toStringAsFixed(2)} KB/s';
  }

  @override
  String toString() => '$name: '
      'success=${successCount}/${results.length}, '
      'avgConnect=${avgConnectMs.toStringAsFixed(1)}ms, '
      'avgHandshake=${avgHandshakeMs.toStringAsFixed(1)}ms, '
      'avgRequest=${avgRequestMs.toStringAsFixed(1)}ms, '
      'avgTotal=${avgTotalMs.toStringAsFixed(1)}ms, '
      'avgThroughput=$throughputFormatted';
}

/// Format bytes to human readable string
String _formatBytes(int bytes) {
  if (bytes >= 1024 * 1024 * 1024) {
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  } else if (bytes >= 1024 * 1024) {
    return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
  } else if (bytes >= 1024) {
    return '${(bytes / 1024).toStringAsFixed(2)} KB';
  }
  return '$bytes bytes';
}

/// Abstract benchmark runner
abstract class TlsBenchmark {
  String get name;

  Future<BenchmarkResult> runOnce(BenchmarkConfig config);

  Future<AggregateResult> run(BenchmarkConfig config) async {
    final results = <BenchmarkResult>[];
    for (var i = 0; i < config.iterations; i++) {
      if (config.verbose) {
        print('  $name iteration ${i + 1}/${config.iterations}...');
      }
      try {
        final result = await runOnce(config);
        results.add(result);
        if (config.verbose) {
          print('    $result');
        }
      } catch (e, st) {
        results.add(BenchmarkResult.error(name, e.toString()));
        if (config.verbose) {
          print('    ERROR: $e');
          print('    Stack: $st');
        }
      }
      // Small delay between iterations to avoid throttling
      await Future.delayed(const Duration(milliseconds: 200));
    }
    return AggregateResult(name, results);
  }
}

/// Progress callback for download benchmarks
typedef ProgressCallback = void Function(int bytesReceived, int? totalBytes, double? mbps);

/// Benchmark for TlsConnection (pure Dart TLS) with large file download support
class TlsConnectionBenchmark extends TlsBenchmark {
  @override
  String get name => 'TlsConnection (pure Dart)';

  @override
  Future<BenchmarkResult> runOnce(BenchmarkConfig config) async {
    final stopwatch = Stopwatch()..start();
    var connectTime = Duration.zero;
    var handshakeTime = Duration.zero;
    var requestTime = Duration.zero;
    var bytesReceived = 0;

    Socket? socket;
    try {
      // Connect
      final connectStart = stopwatch.elapsed;
      socket = await Socket.connect(config.host, config.port,
          timeout: config.timeout);
      connectTime = stopwatch.elapsed - connectStart;

      // Handshake
      final handshakeStart = stopwatch.elapsed;
      final tls = TlsConnection(socket);
      await tls.handshakeClient(
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2
          maxVersion: (3, 3), // TLS 1.3
        ),
        serverName: config.host,
      );
      handshakeTime = stopwatch.elapsed - handshakeStart;

      if (config.verbose) {
        print('    ✓ Negotiated version: ${tls.version}');
        print('    ✓ Cipher suite: 0x${tls.session.cipherSuite.toRadixString(16)}');
      }

      // Request
      final requestStart = stopwatch.elapsed;
      final path = config.downloadPath ?? '/';
      final request = 'GET $path HTTP/1.1\r\n'
          'Host: ${config.host}\r\n'
          'User-Agent: TlsLite-Benchmark/1.0\r\n'
          'Connection: close\r\n'
          'Accept: */*\r\n'
          '\r\n';
      await tls.sendRecord(Message(
        ContentType.application_data,
        Uint8List.fromList(utf8.encode(request)),
      ));

      // Read response
      var headersParsed = false;
      var contentLength = -1;
      final headerBuffer = StringBuffer();
      var lastProgressTime = stopwatch.elapsed;

      while (true) {
        try {
          final (header, parser) = await tls.recvMessage().timeout(config.timeout);
          if (header.type != ContentType.application_data) continue;
          
          final data = parser.getFixBytes(parser.getRemainingLength());
          if (data.isEmpty) break;

          if (!headersParsed) {
            // Parse HTTP headers
            headerBuffer.write(utf8.decode(data, allowMalformed: true));
            final headers = headerBuffer.toString();
            final headerEnd = headers.indexOf('\r\n\r\n');
            if (headerEnd != -1) {
              headersParsed = true;
              // Extract content-length
              final clMatch = RegExp(r'content-length:\s*(\d+)', caseSensitive: false)
                  .firstMatch(headers);
              if (clMatch != null) {
                contentLength = int.parse(clMatch.group(1)!);
              }
              // Count body bytes after headers
              final bodyStart = headerEnd + 4;
              if (bodyStart < headers.length) {
                bytesReceived += headers.length - bodyStart;
              }
            }
          } else {
            bytesReceived += data.length;
          }

          // Progress reporting for large downloads
          if (config.verbose && 
              stopwatch.elapsed - lastProgressTime > const Duration(seconds: 2)) {
            final elapsed = stopwatch.elapsed - requestStart;
            final mbps = elapsed.inMicroseconds > 0
                ? (bytesReceived / (1024 * 1024)) / (elapsed.inMicroseconds / 1000000)
                : 0.0;
            final progress = contentLength > 0 
                ? ' (${(bytesReceived * 100 / contentLength).toStringAsFixed(1)}%)'
                : '';
            print('    ↓ ${_formatBytes(bytesReceived)}$progress @ ${mbps.toStringAsFixed(2)} MB/s');
            lastProgressTime = stopwatch.elapsed;
          }

          // Check download limit
          if (config.downloadLimitBytes != null && 
              bytesReceived >= config.downloadLimitBytes!) {
            break;
          }

          // Check if complete
          if (contentLength > 0 && bytesReceived >= contentLength) break;
        } on TimeoutException {
          break;
        } catch (e) {
          if (config.verbose) print('    Read error: $e');
          break;
        }
      }
      requestTime = stopwatch.elapsed - requestStart;

      final totalTime = stopwatch.elapsed;
      return BenchmarkResult(
        name: name,
        connectTime: connectTime,
        handshakeTime: handshakeTime,
        requestTime: requestTime,
        totalTime: totalTime,
        bytesReceived: bytesReceived,
      );
    } finally {
      try {
        await socket?.close();
      } catch (_) {}
    }
  }
}

/// Benchmark for SecureSocketOpenSSLAsync (FFI OpenSSL) with large file download support
class SecureSocketOpenSSLBenchmark extends TlsBenchmark {
  @override
  String get name => 'SecureSocketOpenSSLAsync (FFI)';

  @override
  Future<BenchmarkResult> runOnce(BenchmarkConfig config) async {
    final stopwatch = Stopwatch()..start();
    var connectTime = Duration.zero;
    var handshakeTime = Duration.zero;
    var requestTime = Duration.zero;
    var bytesReceived = 0;

    SecureSocketOpenSSLAsync? secureSocket;
    try {
      // Connect
      final connectStart = stopwatch.elapsed;
      secureSocket = await SecureSocketOpenSSLAsync.connect(
        config.host,
        config.port,
        eagerHandshake: false,
        timeout: config.timeout,
      );
      connectTime = stopwatch.elapsed - connectStart;

      // Handshake
      final handshakeStart = stopwatch.elapsed;
      await secureSocket.ensureHandshakeCompleted();
      handshakeTime = stopwatch.elapsed - handshakeStart;

      // Request
      final requestStart = stopwatch.elapsed;
      final path = config.downloadPath ?? '/';
      final request = 'GET $path HTTP/1.1\r\n'
          'Host: ${config.host}\r\n'
          'User-Agent: TlsLite-Benchmark-OpenSSL/1.0\r\n'
          'Connection: close\r\n'
          'Accept: */*\r\n'
          '\r\n';
      await secureSocket.send(Uint8List.fromList(utf8.encode(request)));

      // Read response
      var headersParsed = false;
      var contentLength = -1;
      final headerBuffer = StringBuffer();
      var lastProgressTime = stopwatch.elapsed;

      while (true) {
        try {
          final data = await secureSocket.recv(65536).timeout(config.timeout);
          if (data.isEmpty) break;

          if (!headersParsed) {
            headerBuffer.write(utf8.decode(data, allowMalformed: true));
            final headers = headerBuffer.toString();
            final headerEnd = headers.indexOf('\r\n\r\n');
            if (headerEnd != -1) {
              headersParsed = true;
              final clMatch = RegExp(r'content-length:\s*(\d+)', caseSensitive: false)
                  .firstMatch(headers);
              if (clMatch != null) {
                contentLength = int.parse(clMatch.group(1)!);
              }
              final bodyStart = headerEnd + 4;
              if (bodyStart < headers.length) {
                bytesReceived += headers.length - bodyStart;
              }
            }
          } else {
            bytesReceived += data.length;
          }

          // Progress reporting
          if (config.verbose && 
              stopwatch.elapsed - lastProgressTime > const Duration(seconds: 2)) {
            final elapsed = stopwatch.elapsed - requestStart;
            final mbps = elapsed.inMicroseconds > 0
                ? (bytesReceived / (1024 * 1024)) / (elapsed.inMicroseconds / 1000000)
                : 0.0;
            final progress = contentLength > 0 
                ? ' (${(bytesReceived * 100 / contentLength).toStringAsFixed(1)}%)'
                : '';
            print('    ↓ ${_formatBytes(bytesReceived)}$progress @ ${mbps.toStringAsFixed(2)} MB/s');
            lastProgressTime = stopwatch.elapsed;
          }

          // Check download limit
          if (config.downloadLimitBytes != null && 
              bytesReceived >= config.downloadLimitBytes!) {
            break;
          }

          if (contentLength > 0 && bytesReceived >= contentLength) break;
        } on TimeoutException {
          break;
        } catch (e) {
          if (config.verbose) print('    Read error: $e');
          break;
        }
      }
      requestTime = stopwatch.elapsed - requestStart;

      final totalTime = stopwatch.elapsed;
      return BenchmarkResult(
        name: name,
        connectTime: connectTime,
        handshakeTime: handshakeTime,
        requestTime: requestTime,
        totalTime: totalTime,
        bytesReceived: bytesReceived,
      );
    } finally {
      try {
        await secureSocket?.close();
      } catch (_) {}
    }
  }
}

/// Benchmark for dart:io SecureSocket with large file download support
class DartSecureSocketBenchmark extends TlsBenchmark {
  @override
  String get name => 'SecureSocket (dart:io)';

  @override
  Future<BenchmarkResult> runOnce(BenchmarkConfig config) async {
    final stopwatch = Stopwatch()..start();
    var connectTime = Duration.zero;
    var handshakeTime = Duration.zero;
    var requestTime = Duration.zero;
    var bytesReceived = 0;

    SecureSocket? secureSocket;
    try {
      // Connect (includes handshake)
      final connectStart = stopwatch.elapsed;
      secureSocket = await SecureSocket.connect(
        config.host,
        config.port,
        timeout: config.timeout,
        onBadCertificate: (_) => true, // Allow all certs for benchmark
      );
      connectTime = stopwatch.elapsed - connectStart;
      handshakeTime = Duration.zero; // Included in connect

      // Request
      final requestStart = stopwatch.elapsed;
      final path = config.downloadPath ?? '/';
      final request = 'GET $path HTTP/1.1\r\n'
          'Host: ${config.host}\r\n'
          'User-Agent: TlsLite-Benchmark-DartIO/1.0\r\n'
          'Connection: close\r\n'
          'Accept: */*\r\n'
          '\r\n';
      secureSocket.write(request);
      await secureSocket.flush();

      // Read response
      final responseCompleter = Completer<void>();
      var headersParsed = false;
      var contentLength = -1;
      final headerBuffer = StringBuffer();
      var lastProgressTime = stopwatch.elapsed;

      secureSocket.listen(
        (data) {
          if (!headersParsed) {
            headerBuffer.write(utf8.decode(data, allowMalformed: true));
            final headers = headerBuffer.toString();
            final headerEnd = headers.indexOf('\r\n\r\n');
            if (headerEnd != -1) {
              headersParsed = true;
              final clMatch = RegExp(r'content-length:\s*(\d+)', caseSensitive: false)
                  .firstMatch(headers);
              if (clMatch != null) {
                contentLength = int.parse(clMatch.group(1)!);
              }
              final bodyStart = headerEnd + 4;
              if (bodyStart < headers.length) {
                bytesReceived += headers.length - bodyStart;
              }
            }
          } else {
            bytesReceived += data.length;
          }

          // Progress reporting
          if (config.verbose && 
              stopwatch.elapsed - lastProgressTime > const Duration(seconds: 2)) {
            final elapsed = stopwatch.elapsed - requestStart;
            final mbps = elapsed.inMicroseconds > 0
                ? (bytesReceived / (1024 * 1024)) / (elapsed.inMicroseconds / 1000000)
                : 0.0;
            final progress = contentLength > 0 
                ? ' (${(bytesReceived * 100 / contentLength).toStringAsFixed(1)}%)'
                : '';
            print('    ↓ ${_formatBytes(bytesReceived)}$progress @ ${mbps.toStringAsFixed(2)} MB/s');
            lastProgressTime = stopwatch.elapsed;
          }

          // Check download limit
          if (config.downloadLimitBytes != null && 
              bytesReceived >= config.downloadLimitBytes!) {
            if (!responseCompleter.isCompleted) {
              responseCompleter.complete();
            }
          }

          // Check if complete
          if (contentLength > 0 && bytesReceived >= contentLength) {
            if (!responseCompleter.isCompleted) {
              responseCompleter.complete();
            }
          }
        },
        onDone: () {
          if (!responseCompleter.isCompleted) {
            responseCompleter.complete();
          }
        },
        onError: (e) {
          if (!responseCompleter.isCompleted) {
            responseCompleter.complete();
          }
        },
        cancelOnError: true,
      );

      await responseCompleter.future.timeout(
        config.timeout,
        onTimeout: () {},
      );
      requestTime = stopwatch.elapsed - requestStart;

      final totalTime = stopwatch.elapsed;
      return BenchmarkResult(
        name: name,
        connectTime: connectTime,
        handshakeTime: handshakeTime,
        requestTime: requestTime,
        totalTime: totalTime,
        bytesReceived: bytesReceived,
      );
    } finally {
      try {
        await secureSocket?.close();
      } catch (_) {}
    }
  }
}

/// Main benchmark runner
Future<void> main(List<String> args) async {
  print('═══════════════════════════════════════════════════════════════════════════');
  print('                    TLS Implementation Benchmark');
  print('═══════════════════════════════════════════════════════════════════════════');
  print('');
  print('Comparing:');
  print('  1. TlsConnection (pure Dart TLS implementation)');
  print('  2. SecureSocketOpenSSLAsync (FFI-based OpenSSL wrapper)');
  print('  3. SecureSocket from dart:io (Dart\'s native secure socket)');
  print('');

  // Parse command line arguments
  final mode = args.isNotEmpty ? args[0] : 'quick';
  final serverArg = args.length > 1 ? args[1] : 'ash';

  print('Usage: dart run benchmark/tls_connection_benchmark.dart [mode] [server]');
  print('');
  print('Modes:');
  print('  quick     - Quick test with small HTTP request (default)');
  print('  download  - Download test with 100MB file');
  print('  speed     - Full speed test with download limit (10MB)');
  print('  all       - Run all tests on all servers');
  print('');
  print('Hetzner Speed Test Servers:');
  for (final server in HetznerServer.all) {
    print('  ${server.name.toLowerCase().padRight(6)} - ${server.host} (${server.region})');
  }
  print('');

  final benchmarks = <TlsBenchmark>[
    DartSecureSocketBenchmark(),
    SecureSocketOpenSSLBenchmark(),
    TlsConnectionBenchmark(),
  ];

  switch (mode) {
    case 'quick':
      await _runQuickBenchmark(benchmarks);
      break;
    case 'download':
      await _runDownloadBenchmark(benchmarks, serverArg);
      break;
    case 'speed':
      await _runSpeedTest(benchmarks, serverArg);
      break;
    case 'all':
      await _runAllServersBenchmark(benchmarks);
      break;
    default:
      print('Unknown mode: $mode');
      exit(1);
  }

  exit(0);
}

/// Quick benchmark with simple HTTP request
Future<void> _runQuickBenchmark(List<TlsBenchmark> benchmarks) async {
  print('═══════════════════════════════════════════════════════════════════════════');
  print('                      QUICK BENCHMARK (HTTP Request)');
  print('═══════════════════════════════════════════════════════════════════════════');
  print('');

  final config = BenchmarkConfig(
    host: 'www.google.com',
    port: 443,
    iterations: 3,
    verbose: true,
    timeout: const Duration(seconds: 30),
  );

  print('Configuration:');
  print('  Host: ${config.host}:${config.port}');
  print('  Iterations: ${config.iterations}');
  print('');

  final results = await _runBenchmarks(benchmarks, config);
  _printSummary(results);
}

/// Download benchmark with large file
Future<void> _runDownloadBenchmark(List<TlsBenchmark> benchmarks, String serverArg) async {
  final server = _getServer(serverArg);

  print('═══════════════════════════════════════════════════════════════════════════');
  print('              DOWNLOAD BENCHMARK - ${server.name} (${server.region})');
  print('═══════════════════════════════════════════════════════════════════════════');
  print('');

  final config = BenchmarkConfig(
    host: server.host,
    port: 443,
    iterations: 1,
    verbose: true,
    downloadPath: '/${DownloadSize.mb100.filename}',
    timeout: const Duration(minutes: 10),
  );

  print('Configuration:');
  print('  Server: ${server.host} (${server.region})');
  print('  File: ${DownloadSize.mb100.filename}');
  print('  Expected size: ${_formatBytes(DownloadSize.mb100.expectedBytes)}');
  print('  Iterations: ${config.iterations}');
  print('');

  final results = await _runBenchmarks(benchmarks, config);
  _printSummary(results, showThroughputMbps: true);
}

/// Speed test with download limit for faster comparison
Future<void> _runSpeedTest(List<TlsBenchmark> benchmarks, String serverArg) async {
  final server = _getServer(serverArg);
  const downloadLimit = 10 * 1024 * 1024; // 10MB limit for quick comparison

  print('═══════════════════════════════════════════════════════════════════════════');
  print('                SPEED TEST - ${server.name} (${server.region})');
  print('═══════════════════════════════════════════════════════════════════════════');
  print('');

  final config = BenchmarkConfig(
    host: server.host,
    port: 443,
    iterations: 3,
    verbose: true,
    downloadPath: '/${DownloadSize.mb100.filename}',
    downloadLimitBytes: downloadLimit,
    timeout: const Duration(minutes: 5),
  );

  print('Configuration:');
  print('  Server: ${server.host} (${server.region})');
  print('  File: ${DownloadSize.mb100.filename}');
  print('  Download limit: ${_formatBytes(downloadLimit)}');
  print('  Iterations: ${config.iterations}');
  print('');

  final results = await _runBenchmarks(benchmarks, config);
  _printSummary(results, showThroughputMbps: true);
}

/// Run benchmark on all Hetzner servers
Future<void> _runAllServersBenchmark(List<TlsBenchmark> benchmarks) async {
  const downloadLimit = 5 * 1024 * 1024; // 5MB limit for each server

  print('═══════════════════════════════════════════════════════════════════════════');
  print('                  ALL SERVERS BENCHMARK');
  print('═══════════════════════════════════════════════════════════════════════════');
  print('');

  final allResults = <String, Map<String, AggregateResult>>{};

  for (final server in HetznerServer.all) {
    print('');
    print('───────────────────────────────────────────────────────────────────────────');
    print('  Testing: ${server.name} - ${server.host} (${server.region})');
    print('───────────────────────────────────────────────────────────────────────────');
    print('');

    final config = BenchmarkConfig(
      host: server.host,
      port: 443,
      iterations: 1,
      verbose: true,
      downloadPath: '/${DownloadSize.mb100.filename}',
      downloadLimitBytes: downloadLimit,
      timeout: const Duration(minutes: 3),
    );

    final results = await _runBenchmarks(benchmarks, config);
    allResults[server.name] = {
      for (final r in results) r.name: r,
    };
  }

  // Print combined summary
  print('');
  print('═══════════════════════════════════════════════════════════════════════════');
  print('                      ALL SERVERS SUMMARY');
  print('═══════════════════════════════════════════════════════════════════════════');
  print('');

  // Table header
  print('┌────────┬────────────────────────────────┬───────────┬───────────────┐');
  print('│ Server │ Implementation                 │ Total (s) │ Throughput    │');
  print('├────────┼────────────────────────────────┼───────────┼───────────────┤');

  for (final serverName in allResults.keys) {
    final serverResults = allResults[serverName]!;
    for (final benchmark in benchmarks) {
      final result = serverResults[benchmark.name];
      if (result != null && result.successCount > 0) {
        final srv = serverName.padRight(6);
        final name = benchmark.name.padRight(30);
        final total = '${(result.avgTotalMs / 1000).toStringAsFixed(2)}s'.padLeft(9);
        final throughput = result.throughputFormatted.padLeft(13);
        print('│ $srv │ $name │ $total │ $throughput │');
      }
    }
    if (serverName != allResults.keys.last) {
      print('├────────┼────────────────────────────────┼───────────┼───────────────┤');
    }
  }
  print('└────────┴────────────────────────────────┴───────────┴───────────────┘');
}

/// Helper to get server by name
HetznerServer _getServer(String name) {
  final lowerName = name.toLowerCase();
  for (final server in HetznerServer.all) {
    if (server.name.toLowerCase() == lowerName) {
      return server;
    }
  }
  print('Unknown server: $name, using ASH (default)');
  return HetznerServer.ash;
}

/// Run benchmarks and collect results
Future<List<AggregateResult>> _runBenchmarks(
  List<TlsBenchmark> benchmarks,
  BenchmarkConfig config,
) async {
  final aggregateResults = <AggregateResult>[];

  for (final benchmark in benchmarks) {
    print('───────────────────────────────────────────────────────────────────────────');
    print('Running: ${benchmark.name}');
    print('───────────────────────────────────────────────────────────────────────────');
    try {
      final result = await benchmark.run(config);
      aggregateResults.add(result);
      print('');
    } catch (e, st) {
      print('BENCHMARK FAILED: $e');
      print('Stack: $st');
      aggregateResults.add(AggregateResult(benchmark.name, []));
    }
  }

  return aggregateResults;
}

/// Print summary table
void _printSummary(List<AggregateResult> aggregateResults, {bool showThroughputMbps = false}) {
  print('');
  print('═══════════════════════════════════════════════════════════════════════════');
  print('                              SUMMARY');
  print('═══════════════════════════════════════════════════════════════════════════');
  print('');

  // Table header
  print('┌─────────────────────────────────┬─────────┬───────────┬─────────┬───────────┬───────────────┐');
  print('│ Implementation                  │ Success │ Connect   │ Handshk │ Total     │ Throughput    │');
  print('├─────────────────────────────────┼─────────┼───────────┼─────────┼───────────┼───────────────┤');

  for (final result in aggregateResults) {
    final name = result.name.padRight(31);
    final success = '${result.successCount}/${result.results.length}'.padLeft(7);
    final connect = '${result.avgConnectMs.toStringAsFixed(0)}ms'.padLeft(9);
    final handshake = '${result.avgHandshakeMs.toStringAsFixed(0)}ms'.padLeft(7);
    final total = result.avgTotalMs >= 1000 
        ? '${(result.avgTotalMs / 1000).toStringAsFixed(1)}s'.padLeft(9)
        : '${result.avgTotalMs.toStringAsFixed(0)}ms'.padLeft(9);
    final throughput = result.throughputFormatted.padLeft(13);
    print('│ $name │ $success │ $connect │ $handshake │ $total │ $throughput │');
  }

  print('└─────────────────────────────────┴─────────┴───────────┴─────────┴───────────┴───────────────┘');
  print('');

  // Find best performers
  if (aggregateResults.where((r) => r.successCount > 0).isNotEmpty) {
    final sortedByTotal = aggregateResults
        .where((r) => r.successCount > 0)
        .toList()
      ..sort((a, b) => a.avgTotalMs.compareTo(b.avgTotalMs));

    if (sortedByTotal.isNotEmpty) {
      print('🏆 Fastest (total time): ${sortedByTotal.first.name}');
    }

    final sortedByHandshake = aggregateResults
        .where((r) => r.successCount > 0 && r.avgHandshakeMs > 0)
        .toList()
      ..sort((a, b) => a.avgHandshakeMs.compareTo(b.avgHandshakeMs));

    if (sortedByHandshake.isNotEmpty) {
      print('🤝 Fastest handshake: ${sortedByHandshake.first.name}');
    }

    final sortedByThroughput = aggregateResults
        .where((r) => r.successCount > 0)
        .toList()
      ..sort((a, b) => b.avgThroughputKbps.compareTo(a.avgThroughputKbps));

    if (sortedByThroughput.isNotEmpty) {
      print('🚀 Best throughput: ${sortedByThroughput.first.name} (${sortedByThroughput.first.throughputFormatted})');
    }
  }

  print('');
  print('═══════════════════════════════════════════════════════════════════════════');
}
