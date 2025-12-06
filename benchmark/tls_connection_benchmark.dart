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

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

import 'package:tlslite/src/tlsconnection.dart';
import 'package:tlslite/src/handshake_settings.dart';
import 'package:tlslite/src/constants.dart';
import 'package:tlslite/src/recordlayer.dart';
import 'package:tlslite/src/net/secure_socket_openssl_async.dart';

/// Configuration for benchmark runs
class BenchmarkConfig {
  final String host;
  final int port;
  final int iterations;
  final int dataSizeKb;
  final bool verbose;

  const BenchmarkConfig({
    this.host = 'www.google.com',
    this.port = 443,
    this.iterations = 50,
    this.dataSizeKb = 16,
    this.verbose = true,
  });
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
        'received=$bytesReceived bytes, '
        'throughput=${throughputKbps.toStringAsFixed(2)} KB/s';
  }
}

/// Aggregate benchmark results
class AggregateResult {
  final String name;
  final List<BenchmarkResult> results;

  AggregateResult(this.name, this.results);

  double get avgConnectMs =>
      results.isEmpty
          ? 0
          : results.map((r) => r.connectTime.inMilliseconds).reduce((a, b) => a + b) / results.length;

  double get avgHandshakeMs =>
      results.isEmpty
          ? 0
          : results.map((r) => r.handshakeTime.inMilliseconds).reduce((a, b) => a + b) / results.length;

  double get avgRequestMs =>
      results.isEmpty
          ? 0
          : results.map((r) => r.requestTime.inMilliseconds).reduce((a, b) => a + b) / results.length;

  double get avgTotalMs =>
      results.isEmpty
          ? 0
          : results.map((r) => r.totalTime.inMilliseconds).reduce((a, b) => a + b) / results.length;

  double get avgThroughputKbps =>
      results.isEmpty
          ? 0
          : results.map((r) => r.throughputKbps).reduce((a, b) => a + b) / results.length;

  int get successCount => results.where((r) => r.error == null).length;

  @override
  String toString() => '$name: '
      'success=${successCount}/${results.length}, '
      'avgConnect=${avgConnectMs.toStringAsFixed(1)}ms, '
      'avgHandshake=${avgHandshakeMs.toStringAsFixed(1)}ms, '
      'avgRequest=${avgRequestMs.toStringAsFixed(1)}ms, '
      'avgTotal=${avgTotalMs.toStringAsFixed(1)}ms, '
      'avgThroughput=${avgThroughputKbps.toStringAsFixed(2)} KB/s';
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
      await Future.delayed(const Duration(milliseconds: 100));
    }
    return AggregateResult(name, results);
  }
}

/// Benchmark for TlsConnection (pure Dart TLS)
/// Note: This implementation may have compatibility issues with some production servers
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
      socket = await Socket.connect(config.host, config.port);
      connectTime = stopwatch.elapsed - connectStart;

      // Handshake
      final handshakeStart = stopwatch.elapsed;
      final tls = TlsConnection(socket);
      await tls.handshakeClient(
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2
          maxVersion: (3, 3),
        ),
        serverName: config.host,
      );
      handshakeTime = stopwatch.elapsed - handshakeStart;

      print('    ✓ Negotiated version: ${tls.version}');
      print('    ✓ Cipher suite: 0x${tls.session.cipherSuite.toRadixString(16)}');

      // Request
      final requestStart = stopwatch.elapsed;
      final request = 'GET / HTTP/1.1\r\n'
          'Host: ${config.host}\r\n'
          'User-Agent: TlsLite-Benchmark/1.0\r\n'
          'Connection: close\r\n'
          '\r\n';
      await tls.sendRecord(Message(
        ContentType.application_data,
        Uint8List.fromList(utf8.encode(request)),
      ));

      // Read response
      while (true) {
        try {
          final (header, parser) = await tls.recvMessage().timeout(
            const Duration(seconds: 5),
          );
          final data = parser.getFixBytes(parser.getRemainingLength());
          bytesReceived += data.length;
          
          // Check for end of response
          if (data.isEmpty) break;
          final text = utf8.decode(data, allowMalformed: true);
          if (text.contains('</html>') || text.contains('</HTML>')) break;
        } catch (e) {
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
      await socket?.close();
    }
  }
}

/// Benchmark for SecureSocketOpenSSLAsync (FFI OpenSSL)
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
      // Connect and handshake are combined in SecureSocketOpenSSLAsync
      final connectStart = stopwatch.elapsed;
      secureSocket = await SecureSocketOpenSSLAsync.connect(
        config.host,
        config.port,
        eagerHandshake: false,
      );
      connectTime = stopwatch.elapsed - connectStart;

      final handshakeStart = stopwatch.elapsed;
      await secureSocket.ensureHandshakeCompleted();
      handshakeTime = stopwatch.elapsed - handshakeStart;

      // Request
      final requestStart = stopwatch.elapsed;
      final request = 'GET / HTTP/1.1\r\n'
          'Host: ${config.host}\r\n'
          'User-Agent: TlsLite-Benchmark-OpenSSL/1.0\r\n'
          'Connection: close\r\n'
          '\r\n';
      await secureSocket.send(Uint8List.fromList(utf8.encode(request)));

      // Read response
      while (true) {
        try {
          final data = await secureSocket.recv(4096).timeout(
            const Duration(seconds: 5),
          );
          if (data.isEmpty) break;
          bytesReceived += data.length;
          
          final text = utf8.decode(data, allowMalformed: true);
          if (text.contains('</html>') || text.contains('</HTML>')) break;
        } catch (e) {
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
      await secureSocket?.close();
    }
  }
}

/// Benchmark for dart:io SecureSocket
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
        onBadCertificate: (_) => true, // Allow all certs for benchmark
      );
      connectTime = stopwatch.elapsed - connectStart;
      // Handshake is included in connect for SecureSocket
      handshakeTime = Duration.zero;

      // Request
      final requestStart = stopwatch.elapsed;
      final request = 'GET / HTTP/1.1\r\n'
          'Host: ${config.host}\r\n'
          'User-Agent: TlsLite-Benchmark-DartIO/1.0\r\n'
          'Connection: close\r\n'
          '\r\n';
      secureSocket.write(request);
      await secureSocket.flush();

      // Read response
      final responseCompleter = Completer<void>();
      secureSocket.listen(
        (data) {
          bytesReceived += data.length;
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
        const Duration(seconds: 10),
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
      await secureSocket?.close();
    }
  }
}

/// Main benchmark runner
Future<void> main(List<String> args) async {
  print('═══════════════════════════════════════════════════════════════');
  print('       TLS Implementation Benchmark');
  print('═══════════════════════════════════════════════════════════════');
  print('');
  print('Comparing:');
  print('  1. TlsConnection (pure Dart TLS implementation)');
  print('  2. SecureSocketOpenSSLAsync (FFI-based OpenSSL wrapper)');
  print('  3. SecureSocket from dart:io (Dart\'s native secure socket)');
  print('');

  final config = BenchmarkConfig(
    host: 'www.google.com',
    port: 443,    
    verbose: true,
  );

  print('Configuration:');
  print('  Host: ${config.host}:${config.port}');
  print('  Iterations: ${config.iterations}');
  print('');

  final benchmarks = <TlsBenchmark>[
    DartSecureSocketBenchmark(),
    SecureSocketOpenSSLBenchmark(),
    TlsConnectionBenchmark(),
  ];

  final aggregateResults = <AggregateResult>[];

  for (final benchmark in benchmarks) {
    print('───────────────────────────────────────────────────────────────');
    print('Running: ${benchmark.name}');
    print('───────────────────────────────────────────────────────────────');
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

  // Print summary
  print('');
  print('═══════════════════════════════════════════════════════════════');
  print('                     SUMMARY');
  print('═══════════════════════════════════════════════════════════════');
  print('');

  // Table header
  print('┌─────────────────────────────────┬─────────┬───────────┬─────────┬─────────┬───────────────┐');
  print('│ Implementation                  │ Success │ Connect   │ Handshk │ Total   │ Throughput    │');
  print('├─────────────────────────────────┼─────────┼───────────┼─────────┼─────────┼───────────────┤');

  for (final result in aggregateResults) {
    final name = result.name.padRight(31);
    final success = '${result.successCount}/${result.results.length}'.padLeft(7);
    final connect = '${result.avgConnectMs.toStringAsFixed(0)}ms'.padLeft(9);
    final handshake = '${result.avgHandshakeMs.toStringAsFixed(0)}ms'.padLeft(7);
    final total = '${result.avgTotalMs.toStringAsFixed(0)}ms'.padLeft(7);
    final throughput = '${result.avgThroughputKbps.toStringAsFixed(1)} KB/s'.padLeft(13);
    print('│ $name │ $success │ $connect │ $handshake │ $total │ $throughput │');
  }

  print('└─────────────────────────────────┴─────────┴───────────┴─────────┴─────────┴───────────────┘');
  print('');

  // Find best performers
  if (aggregateResults.where((r) => r.successCount > 0).isNotEmpty) {
    final sortedByTotal = aggregateResults
        .where((r) => r.successCount > 0)
        .toList()
      ..sort((a, b) => a.avgTotalMs.compareTo(b.avgTotalMs));

    if (sortedByTotal.isNotEmpty) {
      print('Fastest (total time): ${sortedByTotal.first.name}');
    }

    final sortedByHandshake = aggregateResults
        .where((r) => r.successCount > 0 && r.avgHandshakeMs > 0)
        .toList()
      ..sort((a, b) => a.avgHandshakeMs.compareTo(b.avgHandshakeMs));

    if (sortedByHandshake.isNotEmpty) {
      print('Fastest handshake: ${sortedByHandshake.first.name}');
    }

    final sortedByThroughput = aggregateResults
        .where((r) => r.successCount > 0)
        .toList()
      ..sort((a, b) => b.avgThroughputKbps.compareTo(a.avgThroughputKbps));

    if (sortedByThroughput.isNotEmpty) {
      print('Best throughput: ${sortedByThroughput.first.name}');
    }
  }

  print('');
  print('═══════════════════════════════════════════════════════════════');
  exit(0);
}
