const Map<String, List<int>> _curveNameToOid = {
  'secp256r1': [1, 2, 840, 10045, 3, 1, 7],
  'prime256v1': [1, 2, 840, 10045, 3, 1, 7],
  'nistp256': [1, 2, 840, 10045, 3, 1, 7],
  'nist256p': [1, 2, 840, 10045, 3, 1, 7],
  'secp384r1': [1, 3, 132, 0, 34],
  'nistp384': [1, 3, 132, 0, 34],
  'nist384p': [1, 3, 132, 0, 34],
  'secp521r1': [1, 3, 132, 0, 35],
  'nistp521': [1, 3, 132, 0, 35],
  'nist521p': [1, 3, 132, 0, 35],
  'brainpoolp256r1': [1, 3, 36, 3, 3, 2, 8, 1, 1, 7],
  'brainpoolp384r1': [1, 3, 36, 3, 3, 2, 8, 1, 1, 11],
  'brainpoolp512r1': [1, 3, 36, 3, 3, 2, 8, 1, 1, 13],
  'brainpoolp256r1tls13': [1, 3, 36, 3, 3, 2, 8, 1, 1, 7, 1],
  'brainpoolp384r1tls13': [1, 3, 36, 3, 3, 2, 8, 1, 1, 11, 1],
  'brainpoolp512r1tls13': [1, 3, 36, 3, 3, 2, 8, 1, 1, 13, 1],
};

final Map<String, String> _oidToCurveName = () {
  final map = <String, String>{};
  for (final entry in _curveNameToOid.entries) {
    map.putIfAbsent(_oidKey(entry.value), () => entry.key);
  }
  return map;
}();

String? curveNameFromOid(List<int> oidArcs) {
  return _oidToCurveName[_oidKey(oidArcs)];
}

List<int>? curveOidFromName(String curveName) {
  return _curveNameToOid[curveName.toLowerCase()];
}

List<int> decodeOid(List<int> encoded) {
  if (encoded.isEmpty) {
    throw ArgumentError('OID encoding is empty');
  }
  final arcs = <int>[];
  final first = encoded.first;
  arcs.add(first ~/ 40);
  arcs.add(first % 40);
  var value = 0;
  for (var i = 1; i < encoded.length; i++) {
    final byte = encoded[i];
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) == 0) {
      arcs.add(value);
      value = 0;
    }
  }
  if (value != 0) {
    arcs.add(value);
  }
  return arcs;
}

String _oidKey(List<int> oid) => oid.join('.');
