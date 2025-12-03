import 'dart:core';

BigInt limbsToBigInt(List<int> limbs) {
  var result = BigInt.zero;
  for (var i = limbs.length - 1; i >= 0; i--) {
    result = (result << 28) + BigInt.from(limbs[i]);
  }
  return result;
}

void main() {
  const xLimbs = [
    118276190,
    40534716,
    9670182,
    135141552,
    85017403,
    259173222,
    68333082,
    171784774,
    174973732,
    15824510,
    73756743,
    57518561,
    94773951,
    248652241,
    107736333,
    82941708,
  ];

  const yLimbs = [
    36764180,
    8885695,
    130592152,
    20104429,
    163904957,
    30304195,
    121295871,
    5901357,
    125344798,
    171541512,
    175338348,
    209069246,
    3626697,
    38307682,
    24032956,
    110359655,
  ];

  final x = limbsToBigInt(xLimbs);
  final y = limbsToBigInt(yLimbs);

  print('x = 0x${x.toRadixString(16)}');
  print('y = 0x${y.toRadixString(16)}');
}
