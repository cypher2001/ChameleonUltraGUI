import 'package:chameleonultragui/helpers/definitions.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/security.dart';
import 'package:flutter_test/flutter_test.dart';

// Matches the private pageRanges() helper in ultralight.dart.
String pageRanges(List<int> pages) {
  if (pages.isEmpty) return '-';
  final sorted = [...pages]..sort();
  final parts = <String>[];
  var start = sorted.first;
  var prev = sorted.first;
  for (var i = 1; i < sorted.length; i++) {
    if (sorted[i] == prev + 1) {
      prev = sorted[i];
      continue;
    }
    parts.add(start == prev ? '$start' : '$start-$prev');
    start = sorted[i];
    prev = sorted[i];
  }
  parts.add(start == prev ? '$start' : '$start-$prev');
  return parts.join(', ');
}

void main() {
  test('page range formatting: singleton, run, gaps', () {
    expect(pageRanges([]), '-');
    expect(pageRanges([3]), '3');
    expect(pageRanges([10, 11, 12, 13, 14, 15]), '10-15');
    expect(pageRanges([0, 1, 2, 10, 11, 12, 20]), '0-2, 10-12, 20');
    expect(pageRanges([4, 8, 9]), '4, 8-9');
  });

  test('default password list is 4-byte hex entries', () {
    expect(kMifareUltralightDefaultPasswords, isNotEmpty);
    for (final pwd in kMifareUltralightDefaultPasswords) {
      expect(pwd.length, 8, reason: '$pwd must be 4 bytes of hex');
      expect(int.tryParse(pwd, radix: 16), isNotNull);
    }
    // Factory default is tried first.
    expect(kMifareUltralightDefaultPasswords.first, 'FFFFFFFF');
  });

  test('misdetected candidate types are all password-capable UL family', () {
    // Types offered by the retry button must have a password config page,
    // otherwise re-reading as them would never show protection analysis.
    for (final t in [
      TagType.ntag210,
      TagType.ntag212,
      TagType.ntag213,
      TagType.ntag215,
      TagType.ntag216,
      TagType.ultralight21,
    ]) {
      expect(MifareUltralightSecurity.configStartPage(t), isNotNull,
          reason: '$t must have a PWD config');
    }
  });
}
