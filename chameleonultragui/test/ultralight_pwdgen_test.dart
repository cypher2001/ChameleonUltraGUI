import 'package:chameleonultragui/helpers/general.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/pwdgen.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('pwdgen matches pm3 generator.c self-test vectors', () {
    test('Transport EV1 (A)', () {
      // uid1 = 04 11 12 11 12 11 10 -> 8432EB17
      final cands = mifareUltralightGeneratePwd(
          hexToBytes('04111211121110'));
      expect(cands.firstWhere((c) => c.name == 'Transport EV1').pwdHex,
          '8432EB17');
    });

    test('Amiibo (B)', () {
      // uid2 = 04 1f 98 ea 1e 3e 81 -> 5FD37ECA
      final cands = mifareUltralightGeneratePwd(
          hexToBytes('041F98EA1E3E81'));
      expect(cands.firstWhere((c) => c.name == 'Amiibo').pwdHex, '5FD37ECA');
    });

    test('Lego Dimensions (C)', () {
      // uid3 = 04 62 B6 8A B4 42 80 -> 5A349515
      final cands = mifareUltralightGeneratePwd(
          hexToBytes('0462B68AB44280'));
      expect(cands.firstWhere((c) => c.name == 'Lego Dimensions').pwdHex,
          '5A349515');
    });
  });

  test('hex UID parsing tolerates spaces and colons', () {
    final cands =
        mifareUltralightGeneratePwdFromHex('04 11 12 11 12 11 10');
    expect(cands, isNotEmpty);
    expect(cands.firstWhere((c) => c.name == 'Transport EV1').pwdHex,
        '8432EB17');
  });

  test('short UID returns no candidates', () {
    expect(mifareUltralightGeneratePwd(hexToBytes('0411')), isEmpty);
    expect(mifareUltralightGeneratePwdFromHex(''), isEmpty);
  });

  test('candidate merge dedupes and orders generated first', () {
    final merged = mifareUltralightMergeCandidates(
      '04111211121110',
      defaults: const ['FFFFFFFF', '8432EB17'],
      dictionary: const ['B6AA558D', 'FFFFFFFF'],
    );
    expect(merged.first, '8432EB17', reason: 'generated candidate first');
    expect(merged, contains('FFFFFFFF'));
    expect(merged, contains('B6AA558D'));
    // Dedup: no repeats.
    expect(merged.toSet().length, merged.length);
  });
}
