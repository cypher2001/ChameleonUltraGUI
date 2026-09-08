import 'package:chameleonultragui/helpers/general.dart';
import 'package:chameleonultragui/helpers/mifare_classic/general.dart';
import 'package:chameleonultragui/recovery/recovery.dart' as recovery;
import 'package:chameleonultragui/recovery/recovery.dart';
import 'package:flutter_test/flutter_test.dart';

import 'hardnested_vector.dart';

void main() {
  test('Test darkside', () async {
    var darkside = DarksideDart(uid: 2374329723, items: []);
    darkside.items.add(DarksideItemDart(
        nt1: 913032415, ks1: 216745674933338888, par: 0, nr: 0, ar: 0));
    darkside.items.add(DarksideItemDart(
        nt1: 913032415, ks1: 1010230244403446283, par: 0, nr: 1, ar: 0));
    var keys = await recovery.darkside(darkside);
    expect(keys.contains(0xFFFFFFFFFFFF), true);
  });

  test('Test nested', () async {
    var nested = NestedDart(
        uid: 2374329723,
        distance: 613,
        nt0: 1999585272,
        nt0Enc: 3173333529,
        par0: 3,
        nt1: 128306861,
        nt1Enc: 2363514210,
        par1: 7);
    var keys = await recovery.nested(nested);
    expect(keys.contains(0xFFFFFFFFFFFF), true);
  });

  test('Test static encrypted nested', () async {
    var nested = StaticEncryptedNestedDart(
        uid: 0x72000003, nt: 0x82d91e42, ntEnc: 0x98b90e04, ntParEnc: 1011);
    var keys = await recovery.staticEncryptedNested(nested);
    expect(keys.contains(0x55654483DA14), true);
  });

  test('Test static encrypted nested second key recovery', () async {
    var possibleAKeys = await recovery.staticEncryptedNested(
        StaticEncryptedNestedDart(
            uid: 0x72000003, nt: 647928510, ntEnc: 591664851, ntParEnc: 100));
    var possibleBKeys = await recovery.staticEncryptedNested(
        StaticEncryptedNestedDart(
            uid: 0x72000003,
            nt: 2195267138,
            ntEnc: 2562264580,
            ntParEnc: 1011));
    expect(possibleAKeys.length, 34675);
    expect(possibleBKeys.length, 35256);
    var filtered = await StaticEncryptedKeysFilterAsync.filterKeys(
        possibleAKeys, possibleBKeys, 647928510, 2195267138);
    expect(filtered.$1.length, 14429);
    expect(filtered.$2.length, 14294);
    var keys = await StaticEncryptedKeysFilterAsync.findMatchingKeys(
        2195267138, 0x55654483DA14, 647928510, filtered.$1);
    expect(keys.contains(0xC27E180BAF69), true);
  });

  test('Test hard nested (sync FFI)', () async {
    var nested = HardNestedDart(nonces: hexToBytes(kHardnestedNonceHex));
    var keys = await recovery.hardNested(nested);

    expect(keys.contains(kHardnestedExpectedKey), true);
  });
}
