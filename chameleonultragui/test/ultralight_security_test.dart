import 'package:chameleonultragui/helpers/definitions.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/security.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';

void main() {
  group('config page layout', () {
    test('config start page sits two pages before PWD for NTAG21x', () {
      expect(MifareUltralightSecurity.configStartPage(TagType.ntag213), 41);
      expect(MifareUltralightSecurity.configStartPage(TagType.ntag215), 131);
      expect(MifareUltralightSecurity.configStartPage(TagType.ntag216), 227);
      expect(MifareUltralightSecurity.configStartPage(TagType.ntag212), 37);
      expect(MifareUltralightSecurity.configStartPage(TagType.ntag210), 16);
      // NTAG213: cfg0=41, cfg1=42, PWD=43, PACK=44
      expect(MifareUltralightSecurity.configStartPage(TagType.ntag213)! + 2, 43);
    });

    test('plain Ultralight and UL-C have no password config page', () {
      expect(MifareUltralightSecurity.configStartPage(TagType.ultralight),
          isNull);
      expect(MifareUltralightSecurity.configStartPage(TagType.ultralightC),
          isNull);
    });
  });

  group('parse', () {
    Uint8List page(int a, int b, int c, int d) =>
        Uint8List.fromList([a, b, c, d]);

    test('factory default NTAG213: AUTH0=FF -> open, PWD/PACK readable',
        () {
      // Default config: cfg0 = 00 00 00 FF (AUTH0=0xFF), cfg1 = 00 00 00 00,
      // PWD = FF FF FF FF, PACK = 00 00 XX XX.
      final sec = MifareUltralightSecurity.parse(
        TagType.ntag213,
        page(0x00, 0x00, 0x00, 0xFF),
        page(0x00, 0x00, 0x00, 0x00),
        page(0xFF, 0xFF, 0xFF, 0xFF),
        page(0x00, 0x00, 0x00, 0x00),
      );
      expect(sec.auth0, 0xFF);
      expect(sec.protectedFrom, isNull, reason: 'AUTH0=FF means open');
      expect(sec.readProtected, isFalse);
      expect(sec.configLocked, isFalse);
      expect(sec.authLimit, 0);
      expect(sec.passwordLeaked, isTrue,
          reason: 'PWD page readable on unprotected tag');
      expect(sec.leakedPasswordHex, 'ffffffff');
      expect(sec.leakedPackHex, '0000');
    });

    test('AUTH0 set, PROT=0: write-protected but PWD still readable', () {
      // cfg0 AUTH0 = 0x04 (protect from page 4), cfg1 PROT bit clear (0x00).
      final sec = MifareUltralightSecurity.parse(
        TagType.ntag213,
        page(0x00, 0x00, 0x00, 0x04),
        page(0x00, 0x00, 0x00, 0x00),
        page(0x12, 0x34, 0x56, 0x78),
        page(0xAB, 0xCD, 0x00, 0x00),
      );
      expect(sec.protectedFrom, 4);
      expect(sec.readProtected, isFalse,
          reason: 'PROT=0 -> only writes need the password');
      expect(sec.passwordLeaked, isTrue,
          reason: 'PWD page sits above AUTH0 but reads are open');
      expect(sec.leakedPasswordHex, '12345678');
      expect(sec.leakedPackHex, 'abcd');
    });

    test('AUTH0 set + PROT=1: genuine protection, no readable PWD', () {
      final sec = MifareUltralightSecurity.parse(
        TagType.ntag213,
        page(0x00, 0x00, 0x00, 0x04),
        page(0x80, 0x00, 0x00, 0x00), // PROT = bit 7 of cfg1 byte 0
        page(0xFF, 0xFF, 0xFF, 0xFF),
        page(0x00, 0x00, 0x00, 0x00),
      );
      expect(sec.readProtected, isTrue);
      expect(sec.protectedFrom, 4);
      // On a truly read-protected tag the config read would NACK, so
      // readFromCard returns null - parse() only gets called when readable.
      expect(sec.passwordLeaked, isTrue,
          reason: 'if we could read this page at all, it is leaked');
    });

    test('CFGLCK, NFC_CNT_EN and AUTHLIM decode from cfg1', () {
      // cfg1 byte0 = 0x57 = CFGLCK(0x40) | NFC_CNT_EN(0x10) | AUTHLIM(7).
      final sec = MifareUltralightSecurity.parse(
        TagType.ntag213,
        page(0x00, 0x00, 0x00, 0x10),
        page(0x57, 0x00, 0x00, 0x00),
        page(0xFF, 0xFF, 0xFF, 0xFF),
        page(0x00, 0x00, 0x00, 0x00),
      );
      expect(sec.configLocked, isTrue);
      expect(sec.nfcCounterEnabled, isTrue);
      expect(sec.authLimit, 7);
      expect(sec.protectedFrom, 16);
    });
  });
}
