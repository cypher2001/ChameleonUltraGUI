import 'dart:typed_data';

import 'package:chameleonultragui/helpers/general.dart';

/// UID-derived PWD generators, ported from pm3's `ul_ev1_pwdgenA..G`
/// (common/generator.c). These recover the password of products that derive
/// their tag password from the UID - no dictionary or sniffing needed, only
/// the 7-byte UID (pages 0-2 are readable even on a locked tag).
class MifareUltralightPwdgenCandidate {
  final String name;
  final String pwdHex;
  final String? packHex;

  const MifareUltralightPwdgenCandidate(this.name, this.pwdHex, this.packHex);
}

String _hex32(int v) =>
    (v & 0xFFFFFFFF).toRadixString(16).padLeft(8, '0').toUpperCase();

String _hex16(int v) => (v & 0xFFFF).toRadixString(16).padLeft(4, '0');

int _rotr32(int v, int n) => ((v >>> n) | (v << (32 - n))) & 0xFFFFFFFF;

int _bs32(int v) =>
    ((v & 0xFF) << 24) |
    ((v >> 8) & 0xFF) << 16 |
    ((v >> 16) & 0xFF) << 8 |
    ((v >> 24) & 0xFF);

// "Transport EV1" default used by NXP blank tags (algo A).
int _pwdgenA(Uint8List uid) {
  final pos = (uid[3] ^ uid[4] ^ uid[5] ^ uid[6]) % 32;
  const table = [
    0x4f2711c1, 0x07D7BB83, 0x9636EF07, 0xB5F4460E, 0xF271141C, 0x7D7BB038,
    0x636EF871, 0x5F4468E3, 0x271149C7, 0xD7BB0B8F, 0x36EF8F1E, 0xF446863D,
    0x7114947A, 0x7BB0B0F5, 0x6EF8F9EB, 0x44686BD7, 0x11494fAF, 0xBB0B075F,
    0xEF8F96BE, 0x4686B57C, 0x1494F2F9, 0xB0B07DF3, 0xF8F963E6, 0x686B5FCC,
    0x494F2799, 0x0B07D733, 0x8F963667, 0x86B5F4CE, 0x94F2719C, 0xB07D7B38,
    0xF9636E70, 0x6B5F44E0
  ];
  final e = table[pos];
  final p0 = (e >> 24) & 0xFF,
      p1 = (e >> 16) & 0xFF,
      p2 = (e >> 8) & 0xFF,
      p3 = e & 0xFF;
  return ((p0 ^ uid[1] ^ uid[2] ^ uid[3]) << 24) |
      ((p1 ^ uid[0] ^ uid[2] ^ uid[4]) << 16) |
      ((p2 ^ uid[0] ^ uid[1] ^ uid[5]) << 8) |
      (p3 ^ uid[6]);
}

// Amiibo / Power-Up band (algo B).
int _pwdgenB(Uint8List uid) {
  return ((uid[1] ^ uid[3] ^ 0xAA) << 24) |
      ((uid[2] ^ uid[4] ^ 0x55) << 16) |
      ((uid[3] ^ uid[5] ^ 0xAA) << 8) |
      (uid[4] ^ uid[6] ^ 0x55);
}

// Lego Dimensions (algo C). pm3 memcpy's the 7 UID bytes over the byte
// image of a uint32 array (little-endian), so words 0-1 pick up UID bytes
// with the remaining byte of word 1 kept (0x28), then a feistel-ish mix.
int _pwdgenC(Uint8List uid) {
  final base = [
    0xffffffff, 0x28ffffff, 0x43202963, 0x7279706f,
    0x74686769, 0x47454c20, 0x3032204f, 0xaaaa3431
  ];
  // base[0] little-endian bytes 0-3 <- uid[0..3]; base[1] bytes 0-2 <-
  // uid[4..6], byte 3 stays 0x28.
  base[0] = uid[0] | (uid[1] << 8) | (uid[2] << 16) | (uid[3] << 24);
  base[1] = uid[4] | (uid[5] << 8) | (uid[6] << 16) | 0x28000000;
  var pwd = 0;
  for (final w in base) {
    pwd = (w + _rotr32(pwd, 25) + _rotr32(pwd, 10) - pwd) & 0xFFFFFFFF;
  }
  return _bs32(pwd);
}

// Philips Sonicare toothbrush heads (algo G): CRC16-CCITT over UID + mfg
// string ("philips.com").
int _pwdgenG(Uint8List uid) {
  int crc16(int crc, int b) {
    crc ^= b << 8;
    for (var i = 0; i < 8; i++) {
      crc = (crc & 0x8000) != 0
          ? ((crc << 1) ^ 0x1021) & 0xFFFF
          : (crc << 1) & 0xFFFF;
    }
    return crc & 0xFFFF;
  }

  var crc = 0xFFFF;
  for (final b in uid) {
    crc = crc16(crc, b);
  }
  const mfg = 'philips.com';
  for (var i = 0; i < mfg.length; i++) {
    crc = crc16(crc, mfg.codeUnitAt(i));
  }
  final swapped = ((crc & 0xFF) << 8) | ((crc >> 8) & 0xFF);
  return ((swapped & 0xFFFF) << 16) | (swapped & 0xFFFF);
}

/// Generates candidate passwords for a 7-byte [uid] (raw bytes).
List<MifareUltralightPwdgenCandidate> mifareUltralightGeneratePwd(
    Uint8List uid) {
  if (uid.length < 7) {
    return const [];
  }
  final u = uid.sublist(0, 7);
  final a = _pwdgenA(u);
  final b = _pwdgenB(u);
  final c = _pwdgenC(u);
  final g = _pwdgenG(u);
  final packA = ((u[0] ^ u[1] ^ u[2]) << 8) | (u[2] ^ 8);
  return [
    MifareUltralightPwdgenCandidate('Transport EV1', _hex32(a), _hex16(packA)),
    MifareUltralightPwdgenCandidate('Amiibo', _hex32(b), '8080'),
    MifareUltralightPwdgenCandidate('Lego Dimensions', _hex32(c), 'AA55'),
    MifareUltralightPwdgenCandidate('Philips Sonicare', _hex32(g), null),
  ];
}

/// Generates candidates from a hex UID string (spaces/colons tolerated).
List<MifareUltralightPwdgenCandidate> mifareUltralightGeneratePwdFromHex(
    String uidHex) {
  final clean = uidHex.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  if (clean.length < 14) {
    return const [];
  }
  return mifareUltralightGeneratePwd(hexToBytes(clean.substring(0, 14)));
}

/// Merges pwdgen candidates + default + user-dictionary PWDs, deduplicated,
/// generated algorithms first (cheap, targeted), then defaults, then the
/// user's dictionary.
List<String> mifareUltralightMergeCandidates(
  String uidHex, {
  List<String> defaults = const [],
  List<String> dictionary = const [],
}) {
  final ordered = <String>[];
  void add(String k) {
    if (!ordered.contains(k)) ordered.add(k);
  }

  for (final c in mifareUltralightGeneratePwdFromHex(uidHex)) {
    add(c.pwdHex);
  }
  for (final k in defaults) {
    add(k);
  }
  for (final d in dictionary) {
    add(d);
  }
  return ordered;
}
