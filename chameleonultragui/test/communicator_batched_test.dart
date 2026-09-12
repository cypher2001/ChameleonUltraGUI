import 'dart:typed_data';

import 'package:chameleonultragui/bridge/chameleon.dart';
import 'package:chameleonultragui/connector/serial_abstract.dart';
import 'package:chameleonultragui/helpers/definitions.dart';
import 'package:chameleonultragui/helpers/mifare_classic/key_check_batched.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:logger/logger.dart';

/// Fake serial port that answers each command frame with a canned response
/// frame, mirroring the RRG device framing (SOF + LRC + cmd/status/len + LRC).
class FakeSerial extends AbstractSerial {
  final Map<int, Uint8List> responses; // cmd value -> response payload
  final List<Uint8List> sentFrames = [];
  final List<int> sentCommands = [];

  FakeSerial({required this.responses}) : super(log: Logger(level: Level.off));

  @override
  bool isManualConnectionSupported() => true;

  @override
  Future<bool> connectSpecificDevice(dynamic devicePort) async => true;

  @override
  Future<List<Chameleon>> availableChameleons(bool onlyDFU) async => [];

  @override
  Future<void> open() async {}

  /// Echo handler: capture the frame, then feed a canned response frame back
  /// through the message callback exactly like a real device would.
  @override
  Future<bool> write(Uint8List command, {bool firmware = false}) async {
    sentFrames.add(command);
    if (command.length < 9) return true;

    // Parse cmd (BE u16 at offset 2).
    final cmd = (command[2] << 8) | command[3];
    sentCommands.add(cmd);

    final payload = responses[cmd];
    if (payload != null) {
      // Respond after a tick so the async reader in sendCmd sees it.
      await Future<void>.delayed(const Duration(milliseconds: 1));
      final frame = _makeFrame(cmd, 0x00, payload);
      if (messageCallback != null) {
        await messageCallback!(frame);
      }
    }
    return true;
  }

  Uint8List _makeFrame(int cmd, int status, Uint8List payload) {
    // Reuse the communicator's own framing helpers for a faithful round-trip.
    final comm = ChameleonCommunicator(Logger(level: Level.off));
    return comm.makeDataFrameBytes(
        ChameleonCommand.values.firstWhere((c) => c.value == cmd),
        status,
        payload);
  }
}

void main() {
  Logger.level = Level.off;

  test('mf1CheckKeysOfSectors round-trips request and parses response', () async {
    // Firmware response for cmd 2012: 10-byte found mask + keys.
    // Simulate: Key A (slot 2 = sector 1) and Key B (slot 5 = sector 2) found.
    final resp = Uint8List(10 + 80 * 6);
    resp[0] = 0x00;
    // slot 2 => byte 0, bit 0x80 >> 2 = 0x20
    resp[2 >> 3] |= (0x80 >> (2 & 7));
    // slot 5 => byte 0, bit 0x80 >> 5 = 0x04
    resp[5 >> 3] |= (0x80 >> (5 & 7));
    resp.setRange(10 + 2 * 6, 10 + 2 * 6 + 6, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    resp.setRange(10 + 5 * 6, 10 + 5 * 6 + 6, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    final serial = FakeSerial(
        responses: {2012: resp, 1035: Uint8List.fromList([0x07, 0xDC, 0x00, 0x00])});

    final comm = ChameleonCommunicator(Logger(level: Level.off));
    comm.open(serial);

    // Gate check: cmd 2012 (0x07DC = 2012) must be advertised.
    final supported = await comm.supportsMf1CheckKeysOfSectors();
    expect(supported, isTrue);

    final checked = [mfClassicKeySlot(1, 0), mfClassicKeySlot(2, 1)];
    final mask = buildCheckKeysOfSectorsMask(checked);
    final found = await comm.mf1CheckKeysOfSectors(mask, [
      Uint8List.fromList([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
    ]);

    expect(found, isNotEmpty);
    expect(found.containsKey(2), isTrue);
    expect(found[2], [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    expect(found.containsKey(5), isTrue);
    expect(found[5], [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    // The request frame must carry cmd 2012 and a 10-byte mask + 6-byte key.
    final sent = serial.sentFrames.firstWhere(
        (f) => ((f[2] << 8) | f[3]) == 2012);
    expect(sent.length, greaterThanOrEqualTo(10 + 6 + 9));
    final payload = sent.sublist(9, sent.length - 1);
    expect(payload.length, 10 + 6);
    expect(payload.sublist(0, 10), mask);
  });

  test('mf1CheckKeysOfSectors throws when tag lost (status != 0)', () async {
    // Status HF_TAG_NO (0x01) with empty payload.
    final serial = _StatusFakeSerial(2012, 0x01);
    final comm = ChameleonCommunicator(Logger(level: Level.off));
    comm.open(serial);

    expect(
      () => comm.mf1CheckKeysOfSectors(Uint8List(10), [
        Uint8List.fromList([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
      ]),
      throwsA(isA<Exception>()),
    );
  });
}

/// Fake serial that replies to one cmd with a fixed status and no payload.
class _StatusFakeSerial extends AbstractSerial {
  final int cmd;
  final int status;
  _StatusFakeSerial(this.cmd, this.status) : super(log: Logger(level: Level.off));

  @override
  bool isManualConnectionSupported() => true;

  @override
  Future<bool> connectSpecificDevice(dynamic devicePort) async => true;

  @override
  Future<List<Chameleon>> availableChameleons(bool onlyDFU) async => [];

  @override
  Future<void> open() async {}

  @override
  Future<bool> write(Uint8List command, {bool firmware = false}) async {
    final comm = ChameleonCommunicator(Logger(level: Level.off));
    final frame = comm.makeDataFrameBytes(
        ChameleonCommand.values.firstWhere((c) => c.value == cmd),
        status,
        Uint8List(0));
    await Future<void>.delayed(const Duration(milliseconds: 1));
    if (messageCallback != null) {
      await messageCallback!(frame);
    }
    return true;
  }
}
