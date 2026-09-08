import 'package:chameleonultragui/helpers/general.dart';
import 'package:chameleonultragui/recovery/recovery.dart' as recovery;
import 'package:chameleonultragui/recovery/recovery.dart';
import 'package:flutter_test/flutter_test.dart';

import 'hardnested_vector.dart';

void main() {
  test('hardnested async: recovers key with live progress', () async {
    var nested = HardNestedDart(nonces: hexToBytes(kHardnestedNonceHex));

    var progressSeen = false;
    String lastActivity = '';

    await recovery.hardNestedStartAsync(nested);
    final key = await recovery.hardNestedAwait(
      pollInterval: const Duration(milliseconds: 50),
      onProgress: (progress) {
        if (progress.activity.isNotEmpty) {
          progressSeen = true;
          lastActivity = progress.activity;
        }
      },
    );

    expect(key, kHardnestedExpectedKey);
    expect(progressSeen, isTrue,
        reason: 'expected at least one progress report with activity text');
    expect(lastActivity, isNotEmpty);
    // A finished attack must no longer report running.
    expect(recovery.hardNestedRunning(), isFalse);
  });

  test('hardnested async: cancel stops the attack and reports cancelled',
      () async {
    var nested = HardNestedDart(nonces: hexToBytes(kHardnestedNonceHex));

    await recovery.hardNestedStartAsync(nested);

    // Cancel almost immediately; the attack may only be in its first stage,
    // but it must stop (not run the full ~17 s recovery) and report it.
    recovery.hardNestedCancel();

    await expectLater(
      recovery.hardNestedAwait(
        pollInterval: const Duration(milliseconds: 20),
        onProgress: (_) {},
        // Never cancel through the poller; the direct cancel above is the
        // thing under test.
        isCancelRequested: () => false,
      ),
      throwsA(isA<recovery.HardnestedCancelledException>()),
    );
    expect(recovery.hardNestedRunning(), isFalse);
  });
}
