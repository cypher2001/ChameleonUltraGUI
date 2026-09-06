import 'package:chameleonultragui/helpers/mifare_classic/access_condition_matrix.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class AccessConditionCalculatorMenu extends StatefulWidget {
  final String? initialHex;

  const AccessConditionCalculatorMenu({super.key, this.initialHex});

  @override
  State<AccessConditionCalculatorMenu> createState() =>
      _AccessConditionCalculatorMenuState();
}

class _AccessConditionCalculatorMenuState
    extends State<AccessConditionCalculatorMenu>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final TextEditingController _hexInputController =
      TextEditingController(text: 'FF078069');
  AccessConditionResult? _currentResult;

  // Generator state: tuples [C1, C2, C3] for blocks 0, 1, 2, 3
  final List<List<int>> _blockTuples = [
    [0, 0, 0], // Block 0: Transport
    [0, 0, 0], // Block 1: Transport
    [0, 0, 0], // Block 2: Transport
    [0, 0, 1], // Block 3: Transport FF0780
  ];
  String _generatedHex = 'FF078069';

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    if (widget.initialHex != null && widget.initialHex!.isNotEmpty) {
      _hexInputController.text = widget.initialHex!;
    }
    _recalculateFromHex();
  }

  @override
  void dispose() {
    _tabController.dispose();
    _hexInputController.dispose();
    super.dispose();
  }

  void _recalculateFromHex() {
    String input = _hexInputController.text.trim();
    if (input.isEmpty) {
      setState(() {
        _currentResult = null;
      });
      return;
    }

    var res = AccessConditionMatrixHelper.decodeHex(input);
    setState(() {
      _currentResult = res;
    });
  }

  void _recalculateGeneratedHex() {
    String hex = AccessConditionMatrixHelper.encodeHex(_blockTuples);
    setState(() {
      _generatedHex = hex;
    });
  }

  void _applyPreset(String hex) {
    _hexInputController.text = hex;
    _recalculateFromHex();
  }

  void _copyToClipboard(String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('$label copied to clipboard'),
        duration: const Duration(seconds: 1),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Row(
        children: [
          Icon(Icons.table_chart,
              color: Theme.of(context).colorScheme.primary),
          const SizedBox(width: 8),
          const Expanded(
            child: Text(
              'MIFARE Classic Access Condition Matrix',
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
      content: SizedBox(
        width: 700,
        height: 560,
        child: Column(
          children: [
            TabBar(
              controller: _tabController,
              tabs: const [
                Tab(icon: Icon(Icons.analytics), text: 'Decoder & Inspector'),
                Tab(icon: Icon(Icons.build), text: 'Visual Matrix Builder'),
              ],
            ),
            const SizedBox(height: 10),
            Expanded(
              child: TabBarView(
                controller: _tabController,
                children: [
                  _buildInspectorTab(),
                  _buildBuilderTab(),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Close'),
        ),
      ],
    );
  }

  Widget _buildInspectorTab() {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _hexInputController,
                  decoration: const InputDecoration(
                    labelText: 'Access Condition Hex (3 or 4 bytes)',
                    hintText: 'e.g. FF078069 or 7F078869',
                    border: OutlineInputBorder(),
                  ),
                  style: const TextStyle(
                      fontFamily: 'RobotoMono', fontWeight: FontWeight.bold),
                  onChanged: (_) => _recalculateFromHex(),
                ),
              ),
              const SizedBox(width: 8),
              ElevatedButton.icon(
                icon: const Icon(Icons.refresh),
                label: const Text('Decode'),
                onPressed: _recalculateFromHex,
              ),
            ],
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 6,
            children: [
              const Text('Presets:',
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
              ActionChip(
                label: const Text('Transport (FF078069)'),
                onPressed: () => _applyPreset('FF078069'),
              ),
              ActionChip(
                label: const Text('Key B Write (7F078869)'),
                onPressed: () => _applyPreset('7F078869'),
              ),
              ActionChip(
                label: const Text('Read Only (08778F69)'),
                onPressed: () => _applyPreset('08778F69'),
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (_currentResult != null) _buildResultView(_currentResult!),
        ],
      ),
    );
  }

  Widget _buildResultView(AccessConditionResult res) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Chip(
              avatar: Icon(
                res.isValid ? Icons.check_circle : Icons.error,
                color: res.isValid ? Colors.green : Colors.red,
                size: 18,
              ),
              label: Text(
                res.isValid ? 'Valid Inverted Check Bits' : 'CORRUPT INVERTED BITS',
                style: TextStyle(
                  color: res.isValid ? Colors.green : Colors.red,
                  fontWeight: FontWeight.bold,
                  fontSize: 12,
                ),
              ),
            ),
            Row(
              children: [
                Text('Hex: ${res.hexBytes}',
                    style: const TextStyle(
                        fontFamily: 'RobotoMono', fontWeight: FontWeight.bold)),
                IconButton(
                  icon: const Icon(Icons.copy, size: 16),
                  onPressed: () => _copyToClipboard(res.hexBytes, 'Hex string'),
                ),
              ],
            ),
          ],
        ),
        if (res.warnings.isNotEmpty)
          ...res.warnings.map(
            (w) => Container(
              margin: const EdgeInsets.symmetric(vertical: 2),
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: Colors.amber.withOpacity(0.15),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: Colors.amber),
              ),
              child: Row(
                children: [
                  const Icon(Icons.warning, color: Colors.amber, size: 16),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(w,
                        style: const TextStyle(
                            fontSize: 11, fontWeight: FontWeight.w500)),
                  ),
                ],
              ),
            ),
          ),
        if (res.errors.isNotEmpty)
          ...res.errors.map(
            (e) => Container(
              margin: const EdgeInsets.symmetric(vertical: 2),
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: Colors.red.withOpacity(0.15),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: Colors.red),
              ),
              child: Row(
                children: [
                  const Icon(Icons.error, color: Colors.red, size: 16),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(e,
                        style: const TextStyle(
                            fontSize: 11,
                            color: Colors.red,
                            fontWeight: FontWeight.w500)),
                  ),
                ],
              ),
            ),
          ),
        const SizedBox(height: 10),
        const Text('Data Blocks (0, 1, 2) Permissions:',
            style: TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        Table(
          border: TableBorder.all(color: Colors.grey.withOpacity(0.4)),
          columnWidths: const {
            0: FlexColumnWidth(1.2),
            1: FlexColumnWidth(1.0),
            2: FlexColumnWidth(1.2),
            3: FlexColumnWidth(1.2),
            4: FlexColumnWidth(1.2),
            5: FlexColumnWidth(1.4),
          },
          children: [
            TableRow(
              decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surfaceVariant),
              children: const [
                Padding(
                  padding: EdgeInsets.all(6.0),
                  child: Text('Block',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                ),
                Padding(
                  padding: EdgeInsets.all(6.0),
                  child: Text('Bits',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                ),
                Padding(
                  padding: EdgeInsets.all(6.0),
                  child: Text('Read',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                ),
                Padding(
                  padding: EdgeInsets.all(6.0),
                  child: Text('Write',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                ),
                Padding(
                  padding: EdgeInsets.all(6.0),
                  child: Text('Increment',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                ),
                Padding(
                  padding: EdgeInsets.all(6.0),
                  child: Text('Dec/Trans/Rest',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                ),
              ],
            ),
            ...res.blocks.take(3).map(
                  (b) => TableRow(
                    children: [
                      Padding(
                        padding: const EdgeInsets.all(6.0),
                        child: Text('Block ${b.blockIndex}',
                            style: const TextStyle(fontSize: 11)),
                      ),
                      Padding(
                        padding: const EdgeInsets.all(6.0),
                        child: Text(b.bitTuple,
                            style: const TextStyle(
                                fontFamily: 'RobotoMono', fontSize: 11)),
                      ),
                      Padding(
                        padding: const EdgeInsets.all(6.0),
                        child: Text(b.read, style: const TextStyle(fontSize: 11)),
                      ),
                      Padding(
                        padding: const EdgeInsets.all(6.0),
                        child: Text(b.write, style: const TextStyle(fontSize: 11)),
                      ),
                      Padding(
                        padding: const EdgeInsets.all(6.0),
                        child:
                            Text(b.increment, style: const TextStyle(fontSize: 11)),
                      ),
                      Padding(
                        padding: const EdgeInsets.all(6.0),
                        child:
                            Text(b.decrement, style: const TextStyle(fontSize: 11)),
                      ),
                    ],
                  ),
                ),
          ],
        ),
        const SizedBox(height: 12),
        const Text('Sector Trailer (Block 3) Permissions:',
            style: TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        if (res.blocks.length >= 4)
          Table(
            border: TableBorder.all(color: Colors.grey.withOpacity(0.4)),
            columnWidths: const {
              0: FlexColumnWidth(1.2),
              1: FlexColumnWidth(1.2),
              2: FlexColumnWidth(1.2),
              3: FlexColumnWidth(1.2),
              4: FlexColumnWidth(1.2),
              5: FlexColumnWidth(1.2),
            },
            children: [
              TableRow(
                decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceVariant),
                children: const [
                  Padding(
                    padding: EdgeInsets.all(6.0),
                    child: Text('Key A Read',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                  ),
                  Padding(
                    padding: EdgeInsets.all(6.0),
                    child: Text('Key A Write',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                  ),
                  Padding(
                    padding: EdgeInsets.all(6.0),
                    child: Text('Access Read',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                  ),
                  Padding(
                    padding: EdgeInsets.all(6.0),
                    child: Text('Access Write',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                  ),
                  Padding(
                    padding: EdgeInsets.all(6.0),
                    child: Text('Key B Read',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                  ),
                  Padding(
                    padding: EdgeInsets.all(6.0),
                    child: Text('Key B Write',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                  ),
                ],
              ),
              TableRow(
                children: [
                  Padding(
                    padding: const EdgeInsets.all(6.0),
                    child: Text(res.blocks[3].keyARead ?? 'N/A',
                        style: const TextStyle(fontSize: 11)),
                  ),
                  Padding(
                    padding: const EdgeInsets.all(6.0),
                    child: Text(res.blocks[3].keyAWrite ?? 'N/A',
                        style: const TextStyle(fontSize: 11)),
                  ),
                  Padding(
                    padding: const EdgeInsets.all(6.0),
                    child: Text(res.blocks[3].accessBitsRead ?? 'N/A',
                        style: const TextStyle(fontSize: 11)),
                  ),
                  Padding(
                    padding: const EdgeInsets.all(6.0),
                    child: Text(res.blocks[3].accessBitsWrite ?? 'N/A',
                        style: const TextStyle(fontSize: 11)),
                  ),
                  Padding(
                    padding: const EdgeInsets.all(6.0),
                    child: Text(res.blocks[3].keyBRead ?? 'N/A',
                        style: const TextStyle(fontSize: 11)),
                  ),
                  Padding(
                    padding: const EdgeInsets.all(6.0),
                    child: Text(res.blocks[3].keyBWrite ?? 'N/A',
                        style: const TextStyle(fontSize: 11)),
                  ),
                ],
              ),
            ],
          ),
      ],
    );
  }

  Widget _buildBuilderTab() {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text(
            'Select desired permissions for each block to compute safe access bytes:',
            style: TextStyle(fontSize: 12),
          ),
          const SizedBox(height: 10),
          ...List.generate(3, (i) {
            return Card(
              margin: const EdgeInsets.symmetric(vertical: 4),
              child: Padding(
                padding: const EdgeInsets.all(10.0),
                child: Row(
                  children: [
                    Text('Block $i: ',
                        style: const TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(width: 8),
                    Expanded(
                      child: DropdownButton<int>(
                        isExpanded: true,
                        value: (_blockTuples[i][0] << 2) |
                            (_blockTuples[i][1] << 1) |
                            _blockTuples[i][2],
                        items: const [
                          DropdownMenuItem(
                              value: 0,
                              child: Text('000: Full R/W (Key A | B)')),
                          DropdownMenuItem(
                              value: 2,
                              child: Text('010: Read Only (Key A | B, Write Never)')),
                          DropdownMenuItem(
                              value: 4,
                              child: Text('100: Read (Key A|B), Write (Key B)')),
                          DropdownMenuItem(
                              value: 6,
                              child: Text('110: Value Block (Key B Write/Inc)')),
                          DropdownMenuItem(
                              value: 3,
                              child: Text('011: Secret Data (Key B R/W)')),
                          DropdownMenuItem(
                              value: 7,
                              child: Text('111: Locked (Never R/W)')),
                        ],
                        onChanged: (val) {
                          if (val != null) {
                            setState(() {
                              _blockTuples[i] = [
                                (val >> 2) & 1,
                                (val >> 1) & 1,
                                val & 1,
                              ];
                            });
                            _recalculateGeneratedHex();
                          }
                        },
                      ),
                    ),
                  ],
                ),
              ),
            );
          }),
          Card(
            margin: const EdgeInsets.symmetric(vertical: 4),
            child: Padding(
              padding: const EdgeInsets.all(10.0),
              child: Row(
                children: [
                  const Text('Sector Trailer (Block 3): ',
                      style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Expanded(
                    child: DropdownButton<int>(
                      isExpanded: true,
                      value: (_blockTuples[3][0] << 2) |
                          (_blockTuples[3][1] << 1) |
                          _blockTuples[3][2],
                      items: const [
                        DropdownMenuItem(
                            value: 1,
                            child: Text('001: Transport (FF0780) - Key A full access')),
                        DropdownMenuItem(
                            value: 3,
                            child: Text('011: Secure (7F0788) - Key B write, Key B secret')),
                        DropdownMenuItem(
                            value: 4,
                            child: Text('100: Protected - Key B write, Access locked')),
                        DropdownMenuItem(
                            value: 7,
                            child: Text('111: Permanent Lock - No further changes')),
                      ],
                      onChanged: (val) {
                        if (val != null) {
                          setState(() {
                            _blockTuples[3] = [
                              (val >> 2) & 1,
                              (val >> 1) & 1,
                              val & 1,
                            ];
                          });
                          _recalculateGeneratedHex();
                        }
                      },
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primaryContainer,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Computed Safe Access Bytes:',
                        style: TextStyle(fontSize: 12, fontWeight: FontWeight.w500)),
                    SelectableText(
                      _generatedHex,
                      style: const TextStyle(
                        fontFamily: 'RobotoMono',
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
                ElevatedButton.icon(
                  icon: const Icon(Icons.copy),
                  label: const Text('Copy Hex'),
                  onPressed: () =>
                      _copyToClipboard(_generatedHex, 'Generated Access Bytes'),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
