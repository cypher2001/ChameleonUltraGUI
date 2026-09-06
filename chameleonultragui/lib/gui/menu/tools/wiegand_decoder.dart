import 'package:chameleonultragui/helpers/wiegand.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class WiegandDecoderMenu extends StatefulWidget {
  const WiegandDecoderMenu({super.key});

  @override
  State<WiegandDecoderMenu> createState() => _WiegandDecoderMenuState();
}

class _WiegandDecoderMenuState extends State<WiegandDecoderMenu>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;

  // Decoder state
  final TextEditingController _decodeInputController = TextEditingController();
  WiegandFormat _selectedFormat = WiegandFormat.wiegand26;
  bool _autoDetect = true;
  WiegandResult? _decodeResult;

  // Generator state
  final TextEditingController _genFcController =
      TextEditingController(text: '101');
  final TextEditingController _genCnController =
      TextEditingController(text: '1337');
  WiegandFormat _genFormat = WiegandFormat.wiegand26;
  WiegandResult? _genResult;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _generateWiegand();
  }

  @override
  void dispose() {
    _tabController.dispose();
    _decodeInputController.dispose();
    _genFcController.dispose();
    _genCnController.dispose();
    super.dispose();
  }

  void _decodeInput() {
    String input = _decodeInputController.text.trim();
    if (input.isEmpty) {
      setState(() {
        _decodeResult = null;
      });
      return;
    }

    WiegandResult res;
    if (_autoDetect) {
      res = WiegandHelper.autoDecode(input);
    } else {
      switch (_selectedFormat) {
        case WiegandFormat.wiegand26:
          res = WiegandHelper.decode26Bit(input);
          break;
        case WiegandFormat.wiegand34:
          res = WiegandHelper.decode34Bit(input);
          break;
        case WiegandFormat.wiegand37H10304:
          res = WiegandHelper.decode37BitH10304(input);
          break;
        case WiegandFormat.wiegand37H10302:
          res = WiegandHelper.decode37BitH10304(input);
          break;
      }
    }

    setState(() {
      _decodeResult = res;
    });
  }

  void _generateWiegand() {
    int fc = int.tryParse(_genFcController.text.trim()) ?? 0;
    int cn = int.tryParse(_genCnController.text.trim()) ?? 0;

    WiegandResult res;
    switch (_genFormat) {
      case WiegandFormat.wiegand26:
        res = WiegandHelper.encode26Bit(fc, cn);
        break;
      case WiegandFormat.wiegand34:
        res = WiegandHelper.encode34Bit(fc, cn);
        break;
      case WiegandFormat.wiegand37H10304:
      case WiegandFormat.wiegand37H10302:
        res = WiegandHelper.encode37BitH10304(fc, cn);
        break;
    }

    setState(() {
      _genResult = res;
    });
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
          Icon(Icons.credit_card,
              color: Theme.of(context).colorScheme.primary),
          const SizedBox(width: 8),
          const Expanded(
            child: Text(
              'Wiegand Access Control Decoder',
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
      content: SizedBox(
        width: 620,
        height: 520,
        child: Column(
          children: [
            TabBar(
              controller: _tabController,
              tabs: const [
                Tab(icon: Icon(Icons.search), text: 'Decoder'),
                Tab(icon: Icon(Icons.build_circle), text: 'Generator'),
              ],
            ),
            const SizedBox(height: 12),
            Expanded(
              child: TabBarView(
                controller: _tabController,
                children: [
                  _buildDecoderTab(),
                  _buildGeneratorTab(),
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

  Widget _buildDecoderTab() {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: _decodeInputController,
            decoration: InputDecoration(
              labelText: 'Hex Dump or Binary String',
              hintText: 'e.g. 0200426DA1C or 00100000000001000010011011',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: const Icon(Icons.clear),
                onPressed: () {
                  _decodeInputController.clear();
                  _decodeInput();
                },
              ),
            ),
            style: const TextStyle(fontFamily: 'RobotoMono', fontSize: 13),
            onChanged: (_) => _decodeInput(),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              FilterChip(
                label: const Text('Auto Detect'),
                selected: _autoDetect,
                onSelected: (val) {
                  setState(() {
                    _autoDetect = val;
                  });
                  _decodeInput();
                },
              ),
              const SizedBox(width: 12),
              if (!_autoDetect)
                Expanded(
                  child: DropdownButton<WiegandFormat>(
                    value: _selectedFormat,
                    isExpanded: true,
                    items: WiegandFormat.values.map((f) {
                      return DropdownMenuItem(
                        value: f,
                        child: Text(f.label, style: const TextStyle(fontSize: 13)),
                      );
                    }).toList(),
                    onChanged: (newVal) {
                      if (newVal != null) {
                        setState(() {
                          _selectedFormat = newVal;
                        });
                        _decodeInput();
                      }
                    },
                  ),
                ),
            ],
          ),
          const SizedBox(height: 12),
          if (_decodeResult != null) _buildResultCard(_decodeResult!),
        ],
      ),
    );
  }

  Widget _buildGeneratorTab() {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          DropdownButtonFormField<WiegandFormat>(
            value: _genFormat,
            decoration: const InputDecoration(
              labelText: 'Target Format',
              border: OutlineInputBorder(),
            ),
            items: WiegandFormat.values.map((f) {
              return DropdownMenuItem(
                value: f,
                child: Text(f.label),
              );
            }).toList(),
            onChanged: (newVal) {
              if (newVal != null) {
                setState(() {
                  _genFormat = newVal;
                });
                _generateWiegand();
              }
            },
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _genFcController,
                  decoration: const InputDecoration(
                    labelText: 'Facility Code (FC)',
                    border: OutlineInputBorder(),
                  ),
                  keyboardType: TextInputType.number,
                  onChanged: (_) => _generateWiegand(),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: TextField(
                  controller: _genCnController,
                  decoration: const InputDecoration(
                    labelText: 'Card Number (CN)',
                    border: OutlineInputBorder(),
                  ),
                  keyboardType: TextInputType.number,
                  onChanged: (_) => _generateWiegand(),
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          if (_genResult != null) _buildResultCard(_genResult!),
        ],
      ),
    );
  }

  Widget _buildResultCard(WiegandResult result) {
    final colorScheme = Theme.of(context).colorScheme;

    return Card(
      elevation: 2,
      child: Padding(
        padding: const EdgeInsets.all(14.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  result.format.label,
                  style: const TextStyle(fontWeight: FontWeight.bold),
                ),
                Chip(
                  avatar: Icon(
                    result.isValid ? Icons.check_circle : Icons.warning,
                    color: result.isValid ? Colors.green : Colors.amber,
                    size: 18,
                  ),
                  label: Text(
                    result.isValid ? 'Parity Valid' : 'Parity Error',
                    style: TextStyle(
                      fontSize: 12,
                      color: result.isValid ? Colors.green : Colors.amber,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  visualDensity: VisualDensity.compact,
                ),
              ],
            ),
            const Divider(),
            _buildDataRow(
                'Facility Code:', '${result.facilityCode}', () => _copyToClipboard('${result.facilityCode}', 'Facility Code')),
            _buildDataRow(
                'Card Number:', '${result.cardNumber}', () => _copyToClipboard('${result.cardNumber}', 'Card Number')),
            _buildDataRow(
                'Even Parity:', result.evenParityValid ? 'OK' : 'FAIL', null),
            _buildDataRow(
                'Odd Parity:', result.oddParityValid ? 'OK' : 'FAIL', null),
            const SizedBox(height: 8),
            _buildCopyableField('Hex:', result.rawHex, colorScheme),
            const SizedBox(height: 6),
            _buildCopyableField('Binary:', result.rawBinary, colorScheme),
            if (result.errorMessage != null)
              Padding(
                padding: const EdgeInsets.only(top: 8.0),
                child: Text(
                  result.errorMessage!,
                  style: const TextStyle(color: Colors.red, fontSize: 12),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildDataRow(String label, String value, VoidCallback? onCopy) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2.0),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(fontWeight: FontWeight.w500)),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                value,
                style: const TextStyle(
                  fontFamily: 'RobotoMono',
                  fontWeight: FontWeight.bold,
                ),
              ),
              if (onCopy != null)
                IconButton(
                  icon: const Icon(Icons.copy, size: 16),
                  onPressed: onCopy,
                  visualDensity: VisualDensity.compact,
                ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildCopyableField(
      String label, String value, ColorScheme colorScheme) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: colorScheme.surfaceVariant.withOpacity(0.5),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Row(
        children: [
          Text('$label ', style: const TextStyle(fontWeight: FontWeight.w500)),
          Expanded(
            child: SelectableText(
              value,
              style: const TextStyle(
                fontFamily: 'RobotoMono',
                fontSize: 12,
              ),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.copy, size: 16),
            onPressed: () => _copyToClipboard(value, label),
            visualDensity: VisualDensity.compact,
          ),
        ],
      ),
    );
  }
}
