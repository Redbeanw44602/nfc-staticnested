# nfc-staticnested

This project ports the `hf mf staticnested` command from proxmark3 to the libnfc world.

## Features

- Reimplemented using C++23 and [nfcpp](https://github.com/Redbeanw44602/nfcpp).
- Good cross-platform compatibility.
- Easy to use and works well.

## Why port?

- For non-RFID specialists in developing countries, the proxmark3 might not be cost-effective.
- Furthermore, PN532 can perform almost all tag-based attacks, so it's time to fill that gap.

## Installation

### Via Package Manager

Archlinux ([AUR](https://aur.archlinux.org/packages/nfc-staticnested-git))

```
yay -S nfc-staticnested-git
```

*If you have packaged for other distributions, feel free to add them here.*

### Via Pre-built Binaries

The [release](https://github.com/Redbeanw44602/nfc-staticnested/releases) page provides pre-built binaries for Linux / MacOSX / Windows, covering the latest commits.

*Linux pre-built executables require glibc >= 2.30.*

### Via Self-built

To build this project by yourself, you need:

 - [Xmake](https://xmake.io/guide/quick-start.html)
 - Compiler that supports C++23
   - `GCC >= 15` or `Clang >= 21` are recommended.
   - Clang 20 is not supported: https://github.com/llvm/llvm-project/issues/133132
   - Apple Clang is the worst compiler and is therefore unsupported.
   - MSVC cannot be used because: https://github.com/nfc-tools/libnfc/pull/734

Once you have everything ready:

```
xmake
```

Good luck!

## Usage

The default mode assumes the tag type is 1K and does not save anything, only print the keychain to stdout.

```bash
# If no parameters are specified, the default mode will be used.
nfc-staticnested
```

For `mini`/`2k`/`4k` tags, use -m to specify:

> [!NOTE]
> These tags may lack testing; please see below.

```bash
nfc-staticnested -m 2k
```

To dump tags or generate a list of keys using `--dump` or `--dump-keys`, you need to provide a writable path.

```bash
nfc-staticnested --dump mycard.dump --dump-keys keys.txt
```

Staticnested attacks require at least one valid key; additional keys can be added using the `-k` option.

> [!NOTE]
> You should provide the full 48-bit key.

```bash
nfc-staticnested -k ABCDEFABCDEF -k 114514191981
```

View the full help text.

```bash
nfc-staticnested --help
```

## Important Note ⚠

For tags with two identical NtEncs, we may need to test tens of thousands of keys, which could take hours.

> [!CAUTION]
> **I am not responsible for any damage that may result.**  
> Please be mindful of heat dissipation when running the card reader for extended periods.

```
Attacking sector 1...
NtEnc_0 = 01200145 KeyStream_0 = DB7EFDC7
NtEnc_1 = 01200145 KeyStream_1 = DB7EFDC7
Found 73934 candidate keys.
Testing keys... (252/73934) 4.85 keys/s, estimated time: 4 hr, 13 min, 24 sec. (worst-case scenario)
```

If two different NtEncs can be obtained, a large number of candidate keys will be filtered out, and the attack time will be greatly reduced.

```
Attacking sector 0...
NtEnc_0 = 8EEF8F86 KeyStream_0 = EE5E3073
NtEnc_1 = 422B624D KeyStream_1 = 5CD5B759
Found 1 candidate keys.
KeyA found, is D0A758222680. (1 keys tested)
```

So, good luck! ;)

## Seeking help

I am not an RFID researcher, therefore I lack test samples or some hardwares. If you have any of the following, I would appreciate it if you could submit an issue to let me know if it is works or not.

- Can it work on the ACR122U?
- Can it work on Mifare Classic Mini/2K/4K?
- Can it work on MacOSX?

I have tested it in the following environments:

- PN532 + Mifare Classic 1K + Two Identical NtEncs + Archlinux

## Going further

There are plans to continue implementing `nfc-isen` (for static encrypted nonce) and support the exploit of the [fm11rf08s backdoor](github.com/RfidResearchGroup/proxmark3/blob/master/client/pyscripts/fm11rf08s_recovery.py).

If the tag contains a backdoor, `nfc-staticnested` will exit and print:

```
This tag has fm11rf08s backdoor, try nfc-isen?
```

Please give me a ⭐, thank you.

## Credits

- [Proxmark3](https://github.com/RfidResearchGroup/proxmark3)
- [nfcpp](https://github.com/Redbeanw44602/nfcpp)

## LICENSE

GPLv3
