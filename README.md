# nfc-staticnested

This project ported the `hf mf staticnested` command from proxmark3 to the libnfc world.

### Features

- Reimplemented using C++23 and [nfcpp](https://github.com/Redbeanw44602/nfcpp).
- Good cross-platform compatibility.
- Easy to use and works well.

### Why port?

- For non-RFID specialists in developing countries, the proxmark3 might not be cost-effective.
- Furthermore, PN532 can perform almost all tag-based attacks, so it's time to fill that gap.

### Usage

The default mode assumes the tag type is 1K and does not save anything, only print the keychain to stdout.

```bash
# If no parameters are specified, the default mode will be used.
nfc-staticnested
```

For `mini`/`2k`/`4k` tags, use -m to specify:

> [!WARNING]
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

### Important Note ⚠

For tags with two identical NtEnc sets, we may need to test tens of thousands of keys, which could take hours. Please be mindful of heat dissipation when running the card reader for extended periods.

```
Using key A from sector 0 to exploit...
Attacking sector 1...
NtEnc_0 = 01200145 KeyStream_0 = AA1EFBC9
NtEnc_1 = 01200145 KeyStream_1 = AA1EFBC9
Found 71122 candidate keys.
Testing keys... (123/71122) 5.00 keys/s, estimated time: 4 hr, 5 min, 6 sec. (worst-case scenario)
```

**I am not responsible for any damage that may result.**

Good luck! ... I once succeeded after testing with only 550/70,000 keys ;)

### Please help me!

I am not an RFID researcher, therefore I lack test samples or some hardwares. If you have any of the following, I would appreciate it if you could submit an issue to let me know if it is works or not.

- Can it work on the ACR122U?
- Can it work on Mifare Classic Mini/2K/4K?
- Can it work on tag that can get two sets of NtEnc? (Significantly reducing attack time?)
- Can it work on MacOSX?

I have tested it in the following environments:

- PN532
- Mifare Classic 1K
- Two identical NtEncs
- Archlinux

### LICENSE

GPLv3
