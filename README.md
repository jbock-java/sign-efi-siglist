# sign-efi-siglist

```
This tool is derived from efitools' "sign-efi-sig-list".
The name was changed to avoid confusion, because the output format is different:
"sign-efi-sig-list" creates output in "auth" format,
which is suitable for UEFI's standard "SetVariable" call.
By contrast, "sign-efi-siglist" outputs the native format of the Linux
"efivarfs" filesystem (with four extra bytes of "attributes").
On a Linux system, this can be more convenient, because such a "vardata" file
can be copied directly to the efivarfs filesystem.
This means that secureboot keys can be enrolled
without an additional tool like "efi-updatevar".
```

[efitools upstream](https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git)

[docs: UEFI Services - Runtime Services](https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html)

[docs: UEFI Secure Boot and Driver Signing](https://uefi.org/specs/UEFI/2.11/32_Secure_Boot_and_Driver_Signing.html)

[docs: kernel efivarfs](https://www.kernel.org/doc/html/latest/filesystems/efivarfs.html)

### Install dependencies

```sh
# Ubuntu / Debian
sudo apt-get install gnu-efi
# Fedora
sudo dnf install gnu-efi-devel
```

### Build

```sh
make cert-to-efi-sig-list
make sign-efi-siglist
```

### Create and enroll your keys

Keys and certificates can be created with the `openssl x509` command; see [Controlling Secure Boot](https://www.rodsbooks.com/efi-bootloaders/controlling-sb.html).
Let's assume you have created three pairs consisting of 6 files:

```
PK.key PK.crt
KEK.key KEK.crt
myOrg.key myOrg.crt
```

We could have called the last pair `db.key` and `db.crt`. But let's assume for now that we also want to enroll the "fedora secure boot signing certificate" along with `myOrg.crt`.

The fedora certificate comes in the form of an additional file `fedora.crt`. Note that we do not have the corresponding private key.

Choose a guid and convert all your `crt` files to "efi-siglist" format:

```sh
guid=4212023e-a290-11f0-bd3b-e446b04ad651
./cert-to-efi-sig-list -g $guid PK.crt PK.esl
./cert-to-efi-sig-list -g $guid KEK.crt KEK.esl
./cert-to-efi-sig-list -g $guid db_myOrg.crt db_myOrg.esl
```

You can find the microsoft keys here: <https://github.com/Foxboron/sbctl>

The `esl` files can be concatenated. Combine `myOrg.esl`, `fedora.esl` and microsoft keys to create `db.esl`:

```sh
cat db_myOrg.esl [...more keys, e.g. microsoft...] fedora.esl ../ > db.esl
```

Now sign the three `esl` files. This creates three files `PK.vardata`, `KEK.vardata` and `db.vardata`:

```sh
timestamp="2025-10-06 12:00:01"
# PK signs PK
./sign-efi-siglist -g $guid -t "$timestamp" -k PK.key -c PK.crt PK PK.esl PK.vardata
# PK signs KEK
./sign-efi-siglist -g $guid -t "$timestamp" -k PK.key -c PK.crt KEK KEK.esl KEK.vardata
# KEK signs db
./sign-efi-siglist -g $guid -t "$timestamp" -k KEK.key -c KEK.crt db db.esl db.vardata
```

The three `vardata` files do not contain private key data. They are not a secret.

You can now boot the target system in "Secure Boot Setup Mode" and enroll your keys,
by simply copying each to the appropriate place in the efivarfs:

```sh
chattr -i /sys/firmware/efi/efivars/*
cp db.vardata /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f
cp KEK.vardata /sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c
cp PK.vardata /sys/firmware/efi/efivars/PK-8be4df61-93ca-11d2-aa0d-00e098032b8c
```
