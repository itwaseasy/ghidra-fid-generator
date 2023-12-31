
# Ghidra Function ID database (fidb) generator

A set of scripts to help generate Ghidra fidb files from DEB packages in a headless mode.

It's based on the work of [THREATrack](https://github.com/threatrack/ghidra-fid-generator), so thank you for that.

## Quick start

```bash
$ wget -P debs http://ftp.debian.org/debian/pool/main/z/zlib/zlib1g-dev_1.2.13.dfsg-1_amd64.deb

$ ./01-unpack-debs.sh debs debian_bookworm
$ ./02-generate-fidb.sh ~/ghidra_home
Processing lib variant: debian_bookworm_zlib1g-dev_1.2.13.dfsg-1_amd64
 Importing and analyzing files
 Generating FidDB file
 Optimizing FidDB file
DONE!

$ ls ./fid_files
debian_bookworm_zlib1g-dev_1.2.13.dfsg-1_amd64.fidb
```

## Requirements

```bash
$ sudo apt install binutils gettext
$ # or `brew install binutils gettext` if you're using macOS
```
 **IMPORTANT:** GNU `ar` is required for scripts to work correctly. The default BSD `ar` on macOS will not work. So please set your `PATH` correctly after installing `binutils` using Brew.

All package names must follow [Debian naming conventions](https://www.debian.org/doc/manuals/debian-faq/pkg-basics.en.html#pkgname). This is already the case if you get them directly from the Debian or Ubuntu repositories.
​
## Usage

```
./01-unpack-debs.sh <path> <variant> [output_dir]
```

- `path`: directory containing debs to process.
- `variant`: as the Ghidra docs say, "*Version information that cannot be encoded in the formal _Version_ field can be encoded in this field*". This is usually the version of the compiler, OS, or whatever you want.
- `output_dir`: output directory for unpacked `.a` files, default is `libs`.

<br/>

```
./02-generate-fidb.sh <ghidra_home> [libs_dir] [projects_dir] [logs_dir] [output_dir]
```

- `ghidra_home`: directory containing the Ghidra installation.
- `libs_dir`: directory with unpacked DEB files, i.e. the result of the script `01-unpack-debs.sh`. The default is `libs`.
- `projects_dir`: directory in which Ghidra will create projects when importing libraries. Default value: `projects`.
- `logs_dir`: directory where Ghidra will write logs. Default value: `logs`.
- `output_dir`: directory for storing generated fidb files, default is `fid_files`.
