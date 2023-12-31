
# Ghidra Function ID database (fidb) generator

A set of scripts to help generate Ghidra fidb files from DEB packages in a headless mode.

It's based on the work of [THREATrack](https://github.com/threatrack/ghidra-fidb-repo), so thank you for that.

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
 **IMPORTANT:** scripts require GNU `ar` to run correctly. BSD `ar`, which is the default on macOS, will not work. Therefore, please configure your `PATH` correctly after installing `binutils` with `brew`.

All package names must follow the [Debian naming conventions](https://www.debian.org/doc/manuals/debian-faq/pkg-basics.en.html#pkgname). This is already the case if you'll get them directly from the Debian or Ubuntu repos.
​
## Usage

```
./01-unpack-debs.sh <path> <variant> [output_dir]
```

- `path`: directory that contains debs to process.
- `variant`: as Ghidra docs say, "*Version information that cannot be encoded in the formal _Version_ field can be encoded in this field*". So usually it's a compiler version, OS, or whatever else you would like.
- `output_dir`: output directory for unpacked `.a` files, `libs` by default.

<br/>

```
./02-generate-fidb.sh <ghidra_home> [libs_dir] [projects_dir] [logs_dir] [output_dir]
```

- `ghidra_home`: directory that contains Ghidra installation.
- `libs_dir`: directory with unpacked DEB files, i.e. the result of the `01-unpack-debs.sh` script. The default is `libs`.
- `projects_dir`: directory where Ghidra will create projects during libs importing. The default is `projects`.
- `logs_dir`: directory where Ghidra will write logs, `logs` by default.
- `output_dir`: directory to store generated fidb files, `fid_files` by default.
