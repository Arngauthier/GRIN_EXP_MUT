# Gadgets Splicing: Dynamic Binary Transformation for Precise Rewriting

This repository guides you to build and test our work `GRIN` that is accepted at the CGO 2022.

## Overview

`GRIN` is an open-source dynamic binary rewriter based on REV.NG. It employs QEMU to execute basic blocks and lifts these blocks to LLVM IRs for our gadget-based entry address analysis, and then transforms LLVM IRs into rewritten binary files. 

The current version is an implementation of our concept prototype, the stable version will be updated later. This repository is based on Makefile.

## Requirements

We tested our work `GRIN` on Ubuntu-18.04 version. Check Ubuntu version:

```
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.3 LTS
Release:        18.04
Codename:       bionic
```

## Builds and install

Install dependencies.

```
$ sudo support/install-dependencies.sh
```


Compile and install `GRIN`.

```
$ make install-grin
```

## How to test

Switch to root user (we test in `ubuntu`).

```
$ sudo su
```

Initialize the command environment.

```
$ . ./environment
```

Create a hello world program.

```
$ cat > hello.c <<EOF
#include <stdio.h>

int main(int argc, char *argv[]) {
  printf("Hello, world!\n");
}
EOF
```

Compile.

```
$ x86_64-gentoo-linux-musl-gcc hello.c -o hello -static
```

Lift and translate.

```
$ grin-lift hello hello.ll 2>hello.log
$ grin translate hello
```

## Experimental Evaluation


Initialize the command environment. Note that all scripts need to be run with root admin privileges.

```
$ sudo su
$ . ./environment
$ cd test/
```
### Test SPEC2006 binaries:

Rewrite the SPEC2006 binaries.

```
$ ./lift_spec_O2.sh
$ ./lift_spec_O3.sh
```

After successfully running the lifting script, you can evaluate the rewritten files of SPEC2006 and produce the results.

```
$ ./result_spec_O2.sh
$ ./result_spec_O3.sh
```

### Test Coreutils and Real-World binaries:

We provide scripts to rewrite Coreutils and Real-World binaries.

```
$ ./lift_coreutils_realworld_O2.sh
```

Evaluate the rewritten files of Coreutils and Real-World and produce the results.

```
$ ./result_coreutils_realworld_O2.sh
```

### Results harvest:

```
$ ./count.sh
```

The aggregated results will be saved in `./result.csv` and `./result.csv.ascii_table.txt`.
The generated results are saved in the `result/` directory, which contains the test results of each benchmark.
