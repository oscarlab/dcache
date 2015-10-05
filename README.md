# Linux Directory Cache (dcache) Optimization

For more details about the principles and designs of this optimization, please
see this paper:

*How to Get More Value From Your File System Directory Cache*<br>
[download](http://www3.cs.stonybrook.edu/~porter/pubs/sosp15-final.pdf)<br>
**Chia-Che Tsai, Yang Zhan, Jayashree Reddy, Yizheng Jiao, Tao Zhang,
Donald E. Porter (Stony Brook University)**<br>
Published in SOSP 2015

This code is a optimized design of Linux directory cache, to improve hit latency
for path lookup, and reduce cache miss for directory listing and unique file
creation.

### Building instructions

This optimization is implemented on top of Linux 3.14 kernel, with changes in
the dcache source code, including:

* include/linux/types.h
* include/linux/dcache.h
* include/linux/namei.h
* fs/dcache.c
* fs/namei.c
* fs/namespace.c

To build the kernel, use `make menuconfig` or copy a old Linux 3.14 config file
into the `linux-3.14` directory. By default, the dcache optimization is enabled,
and set to default options. For more tuning in the dcache optimization, change
the options in `make menuconfig`:

```
  -> File systems
      -> dcache optimization
```

After setting up the kernel options, use `make` and `make install`, or building
tools such as `make-kpkg` to build and install the kernel. Basic knowledge and
experience about building, installing and booting alternative Linux kernel is
required.
