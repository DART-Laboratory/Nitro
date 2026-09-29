# Third-party components in `eval/`

Nitro's own code is released under the [MIT License](../LICENSE), and its eBPF programs are dual-licensed `GPL-2.0-only OR MIT`. The files listed below were **not originally written by the Nitro authors** (some were adapted by them; see *Modifications*). They are **not covered by Nitro's license**, keep their original licenses, and are included only so the benchmarks in the paper are easy to reproduce.

| Path | Origin | License |
|---|---|---|
| `bmrun`, `bmrunall`, `run_find`, `run_httperf`, `run_kernbuild`, `run_pm`, `run_rdwr`, `run_shbm`, `run_tar`, `httperf/README`, `httperf/uris.txt`, `postmark/README`, `postmark/Makefile`, `postmark/pm-config.reg`, `postmark/pm-config.sm`, `rdwr/README`, `rdwr/Makefile`, `rdwr/twrite.c`, `rdwr/rdwr_data.tgz`, and [`../bcc_install.sh`](../bcc_install.sh) | Benchmark scripts and installer from [eAudit](https://github.com/seclab-stonybrook/eaudit), © Hanke Kimm, R. Sekar and the eAudit authors, Stony Brook University | GPL-3.0-or-later ([license text](../LICENSES/GPL-3.0-or-later.txt)) |
| `postmark/postmark-1_5.c` | PostMark 1.5 by Jeffrey Katcher, © 1997–2001 Network Appliance, Inc. (unmodified; obtained through eAudit) | Artistic License 1.0 (Perl variant), appended to the file. The Mersenne Twister code inside the file is LGPL-2.0-or-later ([license text](../LICENSES/LGPL-2.0-or-later.txt)). |
| `lmbench/` | lmbench3 by Larry McVoy and Carl Staelin, taken from [intel/lmbench](https://github.com/intel/lmbench) commit `701c6c3` with a local change to `scripts/build` by the Nitro authors in 2025 (link against libtirpc) | GPL plus additional restrictions on publishing results; see `lmbench/COPYING` and `lmbench/COPYING-2`. If you publish lmbench results, read `COPYING-2` first. |
| `httperf/contents/` | Copy of files from the public website of the Secure Systems Lab (R. Sekar), Stony Brook University, <https://www.seclab.cs.sunysb.edu/seclab/>. Nitro uses them only as static files served during the httperf benchmark. | All rights reserved by their respective owners, including the publishers of the included papers. **Not** licensed under Nitro's license. |
| `postmark/postmark`, `rdwr/twrite`, `lmbench/bin/`, `lmbench/results/` | Binaries built from the sources above, and lmbench output from the authors' test machine | Same as the corresponding sources |

**Modifications.** In 2025 the Nitro authors modified `bmrun`, `bmrunall`, `run_httperf`, `httperf/README`, `httperf/uris.txt` (two entries removed), `postmark/README`, and `rdwr/README` to adapt the eAudit suite to Nitro/Nitro-R. The remaining eAudit files listed above are unmodified.

**Nitro-authored files** in this directory (`README.md`, `prepare.sh`, this file) are covered by Nitro's MIT License.

If you are a rights holder of any of the files above and would like them attributed differently or removed, please open an issue.
