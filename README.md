<p align="center">
  <img src="./logo.png" alt="Nitro Logo" width="300"/>
</p>

**Nitro** is a high-performance, tamper-evident logging system built entirely on Linux eBPF. It ensures forward security (FA) and offers provable security guarantees through the XLog secure logging protocol proposed in our paper.

Nitro is based on our paper published at **ACM Conference on Computer and Communications Security (CCS) 2025**:  
*Rethinking Tamper-Evident Logging: A High-Performance, Co-Designed Auditing System*  
Rui Zhao, Muhammad Shoaib, Viet Tung Hoang, and Wajih Ul Hassan  
**🏅 Distinguished Paper Award**

```bibtex
@inproceedings{nitro,
  title = {Rethinking Tamper-Evident Logging: A High-Performance, Co-Designed Auditing System},
  author = {Zhao, Rui and Shoaib, Muhammad and Hoang, Viet Tung and Hassan, Wajih Ul},
  booktitle = {ACM Conference on Computer and Communications Security (CCS)},
  year = {2025},
}
```

## Why Nitro?
Security teams rely on logs to reconstruct attacks — but traditional loggers are too slow, lose data, or require expensive hardware. Nitro brings together **cryptography, operating systems, and modern kernel technology** to deliver logs that are:  

- **Tamper-evident** (attackers cannot silently alter history)  
- **Fast and scalable** (handles enterprise-level workloads)  
- **Practical to deploy** (no kernel patches, works with standard Linux)  

---

## Key Features

- 🔒 **Stronger Security**  
  Every log entry is cryptographically protected, making it obvious if attackers try to modify or delete logs.  

- ⚡ **High Performance**  
  Nitro handles massive workloads with **10×–25× speedups** in stress tests and **2×–10× faster performance** in real-world scenarios — all while avoiding data loss.  

- 🛠 **Easy to Deploy**  
  Runs fully in eBPF, meaning no kernel recompilation, no special hardware, and smooth integration on modern Linux systems.  

- 🧩 **Built for Today’s SOCs**  
  Designed to support security teams with reliable logs for **forensics, incident response, and compliance**.  

- 🗂 **Nitro-R Extension**  
  An optional add-on that reduces duplicate or redundant logs *before* they leave the kernel, cutting down storage and runtime costs even further.  

---


## 📦 Installation

### 1) Native install (by OS)

#### Ubuntu

Run the provided script to install all necessary components:
```bash
./bcc_install.sh
```

#### CentOS

For CentOS systems, you need to install BCC (BPF Compiler Collection) manually:

1. Clone the BCC repository:

```bash
git clone https://github.com/iovisor/bcc
```

2. Install dependencies and build:

Follow the official BCC installation instructions from the repository you just cloned.

📌 Tip: You can also refer to bcc_install.sh in this repo for version-specific dependencies and setup guidance.


### 2) Easiest: use our prebuilt VM image (`Nitro.qcow2`)

We provide a prebuilt Ubuntu 22.04 image with kernel 6.8.0, including Nitro and all dependencies preinstalled.

You can download the VM [here](https://myuva-my.sharepoint.com/:f:/g/personal/hur7wv_virginia_edu/EpDI8d9GXfFPvDDTi6XJagUBBOV-CFgGK5REW-dnUMplzQ?e=Xg15gS).

- **Default credentials**  
  `username: nitro`  
  `password: Nitro`

#### A) Import with KVM/libvirt (`virt-install`)
1. Place the image on the host, e.g. `/tmp/Nitro.qcow2`.
2. Create the VM by importing the existing disk:
```bash
   sudo virt-install \
     --name Nitro \
     --ram 307200  --vcpus 36 \
     --cpu host-passthrough \
     --disk path=/tmp/Nitro.qcow2,format=qcow2,bus=virtio \
     --os-variant ubuntu22.04 \
     --network network=default,model=virtio \
     --import \
     --graphics none
```

3. Get the VM’s IP:

   ```bash
   virsh domifaddr Nitro
   ```
4. Log in:

   ```bash
   ssh nitro@<vm-ip>
   ```

#### B) Import with **virt-manager** (GUI)

1. Open **virt-manager** → “Import existing disk image”.
2. Select `Nitro.qcow2`, set OS type to Ubuntu 22.04, and choose virtio for disk/NIC.
3. Assign vCPUs/RAM (use paper or dev profile), finish, boot, and log in as `nitro`.

> Tips  
> • Disable unnecessary background services in the guest to reduce noise during benchmarking.  
> • If you need stable timings, pin vCPUs and consider using hugepages on the host.

## 📜 Script Overview

This repository contains the following key scripts and sources:

- **`Nitro.py`**  
  Loader/runner for the C-side programs **Nitro** and **Nitro-R**. 

  It compiles/loads the eBPF program, opens the ring buffer, captures logs streamed from kernel space, and writes them to disk. It also exposes command-line options for runtime configuration.

- **`Nitro.c`** & **`Nitro.h`**  
  Core eBPF logic of **Nitro** and its header definitions. 

  Including MAC processing (XLog), log capture, two-level buffers (Per-CPU Array/ring buffer), and two-level time controllers (SGAP/GAP).

- **`Nitro-R.c`** & **`Nitro-R.h`**  
  Variant of the core logic (**Nitro-R**) and its headers. 

  Including all Nitro features plus kernel-side log reduction.

- **`Decoder.py`**  
  Userspace decoder for kernel-encoded records. It can be invoked **at runtime** (decode on the fly) or **post-hoc** (decode after capture).  

  Post-hoc decoding provides better runtime performance. For easier auditing and inspection, runtime decoding is **enabled by default**.

- **`bcc_install.sh`**  
  One-step script to install eBPF/BCC dependencies (primarily for Ubuntu).

See [Evaluation Readme](./eval/README.md) for more Details.


## 🧪 Usage

**Nitro** includes two main components:

- `Nitro.c` – the eBPF-based system call logger
- `Nitro.py` – the Python-based log parser and printer

To start capturing system calls with the general default settings, run:

```bash
python3 Nitro.py --full-fixed-len 3000 \
              --full-flex 8000 \
              --flexsize 32 \
              --ring-size 64 \
              --total-max-flex 100 \
              --commsize 64 \
              --gap 1000000000 \
              --sgap 200000000 \
              --output-file "./log.txt"
```

This setting works well for most scenarios.

### 🛠 Command-Line Options

| Option                   | Description                      | Default      |
|--------------------------|----------------------------------|--------------|
| `-f`, `--full-fixed-len` | Full fixed buffer length         | `3000`       |
| `-x`, `--full-flex`      | Full flex buffer length          | `8000`       |
| `-z`, `--flexsize`       | Flex MAC size                    | `32`         |
| `-r`, `--ring-size`       | Ring buffer size (MB)            | `64`         |
| `-t`, `--total-max-flex` | Total max flex entries           | `100`        |
| `-c`, `--commsize`       | Communication buffer size        | `64`         |
| `-s`, `--sgap`           | First-level time threshold (ns)  | `200000000`  |
| `-g`, `--gap`            | Second-level time threshold (ns) | `1000000000` |
| `-o`, `--output-file`    | Output file path                 | `./log.txt`  |


Running Nitro-R:

1. Open Nitro.py and find the line that loads the eBPF source.
2. Replace:
```python
BPF_SOURCE_CODE = open('Nitro.c', 'rb').read().decode()
```
with
```python
BPF_SOURCE_CODE = open('Nitro-R.c', 'rb').read().decode()
```


### 📄 License

Nitro is released under the [MIT License](./LICENSE).

- **eBPF programs** (`Nitro.c`, `Nitro-R.c`, `Nitro.h`, `Nitro-R.h`) are dual-licensed under `GPL-2.0-only OR MIT` ([GPL-2.0 text](./LICENSES/GPL-2.0-only.txt)), so you may use them under either license. They call GPL-only kernel helpers, so they declare the GPL-compatible license string `Dual MIT/GPL` to the kernel.
- **Third-party benchmark code and data** under `eval/`, as well as `bcc_install.sh`, are not covered by Nitro's license and keep their original licenses (eAudit: GPL-3.0-or-later; lmbench, PostMark, and the httperf web content: see [eval/THIRD_PARTY.md](./eval/THIRD_PARTY.md)).
- The Nitro logo (`logo.png`, `logo.pptx`) is not covered by the MIT License. It was made with Canva and contains third-party design elements and the Lovelo typeface.
- Versions of this repository up to commit `9b1ee5f` (October 2025) stated that Nitro was licensed under GPLv3. That grant is not revoked: Nitro's own code obtained from those versions may continue to be used under GPLv3. Third-party files in `eval/` were always under their own licenses.
