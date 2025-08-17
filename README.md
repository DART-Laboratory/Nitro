# Nitro

**Nitro** is a high-performance, tamper-evident logging system built entirely on Linux eBPF. It ensures forward security (FA) and offers provable security guarantees through the XLog secure logging protocol proposed in our paper.

---
> **This system is based on our paper published at ACM CCS 2025:**  
> *Rethinking Tamper-Evident Logging: A High-Performance, Co-Designed Auditing System*  
> Rui Zhao, Muhammad Shoaib, Viet Tung Hoang, and Wajih Ul Hassan  
> In ACM Conference on Computer and Communications Security (CCS), 2025  
>
> ```bibtex
> @inproceedings{nitro,
>   title = {Rethinking Tamper-Evident Logging: A High-Performance, Co-Designed Auditing System},
>   author = {Zhao, Rui and Shoaib, Muhammad and Hoang, Viet Tung and Hassan, Wajih Ul},
>   booktitle = {ACM Conference on Computer and Communications Security (CCS)},
>   year = {2025},
> }
> `
---

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


### 2) Recommended: run in a VM

For reproducibility and isolation, we recommend running Nitro inside a virtual machine.

- **Paper-scale configuration (for reproducing our experiments)**  
  Use **Ubuntu 22.04** with **Linux kernel 6.5.0** (or later).  
  Example profile: **36 vCPUs**, **300 GB RAM**, **≥ 200 GB disk**, virtio disk/NIC, and virtio-rng.
- Run ./bcc_install.sh to complete the setup.

> Tips  
> • Disable unnecessary background services in the guest to reduce noise during benchmarking.  
> • If you need stable timings, pin vCPUs and consider using hugepages on the host.

---

### 3) Easiest: use our prebuilt VM image (`Nitro.qcow2`)

We provide a prebuilt image aligned with the paper’s environment: **Ubuntu 22.04, kernel 6.5.0**, with Nitro and dependencies preinstalled.

You can download the VM [here](https://myuva-my.sharepoint.com/:f:/g/personal/dkw7xn_virginia_edu/EiFmv8E8mcJCnS4HWC1bVOcBbAs_m7ctdOjo06OeoY58gA?e=NnOaou).

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

1. Open Nitro.py, and go to line 28.
2. Replace:
```python
BPF_SOURCE_CODE = open('Nitro.c', 'rb').read().decode()
```
with
```python
BPF_SOURCE_CODE = open('Nitro-R.c', 'rb').read().decode()
```


### 📄 License

Nitro is licensed under the GNU General Public License v3.0 (GPLv3).
