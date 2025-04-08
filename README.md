# 🧠 ROP & Return-to-libc Exploitation

This project demonstrates **advanced memory exploitation** techniques including **Return-to-libc** and **ROP (Return-Oriented Programming)** using a vulnerable binary. The goal is to gain control over execution flow using crafted payloads, perform arbitrary function calls, and hijack logic using gadgets in `libc`.

---

## 🧱 Lab Goals

- 🔁 Crash a binary and inspect memory state.
- 🧨 Exploit return-to-libc with `system("/bin/sh")`.
- 💀 Chain `system` and `exit` for controlled shell exit.
- 🔐 Modify program logic by overwriting variables via ROP.
- 📣 Build ROP loops that print messages repeatedly or a set number of times.

---

## 🗂️ Project Structure

```
rop-and-return-to-libc/
├── q1a.py / q1b.py / q1c.py       # Return-to-libc payload generators
├── q3.py / q4.py / q5.py          # ROP chain payloads
├── addresses.py                   # Precomputed libc/sudo addresses
├── search.py                      # ROP gadget search engine
├── sudo / sudo.c                  # Vulnerable binary
├── libc_disassembly.asm          # Disassembly dump for gadget searching
├── smoketest.py                  # Auto-tests for each question
├── core, *.txt                   # Crash outputs & writeups
```

---

## 🚀 Usage

Each Python script generates an exploit payload and runs the binary.

### Example (Q1b: Return-to-libc)

```bash
python3 q1b.py
# Should spawn a shell via system("/bin/sh")
```

### Example (Q3: Overwrite Auth Variable)

```bash
python3 q3.py
# Should set auth = 1 and print "Victory!"
```

---

## 🔍 Key Concepts

- **Return-to-libc**: Overwrite return address with a libc function (like `system`).
- **ROP Chaining**: Chain small instruction "gadgets" ending in `ret` to perform logic without injecting shellcode.
- **Gadget Search**: Find gadgets via custom Python tooling in `search.py`.

---

## 🧪 Testing

Run smoketests for automated validation:

```bash
python3 smoketest.py
```

Covers:
- Core dump generation
- Functional shell execution
- Auth logic hijacking
- Message loops via ROP
- Gadget searching functionality

---

## 🧠 Requirements

- Linux OS (32-bit compatible for stack exploitability)
- Python 3.8+
- `infosec` Python module
- GDB for debugging and libc dumps
- Enabled core dumps (`ulimit -c unlimited`)

---

## ⚠️ Disclaimer

This repository is intended for **educational purposes only**. Do not use any techniques herein on unauthorized systems.

---

## 👨‍💻 Author

Crafted with stack-smashing love by [mati1mati1](https://github.com/mati1mati1)
