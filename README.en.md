# Xiaomi Mi Note 2 (scorpio / MSM8996) Bootloader Unlock Feasibility — Research Notes

> **Status: terminal negative result**
> **One-line conclusion:** Without Xiaomi's RSA private key and without manipulating the device fuses (QFPROM), the Xiaomi Mi Note 2 (`scorpio`, MSM8996) has **no structural path to bootloader unlock, and no way to boot an unsigned kernel** (e.g. postmarketOS). Every zero-cost route is sealed off at the firmware level.
>
> This repo collects the reverse-engineering evidence, real-device tests, and independent community cross-validation — written so that **future researchers can pick it up** (see [Open Leads](#open-leads--where-to-continue)).

*[中文版见 README.md](README.md)*

---

## TL;DR

- Bootloader unlock = a **RSA-2048 signature over a device-generated token**, verified inside `aboot` against Xiaomi's embedded public key. The signature can only be produced by Xiaomi's server.
- `aboot` itself is verified by SBL / Qualcomm secure boot — **any 1-byte patch bricks it** (real-device tested: reverts to EDL in ~0.4 s).
- The unlock flag is **re-derived from a signed token at every boot** (`AE0C`), so writing flags into `devinfo` is useless.
- On top of all that, **Xiaomi's unlock server rejects the Note 2 with error `20039`** ("Device basic data verification failed"), because this old `aboot` emits an *incomplete* token. Independently confirmed by the MiUnlockTool community — including a maintainer experiment that reproduces our RE exactly.
- The only theoretical bypass left is an `aboot` memory-corruption exploit (research-grade, guarded by a global stack canary). Details in [Open Leads](#open-leads--where-to-continue).

---

## 1. Background & Goal

- Device: Xiaomi Mi Note 2 (codename `scorpio`, Qualcomm MSM8996), a 2016 phone.
- Goal: run **postmarketOS** (which officially supports `xiaomi-scorpio`). To deploy 10 units cheaply, we tried to **unlock without depending on Xiaomi's server, at zero cost**.
- Preconditions: EDL (9008) is always reachable; all partitions are backed up; any failed experiment can be restored.
- The official unlock channel no longer supports this device; the community/server route requires account binding and returns an error for this exact model (see §6).

---

## 2. Boot chain & root of trust

```
PBL (ROM, unreadable)
  → XBL / SBL     (signed by QFPROM root hash)
    → aboot / ABL (Qualcomm secure-boot self-signed; SBL enforces it)
      → boot.img / recovery.img  (verified by a QSEE TA when locked)
```

Key points:

- `aboot` (a.k.a. LinuxLoader) implements the fastboot server and the lock logic.
- `aboot` carries an authentication segment (ELF PH[2] `p_flags=0x70000001`, starting at file offset `0x1e6000`), checked by SBL against Qualcomm's OEM root certificate.
- **Real-device test:** a **1-byte** change to `aboot`, flashed in, makes the device fall back to EDL in ~0.4 s (SBL rejects it). → Any "patch aboot to skip verification" route is dead on arrival.

---

## 3. The full unlock algorithm (from RE)

Main entry: `0x92a3db20`. In the locked state it drops into fastboot.

```
getvar token                      → device returns its token (base64)
        │
        ▼  (Xiaomi server signs it with its private key, RSA)
fastboot stage <encryptData>      → push the signature onto the device
fastboot oem unlock               → handled by aboot
```

Handler for `oem unlock` (`FUN_0x92a3abd4`):

```c
// 0x92a3c048
memset(sp+4, 0, 0x80);                 // 128-byte output buffer
bd60(len, arg, sp+4);                  // → 0x92a64860  RSA_public_decrypt
                                       //   RSA_NO_PADDING (rsa_none.c)
                                       //   public key DER @ 0x92a705a0, N = 2048-bit
if (failed)  print("Token Decryptiton Failed");
if (strcmp(0x92b8f298 /*current token*/, sp+4) != 0)   // 0x92a3a5b8, byte-by-byte
    print("Token Verification Failed");
else {
    RAM+0x10 = 1; RAM+0x18 = 1;        // unlock flag
    memcpy(RAM+0xE4, arg, 0x100);
    // persist into devinfo
}
// failure path:  reboot(8)   (0x92a3291c, r0=8)
```

**Token generation** (produced at boot by `be00`, published as `getvar token`):

```
token = base64url( 12 random bytes (RNG)  +  6 bytes QFPROM "Serial Number" fuse )
      = 18 bytes  →  24 chars
```

- The last 6 bytes are **this unit's unique** fuse serial → a donor's token can never be transplanted (mathematically).
- The random part changes **every boot** → observed `AncBtvmIlaA/78ER2KG7duoD` before a reboot and `PBHSrjPI6ifzERf22KG7duoD` after. Any captured token **cannot be replayed across boots** (the signature also expires immediately after a reboot).

**Boot-time loader `AE0C` (`0x92a3ae0c`) — why writing the flag is useless:**

```
boot → read devinfo → check magic("ANDROID-BOOT!")
     → re-verify the token at +0xE4 (RSA vs. fuse)
        ├─ valid:  RAM+0x10 = 1
        └─ invalid/empty: force RAM+0x10 = 0
```

`DECIDE` (`0x92a38fc8`) is the *only* reader of that RAM flag, choosing `mode` (1 = unlocked / 3 = locked). **The unlock state is not trusted from storage; it is recomputed from a token every boot.** So writing a flag into `devinfo` gets wiped on the next boot.

---

## 4. Verified dead ends (all with evidence)

| # | Route | Why it fails |
|---|-------|--------------|
| 1 | Patch `aboot` to skip checks | SBL enforces aboot's self-signature; real-device 1-byte change → EDL in 0.4 s |
| 2 | Transplant a donor token | Token tail 6B = this unit's unique fuse serial |
| 3 | Forge a token | Needs Xiaomi's RSA-2048 private key (e=65537, infeasible) |
| 4 | Replace the OEM keystore (root of trust) | keystore is **embedded in aboot** (DER @ file `0x7a3bc`); the `keystore` partition is all-zero and never read at boot |
| 5 | Bypass via a global verification variable | Full scan found no bypass; the failure branch is unconditional |
| 6 | `fastboot boot` (tethered boot) | Gate vars `0x92a35024` / `0x92a34db0` are constant 1 when locked (hard refuse + hard verify) |
| 7 | A fastboot command to set the unlock flag | The only write site needs a valid token; `mode` is only set by `DECIDE` reading the RAM flag |
| 8 | Write the `devinfo` unlock flag | `AE0C` recomputes/overwrites it from the token every boot (§3) |

> Note: an earlier "`oem unlock <malformed arg>` USB crash" was mistaken for a memory-corruption bug seed. Real-device testing **disproved** it — it is the designed failure path `reboot(8)` (the message literally says "reboot the device"). The device self-recovers to fastboot, still locked and healthy.

---

## 5. Real-device test log

- `fastboot oem device-info` → `Device unlocked: false` (locked, healthy).
- `getvar token` twice within one boot → **identical** (static per boot); **changes after reboot** → proves per-boot regeneration.
- `oem unlock` (no arg / invalid) → `Token verification failed, reboot the device` → device reboots (by design), then self-recovers to fastboot.
- Every experiment is recoverable via EDL backups.

> For privacy, this repo does not publish this unit's fuse serial or full tokens; the structure shown is enough to reproduce the analysis.

---

## 6. Independent community cross-validation (2026-10)

This is the most valuable part: **independent community evidence matches our RE exactly.**

### 6.1 `lrh2000/Xiaomi-bootloader` (authoritative RE)
- TL;DR: **"It is impossible to bypass Xiaomi's server to unlock the boot loader, unless the boot loader itself contains vulnerabilities."**
- Boot chain PBL→XBL→ABL (our "aboot"); unlock = `getvar token` → server private-key signature → device verifies with an **embedded public key**.
- Modern devices' token = **36 bytes** (header, 14 random bytes, **codename string**, chip SN) → 48 chars.

### 6.2 `MiForge/MiUnlockTool` (offici5l)
- Issue #58 "Successful unlocks": many **old devices** succeed in 2024–2026 (Redmi 4X/santoni, 3S, 4A, 8, Note 7/8, Poco F1…), old devices often **skip the 7-day wait**.
- FAQ: non-HyperOS old MIUI devices need **no** community permission — just bind the account in Developer Options.

### 6.3 But the Note 2 is rejected by the server with `20039` (decisive)
- **Issue #148 "Mi Note 2 couldn't be unlocked"**: `product: MSM8996_A4` → `code 20039`.
- Issues #64 / #33: Note 2, Redmi 5A get 20039; **Mi 5 (also MSM8996)** gets 20039 in SG/EU (China returns 500).
- Error-code docs: **20039 = "The device token is incomplete — it doesn't contain the full set of required data."** Maintainer: **"only occurs in some older devices"**, **"no confirmed solution at this time."**

### 6.4 The maintainer's experiment (Issue #162 — reproduces our RE verbatim)

```
device returns an incomplete token:  deviceToken: 3ztAxu8xgV67edowT68
server:                              code 20039  "Device basic data verification failed"
reconstruct:                         deviceToken + cpuid + codename
server:                              code 0  "Private key signing successful"  → encryptData = signed token
send back to device:                 aboot verifies the signature, then compares the token it ORIGINALLY
                                     returned against the token inside the signature
result:                              comparison fails → unlock fails
```
> Maintainer's closing note: `Closing: the issue lies with the device itself, not the tool.`

**This is exactly our `aboot`'s `c048 → strcmp(0x92b8f298 /*current token*/, RSA_decrypt(...))` (§3).**

### 6.5 Data match
- Our `getvar token` decodes to **18 bytes** = `12 random` + `6 fuse SN`.
- The modern format is **36 bytes with the codename embedded**; ours **lacks** that segment → exactly the server's "token incomplete".
- `encryptData.md` also confirms `RAND` refreshes every boot → `encryptData` expires right after a reboot (matches our tests).

---

## 7. Final conclusion

1. **The unlock state is cryptographically bound to a Xiaomi RSA signature valid for this unit's fuse.** It cannot be forged without Xiaomi's private key.
2. **Writing the `devinfo` flag does nothing** (`AE0C` recomputes it every boot); **tokens cannot be replayed** (regenerated every boot).
3. **Patching `aboot` does nothing** (SBL enforces its self-signature).
4. **The server route is dead for this model**: the Note 2's `aboot` emits an *incomplete* token (18 B, missing the codename segment), so the server returns `20039`; even reconstructing the segment to please the server doesn't help, because the device only accepts the token it originally emitted (`strcmp` fails). This is a **firmware defect**, not an account/region/tooling problem; paid third parties cannot fix it either.

→ **There is no zero-cost, standalone path to postmarketOS on this hardware.** This is a factual conclusion, not a "not found yet".

---

## Open Leads — where to continue

Tracked as GitHub issues (label `help wanted`):

1. **[Issue #1](https://github.com/wvivi5/xiaomi-scorpio-unlock-research/issues/1)** — `aboot c048`: 256-byte RSA output into a 128-byte stack buffer (+ global canary `0x92b96d34`). Needs a canary leak → ROP → set flag.
2. **[Issue #5](https://github.com/wvivi5/xiaomi-scorpio-unlock-research/issues/5)** — *(most promising)* Is there any **official** Note 2 `aboot`/ROM that emits a **complete** token? If so, flashing it (it's officially signed, so SBL accepts it) would make both server and device agree → unlock.
3. **[Issue #2](https://github.com/wvivi5/xiaomi-scorpio-unlock-research/issues/2)** — audit the third (ignored) function of XBL's Mi-Token UEFI protocol.
4. **[Issue #3](https://github.com/wvivi5/xiaomi-scorpio-unlock-research/issues/3)** — audit other fastboot command parsers for pre-auth memory corruption.
5. **[Issue #4](https://github.com/wvivi5/xiaomi-scorpio-unlock-research/issues/4)** — audit the QSEE TA (`lksecapp`) signature-verification interface.

Other notes:

6. **Hardware:** QFPROM fuse manipulation (needs JTAG/fuse-blowing hardware) — **not zero-cost**, out of scope here.
7. **Different device:** if the real goal is "10 cheap devices running pmOS", picking a model **without this firmware defect** (many old devices unlock fine per §6.2) is the only reliable batch option.

---

## References

- `lrh2000/Xiaomi-bootloader` — https://github.com/lrh2000/Xiaomi-bootloader
- `MiForge/MiUnlockTool` (offici5l) — https://github.com/MiForge/MiUnlockTool
  - Issue #58 "Successful unlocks"; #64; #148 "Mi Note 2 couldn't be unlocked"; #162 "Error code: 20039"
  - error-code reference & `encryptData.md`
- `penn5/miunlock` (server protocol `unlock.update.miui.com`, unmaintained)
- Qualcomm Chain of Trust — https://lineageos.org/engineering/Qualcomm-Firmware/
- postmarketOS device page: `xiaomi-scorpio`

---

## Disclaimer

This material documents security research / reverse engineering performed on a device the author legally owns, for the purpose of installing postmarketOS (an open-source OS). It contains no private keys and provides no means to bypass Xiaomi's servers. Do not use it on devices you do not own or for unlawful purposes.

## License

Text content is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
