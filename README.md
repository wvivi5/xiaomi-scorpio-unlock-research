# Xiaomi Mi Note 2 (scorpio / MSM8996) Bootloader Unlock Feasibility — Research Notes

> **状态：终结性负面结论（Terminal negative result）**
> **结论一句话**：在不持有小米 RSA 私钥、不改动设备熔丝（QFPROM）的前提下，小米 Note 2（scorpio / MSM8996）**不存在任何可解锁、或可引导未签名内核（如 postmarketOS）的结构性通路**。零成本方案在固件层面被完整封死。
>
> 本文把逆向证据、真机实测、以及 GitHub 社区的独立交叉验证全部整理出来，**供后来者接着做**（见文末 [Open Leads](#open-leads--给后来者的接续点)）。

---

## TL;DR (English)

The Xiaomi Mi Note 2 (`scorpio`, MSM8996) **cannot be bootloader-unlocked**, and no unsigned kernel (e.g. postmarketOS) can be booted on a locked unit, **without Xiaomi's RSA private key or physical fuse manipulation**.

- Bootloader unlock = a **RSA-2048 signature over a device-generated token**, verified in `aboot` against Xiaomi's embedded public key. The signature only comes from Xiaomi's server.
- `aboot` itself is verified by SBL/Qualcomm secure boot — **any 1-byte patch bricks it** (real-device tested: reverts to EDL in ~0.4 s).
- The unlock flag is **re-derived from a signed token at every boot** (`AE0C`), so writing flags to `devinfo` is useless.
- And on top of all that, **Xiaomi's unlock server rejects the Note 2 with error `20039`** ("Device basic data verification failed"), because this old `aboot` emits an *incomplete* token. Independently confirmed by the MiUnlockTool community.
- The only theoretical bypass left is an `aboot` memory-corruption exploit (research-grade, guarded by a global stack canary). Details in [Open Leads](#open-leads--给后来者的接续点).

---

## 1. 背景与目标

- 设备：小米 Note 2（代号 `scorpio`，高通 MSM8996），2016 年机型。
- 目标：把 **postmarketOS**（官方支持 `xiaomi-scorpio`）刷上设备。为了让 10 台设备能低成本批量部署，尝试**零成本、不依赖小米官方服务器**地解除锁。
- 前提：EDL（9008）可进，全量包/分区镜像均已备份，任何实验失败都能恢复。
- 官方解锁通道对本机已不受支持；小米社区/服务器路线需要账号绑定且对本机报错（见 §6）。

---

## 2. 启动链与信任根

```
PBL (ROM, 高通不可读)
  → XBL / SBL  (QFPROM 根哈希签名)
    → aboot / ABL  (Qualcomm secure boot 自签名, SBL 强制校验)
      → boot.img / recovery.img  (锁定态下由 QSEE TA 验签)
```

关键点：

- `aboot`（即 LinuxLoader）里实现了 fastboot server 与锁逻辑。
- `aboot` 自身带认证段（ELF PH[2] `p_flags=0x70000001`，文件偏移 `0x1e6000` 起），由 SBL 用高通 OEM 根证书校验。
- **真机实测**：对 `aboot` 做 **1 字节** 改动并刷入 → 开机约 0.4 秒后弹回 EDL（SBL 拒绝）。→ 任何"改 aboot 跳过校验"的路直接死。

---

## 3. 解锁算法全图（逆向所得）

主入口：`0x92a3db20`；锁定判定后进入 fastboot。

```
getvar token                      → 设备返回本机 token（base64）
        │
        ▼  (小米服务器用私钥签名, RSA)
fastboot stage <encryptData>      → 把签名结果放进设备
fastboot oem unlock               → 交给 aboot 的 handler
```

`oem unlock` handler（`FUN_0x92a3abd4`）核心：

```c
// 0x92a3c048
memset(sp+4, 0, 0x80);                 // 128B 输出缓冲
bd60(len, arg, sp+4);                  // → 0x92a64860  RSA_public_decrypt
                                       //   RSA_NO_PADDING (rsa_none.c)
                                       //   公钥 DER @ 0x92a705a0, N = 2048-bit
if (失败)  print("Token Decryptiton Failed");
if (strcmp(0x92b8f298 /*当前 token*/, sp+4) != 0)   // 0x92a3a5b8 逐字节比较
    print("Token Verification Failed");
else {
    RAM+0x10 = 1; RAM+0x18 = 1;        // 解锁标志
    memcpy(RAM+0xE4, arg, 0x100);
    // 持久化到 devinfo
}
// 失败路径： reboot(8)   (0x92a3291c, r0=8)
```

**token 生成**（开机时由 `be00` 生成，发布为 `getvar token`）：

```
token = base64url( 12B 随机(RNG)  +  6B QFPROM "Serial Number" 熔丝 )
      = 18 字节  →  24 字符
```

- 末 6 字节是**本机唯一**的熔丝序列号 → donor 机器的 token 数学上不可移植。
- **每次开机随机段都变** → 实测重启前 `AncBtvmIlaA/78ER2KG7duoD` → 重启后 `PBHSrjPI6ifzERf22KG7duoD`。任何捕获的 token **无法跨 boot 重放**（签名也在重启后立即作废）。

**启动装载器 `AE0C`（`0x92a3ae0c`）—— 解释"为什么写标志没用"**：

```
开机 → 读 devinfo → 校验 magic("ANDROID-BOOT!")
     → 重新验证 +0xE4 处的 token（RSA vs 熔丝）
        ├─ 有效: RAM+0x10 = 1
        └─ 无效/空: 强制 RAM+0x10 = 0
```

`DECIDE`（`0x92a38fc8`）唯一读取该 RAM flag 来决定 `mode`（1=解锁 / 3=锁定）。**解锁状态不被存储信任，每次开机都按 token 重算** → 往 `devinfo` 里写标志位，下次开机即被抹掉。

---

## 4. 已验证死路清单（均有证据）

| # | 路线 | 死因 |
|---|------|------|
| 1 | 改 aboot 跳过校验 | SBL 强制校验 aboot 自签名；真机 1 字节改动 → 0.4s 弹回 EDL |
| 2 | donor token 移植 | token 尾 6B = 本机熔丝序列号，设备唯一 |
| 3 | 伪造 token | 需小米 RSA-2048 私钥（e=65537，不可分解） |
| 4 | 替换 OEM keystore（信任根） | keystore **内嵌于 aboot**（DER @文件 `0x7a3bc`）；`keystore` 分区全零且开机从不被读取 |
| 5 | 验签旁路全局变量 | 全量扫描无旁路；验签失败分支无条件 |
| 6 | `fastboot boot`（tethered 启动） | 门变量 `0x92a35024` / `0x92a34db0` 在锁定态恒为 1（强制拒绝 + 强制验签） |
| 7 | fastboot 命令置解锁标志 | 唯一写点需合法 token；`mode` 唯一入口是 `DECIDE` 读 RAM flag |
| 8 | 改 `devinfo` 解锁标志 | `AE0C` 每次开机按 token 重算覆盖（§3） |

> 说明：早期曾把 `oem unlock <畸形参数>` 导致的 USB 掉线当作"内存破坏漏洞种子"，后经真机实测**证伪**——那是设计好的失败路径 `reboot(8)`（消息原文即 "reboot the device"），设备重启后自恢复、仍锁定、健康。

---

## 5. 真机实测记录

- `fastboot oem device-info` → `Device unlocked: false`（锁定、健康）。
- `getvar token` 同一次开机内两次读取**相同**（boot 内静态）；**重启后改变** → 证明每次开机重生成。
- `oem unlock`（无参/非法值）→ `Token verification failed, reboot the device` → 设备重启（设计行为），随后自恢复 fastboot。
- 全部实验均可用 EDL 备份回滚。

> 出于隐私，本仓库不公开本机熔丝序列号与完整 token；文中结构已足以复现分析。

---

## 6. GitHub 社区独立交叉验证（2026-10）

这一节是本文最有价值的部分：**社区的独立证据与本机逆向结论逐字吻合**。

### 6.1 `lrh2000/Xiaomi-bootloader`（权威逆向）
- 原文 TL;DR：**"It is impossible to bypass Xiaomi's server to unlock the boot loader, unless the boot loader itself contains vulnerabilities."**
- 启动链 PBL→XBL→ABL（即本文 `aboot`）；解锁 = `getvar token` → 服务器私钥签名 → 设备用**内嵌公钥**验签。
- 现代机型 token = **36 字节**（含 header、14B 随机、**codename 字符串**、芯片 SN）→ 48 字符。

### 6.2 `MiForge/MiUnlockTool`（offici5l）
- Issue #58「Successful unlocks」：2024–2026 大量**老机型成功**（Redmi 4X/santoni、3S、4A、8、Note 7/8、Poco F1…），老机型常**免 7 天等待期**。
- FAQ：非 HyperOS 的老 MIUI 设备**无需**社区权限，只需在开发者选项绑定账号。

### 6.3 但 Note 2 被服务器以 `20039` 拒绝（决定性）
- **Issue #148「Mi Note 2 couldn't be unlocked」**：`product: MSM8996_A4` → `code 20039`。
- Issue #64 / #33：Note 2、Redmi 5A 同样 20039；**Mi 5（也是 MSM8996）**在 SG/EU 均 20039（中国区 500）。
- 错误码文档：**20039 = "The device token is incomplete — it doesn't contain the full set of required data."** 维护者注：**"只发生在部分老机型"**、**"目前无解"**。

### 6.4 维护者的关键实验（Issue #162，逐字复现本机逆向）

```
设备返回不完整 token:  deviceToken: 3ztAxu8xgV67edowT68
服务器:               code 20039  "Device basic data verification failed"
补齐:                 deviceToken + cpuid + codename
服务器:               code 0  "Private key signing successful"  → encryptData = 已签名 token
发回设备:              aboot 验签通过后，用【它原本返回的那份 token】与签名里的 token 比较
结果:                 比较失败 → 解锁失败
```
> 维护者结语：`Closing: the issue lies with the device itself, not the tool.`

**这正是本机 `aboot` 的 `c048 → strcmp(0x92b8f298 /*当前token*/, RSA解密结果)`（§3）。**

### 6.5 数据吻合
- 本机 `getvar token` 解码 = **18 字节** = `12B 随机` + `6B 熔丝 SN`。
- 现代格式为 **36 字节且内嵌 codename**；本机 18B **缺**该段 → 即服务器所说 "token incomplete"。
- `encryptData.md` 亦确认：`RAND` 每次开机刷新 → `encryptData` 重启后立即过期（与本机实测一致）。

---

## 7. 最终结论

1. **解锁态在密码学上绑定于"一段对本机熔丝有效的小米 RSA 签名"**。无小米私钥不可伪造。
2. **改 `devinfo` 标志无效**（每次开机 `AE0C` 重算归零）；**token 不可重放**（每次开机重生成）。
3. **改 `aboot` 无效**（SBL 强制校验其自签名）。
4. **服务器路线对本机证死**：Note 2 的 `aboot` 生成的是 *不完整* token（18B，缺 codename 段），服务器报 `20039`；即便补齐段能骗过服务器签发，本机 `aboot` 只认自己那份 18B token，`strcmp` 必失败。这是**固件缺陷**，非账号/区域/工具问题；付费第三方同样无解。

→ **该硬件不存在零成本、独立部署 pmOS 的通路。** 这是如实结论，不是暂未找到。

---

## Open Leads — 给后来者的接续点

如果你愿意继续，以下是我评估过、但未走完的方向（按可行性排序）：

1. **`aboot` 内存破坏漏洞（唯一残留理论通路）**
   - 起点：`c048` 把 2048-bit（256B）RSA 输出写进 **128B** 栈缓冲（`sub sp,#0x88` + `memset(sp+4,0,0x80)`）。
   - 限制：RSA 输入长度必须 ==256 才进入该路径（24B 短输入直接被拒）；且受**全局栈 canary `0x92b96d34`** 保护。
   - 需要：先找到 canary 泄漏原语 → ROP 置 RAM flag → **但仍需解决持久化**（重启后 `AE0C` 归零）→ 需写入真 token（需私钥）。工程闭环极难。
   - 有利面：无 KASLR（全固定地址），fastboot 攻击面是 2016 年代的代码。
2. **重新审视 XBL 的 Mi-Token UEFI 协议**：`lrh2000` 提到该协议有**三个函数**，其中一个被忽略。值得看看是否有可滥用点。
3. **审计其它 fastboot 命令解析器**：找 pre-auth 的内存破坏（越界/整数溢出），不局限于 `oem unlock`。
4. **QSEE TA（`lksecapp`）验证旁路**：锁定态下 boot/recovery 由 TA 验签。审计 TA 接口契约是否有缺陷。
5. **硬件层**：QFPROM 熔丝改写（需要 JTAG/熔丝烧录设备）——**非零成本**，故排除在本文范围外。
6. **换机**：确认了 Note 2 这条路封死后，若目标只是"跑 pmOS 的 10 台设备"，选择**没有此固件缺陷的机型**（例如社区大量成功解锁的老机型）是唯一稳妥的批量方案。

如果你在这些方向上取得进展，欢迎开 Issue / PR 补充证据。

---

## 参考文献 / References

- `lrh2000/Xiaomi-bootloader` — https://github.com/lrh2000/Xiaomi-bootloader
- `MiForge/MiUnlockTool`（offici5l）— https://github.com/MiForge/MiUnlockTool
  - Issue #58「Successful unlocks」、#64、#148「Mi Note 2 couldn't be unlocked」、#162「Error code: 20039」
  - 错误码参考 & `encryptData.md`
- `penn5/miunlock`（服务器端协议 `unlock.update.miui.com`，已停止维护）
- Qualcomm Chain of Trust — https://lineageos.org/engineering/Qualcomm-Firmware/
- postmarketOS device page: `xiaomi-scorpio`

---

## 免责声明 / Disclaimer

本记录仅针对**本人合法拥有的设备**进行**安全研究与逆向分析**，目的是安装开源操作系统（postmarketOS）。不包含、也无法提供小米私钥或任何绕过服务器的可用手段。请勿用于非授权设备或非法用途。

## License

文本内容采用 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)。
