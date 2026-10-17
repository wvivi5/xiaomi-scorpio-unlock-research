# 小米 Note 2 (scorpio) 不解锁装 pmOS —— 攻防路线终局报告

日期：2026-10-17（Phase A 失败后多轮逆向的最终结论）
设备：测试机 SN 8512**REDACTED**（token 序列号 `d8a1bb**REDACTED**`），donor SN 28a3**REDACTED**（token 序列号 `9cee**REDACTED**`）

## 一、结论（一句话）

**在不持有小米 RSA 私钥、不改动 QFPROM 熔丝的前提下，本机不存在任何可引导未签名内核的结构性通路。**
零成本独立部署 pmOS 在硬件/固件层面被完整封死；余下仅两条非常规路：官方/付费解锁（依赖小米服务器）或 aboot 内存破坏漏洞利用（研究级工程）。

## 二、已验证死路清单（全部有证据）

| # | 路线 | 死因 | 证据 |
|---|------|------|------|
| 1 | 改 aboot（跳过 token 校验） | QC secboot 自签名：aboot 尾部 0x1e6000 起为认证段，SBL 内置 OEM 根证书校验 aboot 自身签名；**真机实测**：1 字节改动的 aboot 刷入后 0.4s 弹回 EDL | `gate_test.log`；aboot ELF PH[2]=0x70000001 认证段 |
| 2 | donor token 移植 | 解锁 token = RSA-2048 PKCS#1 v1.5 真签名，消息尾 6 字节 = QFPROM "Serial Number" 熔丝（设备唯一）；我方 `d8a1bb**REDACTED**` ≠ donor `9cee**REDACTED**`（`fastboot getvar token` 直读，静态值，18B base64） | `token_final.py`、本轮 getvar token 实测 |
| 3 | 伪造 token | e=65537 标准 PKCS#1，无攻击面；需小米私钥 | 同上 |
| 4 | 替换 OEM keystore（信任根） | keystore = **内嵌于 aboot**（DER @文件偏移 0x7a3bc，1653B，含 RSA-2048 根证书，sha256WithRSA）；`keystore` 分区（sda，512KB 全零）开机从不被读取，仅 fastboot flash 功能且需解锁 | `disasm16-19.txt`、`keystore_embedded.der` |
| 5 | 验签旁路全局变量 | 119e0 = `bl QSEE验证; cmp r0,#0x33; beq 成功`，无任何条件旁路；c3c/bc4 等"疑似变量"经全量扫描无引用或仅为状态标志 | `disasm19.txt` |
| 6 | fastboot boot（tethered 启动） | gate 0x92a35024 恒 1（锁定时直接 "unlock device to use this command"）；验签 gate 0x92a34db0 恒 1（锁定时必验签） | `disasm15.txt` |
| 7 | fastboot 命令置解锁标志 | 无任何命令无条件写 +0x10；唯一写点 ac18 需 token；mode(0x92a937b8) 唯一设置入口 = DECIDE(0x92a38fc8) 读 RAM flag | `fastboot_cmds.txt`、`disasm17.txt` |
| 8 | ae0c / 改 devinfo 解锁标志 | **AE0C(0x92a3ae0c) 开机重验 token**：读 devinfo → 重验 +0xE4 处 token(RSA vs 熔丝) → 有效才置 +0x10=1，无效/空强制归 0。解锁标志不被存储信任，每次开机按 token 重算 → Phase A 写 +0x10 下次开机即被抹 | `disasm27.txt`（AE0C 全解码） |

## 三、验证架构全图（本轮逆向成果）

```
开机 → PBL(ROM) → XBL(SBL, QFPROM根哈希签名) → aboot(QC secboot 自签名, SBL强制校验)
aboot 主入口:
  ae0c: 读 devinfo → magic → RSA验 token(内嵌公钥 0x92a705a0) →
        解出18B → [12:18] 与 QFPROM Serial Number 熔丝暂存(0x74138) strcmp
        → 有效: RAM+0x10=1; 无效/空: 强制0
  DECIDE(38fc8): flag? → set_mode(1)=解锁(横幅+跳验签) : set_mode(3)=锁定
                 → 11b70: 加载内嵌keystore(117e4→54b90解析DER@0x7a3bc)
                 → 失败仅打印 "Keystore verification failed! Continuing anyways"
  锁定路径: 读 boot 分区 → 37510→120ac verify_image_with_sig(目标名 /boot|/recovery)
            → 119e0 → QSEE TA(lksecapp) 验签, 成功条件 = TA 返回 0x33
  fastboot boot: 35024(恒1)&&flag==0 → 拒绝; 34db0(恒1)&&flag==0 → 强制验签
unlock token 消息 = base64(12B固定数据 + 6B熔丝序列号); getvar token 可读我方消息
```

关键地址：mode=0x92a937b8（初值3，1=解锁）；keystore DER=aboot 文件 0x7a3bc（VA 0x92a723bc）；RAM flag=0x92b6a32c+0x10；"Device is unlocked!" 判定 = get_mode()==1 @0x92a39980。

## 四、真机行为验证（本轮，fastboot 模式，全部无写入）

- `getvar token` ×2（同一次开机）→ `AncBtvmIlaA/**REDACTED**`（相同，**同 boot 内静态**）→ 解码 18B = `027701b6f98895a03fefc111` + `d8a1bb**REDACTED**`
- **重启后** `getvar token` → `PBHSrjPI6ifzER**REDACTED**`（**值改变**）→ 实证 token 每次开机重生成（12B 随机 + 6B 熔丝），**任何捕获的 token 无法跨 boot 重放**
- `oem unlock`（无参或任意非法值）→ `Token verification failed, reboot the device` → 设计行为：handler 调 `reboot(8)`（消息原文即 "reboot the device"），设备重启后自恢复 fastboot、仍锁定、健康 → **此前误判的"USB 掉线崩溃"实为该设计重启，非内存 bug**
- `oem device-info` → Device unlocked: false

## 四·B、解锁验证链完整解码（本轮决定性逆向）

```
oem unlock handler(FUN_92a3abd4):
  c048(arg,len):
    memset(sp+4, 0, 0x80)                       // 128B 输出缓冲
    bd60(len, arg, sp+4)                        // → 64860 RSA_public_decrypt
        // RSA_NO_PADDING（rsa_none.c 字符串 @0x92a64908/4930/49c8）
        // 公钥 DER @0x92a705a0，模数 INTEGER 257B = RSA-2048（不可分解）
    → 失败: "Token Decryptiton Failed"
    strcmp(0x92b8f298 /*当前 token*/, sp+4)     // a5b8 逐字节比较
    → ≠0: "Token Verification Failed"; =0: return 0
  r0==0 (成功): RAM+0x10=1; +0x18=1; memcpy(+0xE4, arg, 0x100); +0xE0=0; 持久化 devinfo
  r0≠0 (失败): print; reboot(8)

AE0C(0x92a3ae0c) 开机 devinfo 装载器（Phase A 死因的完整解释）:
  读 devinfo → magic "ANDROID-BOOT!" → 重验 +0xE4 处 token(c0ec, RSA vs 熔丝)
  → 有效: +0x10=1; 无效/空: 强制 +0x10=0   ← 解锁标志不被存储信任，每次开机按 token 重算
  → 该 flag 才是 DECIDE 决定 mode(1解锁/3锁定) 的唯一输入
```

**结论**：解锁态在密码学上绑定于"devinfo+0xE4 存有对本机熔丝有效的 RSA-2048 签名"。无小米私钥无法伪造；改 devinfo+0x10 无效（下次开机 AE0C 归零）；token 不可重放。**结构性通路彻底闭合，无遗留。**

## 五、余下选项

### A. 官方/付费解锁 —— ❌ 已证死（见第七节，2026-10-17 更新）
- 服务器对老机型**仍在签发** token（Redmi 4X/4A/3S/8、Poco F1 等在 2024–2026 持续成功解锁，老机型常免等待期）。
- **但 Note 2 本机被服务器以 `20039` 拒绝**：`Device basic data verification failed. This device couldn't be unlocked.` 社区多例（Note 2 / Mi 5 / MSM8952 / Redmi 5A），维护者结论 "问题在设备固件本身，非工具"，**无解**。
- 根因 = 本机 aboot 生成的 token **不完整**（18B，缺 codename/cpuid 段）；补齐后服务器可签发，但**本机 aboot 只认自己那份 18B token**，strcmp 必失败 —— 与我方逆向结论完全一致。付费第三方同样无解（无小米私钥 / 无法改签名保护的 aboot）。

### B. aboot 漏洞利用（研究级，数周，不确定）—— 本轮评估后**吸引力下降**
- 原起点"`oem unlock <畸形参数>` 崩溃"经实测证伪：为设计重启(8)，非内存 bug。
- 余下唯一静态可疑点：c048 将 2048-bit(256B) RSA 输出写入 128B 栈缓冲（`sub sp,#0x88`+`memset(sp+4,0,0x80)`）。但 RSA 输入长度须==256 才会执行，24B 短输入直接被拒；发 256B 输入才可能溢出 → 仍受全局栈 canary(0x92b96d34) 保护，需先泄漏 canary。
- 有利面：无 KASLR（全固定地址）、fastboot 攻击面 2016 年代。
- 不利面：全局栈 canary、QC 已修补已知整数溢出；即使 ROP 置 flag 也仅当次会话有效（重启后 AE0C 归零），持久化仍需写入真 token（需私钥）→ 工程闭环极难。
- 结论：**除非用户明确愿意投入数周做 canary 泄漏 + ROP + 持久化研究，否则不推荐。**

### C. 终止（如实接受：该硬件无零成本独立 pmOS 通路）

## 六、资产与恢复（随时可回滚）

- 备份完好：devinfo_restore.bin、boot_current_64mb.bin、keystore_lun0.bin、aboot_current_backup.bin、全量包。
- EDL 管线多次验证；测试机任何实验失败均可恢复。
- donor 仅做过只读操作。

## 七、GitHub 社区证据交叉验证（2026-10-17，决定性）

### 1. `lrh2000/Xiaomi-bootloader`（179★，权威逆向）
- TL;DR 原文：**"It is impossible to bypass Xiaomi's server to unlock the boot loader, unless the boot loader itself contains vulnerabilities."** —— 与本节第二/四·B节结论一致。
- 启动链 PBL→XBL→ABL（即我方 "aboot"）。解锁 = `getvar token` → 服务器 RSA 私钥签名 → 设备用**内嵌公钥**验签。
- 现代机型 token = **36 字节**（含 header、14B 随机、**codename 字符串**、芯片 SN），base64url → 48 字符。

### 2. `MiForge/MiUnlockTool`（offici5l，仍活跃）
- Issue #58「Successful unlocks」：2024–2026 大量老机型成功（santoni/Redmi 4X、Redmi 3S/4A/8、Note 7/8、Poco F1…），老机型常**免 7 天等待期**。
- FAQ：非 HyperOS 的老 MIUI 设备**无需**小米社区权限，仅需开发者选项里绑定账号；`scorpio` 不在免清数据白名单 → 解锁会清 userdata（已获批）。

### 3. 本机（Note 2 / MSM8996_A4）被服务器拒绝 —— 20039
- Issue **#148「Mi Note 2 couldn't be unlocked」**：`product: MSM8996_A4`，`code 20039`。
- Issue **#64 / #33**：Note 2、Redmi 5A 同样 20039；Mi 5(MSM8996) 在 SG/EU 均 20039（中国区 500）。
- 错误码文档 #20039：**"The device token is incomplete — it doesn't contain the full set of required data."** 维护者注：**"only occurs in some older devices"**、**"No confirmed solution at this time."**

### 4. 维护者的关键实验（#162，逐字复现我方逆向）
```
设备返回不完整 token:  deviceToken: 3ztAxu8xgV67edowT68
服务器:               code 20039 (Device basic data verification failed)
补齐:                 deviceToken + cpuid + codename
服务器:               code 0, "Private key signing successful", encryptData = 已签名 token
发回设备:              bootloader 验签通过后，用【它原本返回的那份 token】与新签名里的 token 比较
结果:                 比较失败 → 解锁失败     ← 与我方 c048 strcmp(0x92b8f298, sig) 完全一致
```
维护者结语：`Closing: the issue lies with the device itself, not the tool.`

### 5. 与本次实测数据的吻合
- 本机 `getvar token`（重启后）= `PBHSrjPI6ifzER**REDACTED**` → 解码 **18 字节** = `3c11d2ae33c8ea27f311 17f6` + `d8a1bb**REDACTED**`（末 6B = 本机熔丝 SN）。
- 现代格式为 36 字节且**内嵌 codename**；本机 18B **缺**该段 → 即服务器所述"token incomplete"。
- 两独立 Note 2 token（本机、#148）均 18B、均以 `ea 03` 结尾；`encryptData.md`：RAND 每次开机刷新 → token 即刻过期（与本机实测一致）。

### 结论
**服务器路线（A）对本机（scorpio）在固件层面被证死**：这是本机 aboot token 生成器"不完整"的固件缺陷，非账号/区域/工具问题；补齐段可骗过服务器签发，但本机 aboot 只认自己那份 18B token（strcmp 必失败），而修改 aboot 会被 XBL 拒绝（见死路 #1）。→ **A 与 B 均无零成本通路；维持"终止/如实接受"结论。**
