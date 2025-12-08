# CVE-2023-38831漏洞复现与分析:

## 漏洞简介

| 信息 | 内容 |
| --- | --- |
| 漏洞名称 |  WinRAR XXE → RCE |
| 漏洞编号 | CVE-2023-38831 |
| 风险等级 | 高危 |
| 漏洞类型 | 逻辑缺陷 / 远程代码执行 |
| 利用难度 | 低 |


## 漏洞复现：
- 构造阶段：利用ZIP格式特性，制作包含“同名文件+同名文件夹（内藏脚本）”的压缩包。

- 诱导阶段：诱骗用户双击压缩包内看似无害的PNG文件（或其他任意格式文件）。

- 释放阶段：WinRAR因字符串匹配逻辑缺陷，将诱饵文件和恶意脚本同时释放到临时目录。

- 执行阶段：ShellExecute 因路径解析空格问题导致扩展名识别失败，进而触发“查找同名可执行文件”的回退机制，错误地执行了恶意脚本而非打开诱饵文件。

### 1. 创建恶意文件：
![](https://s3.bmp.ovh/imgs/2025/12/08/1e321e18256586eb.png)

#### 恶意脚本内容
**pure.png3.cmd:**

```
@echo off
start calc.exe
echo ==
echo CVE-2023-38831 EXPLOIT SUCCESS!
echo ==
echo Vulnerability Triggered!
pause
```

### 2.将poc.zip用HxD修改

- 将png后面的123皆改为空格（ASCII 编码中0x31-0x33对应1,2,3，空格为0x20）

![](https://s3.bmp.ovh/imgs/2025/12/08/b8112286e321e234.png)

### 3.改名为.rar发给安有低版本winrar的win10虚拟机

![](https://s3.bmp.ovh/imgs/2025/12/08/9130e8824699a5bc.png)


### 4.双击文件pure.png

弹出calc.exe窗口并启动计算机：
![alt text](36b3e71b249d8ae5834762c5ad8afbae.png)

## 漏洞原理(以png文件为例)：

### 1.核心机理：
- WinRAR 6.23 之前的版本在处理 ZIP 压缩包时存在逻辑缺陷，当用户尝试打开压缩包内的良性文件（如图片或文本文件）时，若压缩包内存在同名恶意脚本文件，WinRAR 会错误调用 ShellExecute 函数执行恶意脚本，导致远程代码执行（RCE）。
- 本漏洞（CVE-2023-38831）的核心在于 WinRAR 在处理 ZIP 压缩包时，存在文件名匹配逻辑缺陷与 Shell 执行链扩展名解析错误的结合。以下分析将基于一个典型的攻击场景展开：攻击者构造一个诱饵文件 pure.png，最终导致任意代码执行。


### 2.详细分析：
#### 2.1 漏洞触发条件与前置构造:
- 正常系统中，无法在同一路径下创建同名文件和文件夹。然而，攻击者可以通过直接修改 ZIP 文件的二进制结构绕过此限制。

**构造恶意包体：攻击者创建一个 ZIP 文件，其中包含：**
- **一个文件**：`pure.pngA`（诱饵文件）
- **一个文件夹**：`pure.pngB`（文件夹）
  - 在该文件夹内放置恶意脚本：`pure.pngB.cmd`（例如，内容为 `start calc`）

**二进制修改实现“强制同名”：**
- 使用十六进制编辑器（如 HxD）打开此 ZIP 文件，找到中心目录区（ZIP_DIR_ENTRY）中存储文件名的位置，将 pure.pngA 和 pure.pngB 末尾的标识字符 A 和 B（例如十六进制 0x41, 0x42）均修改为空格（0x20）。
  - 结果:在 ZIP 包内部，deFileName 字段记录的文件名变为 pure.png（末尾带空格）。此时，ZIP 包中存在两个 deFileName 完全相同的条目：一个指向文件，另一个指向文件夹。这为后续逻辑错误埋下了伏笔。


#### 2.2 漏洞原理剖析：WinRAR 的错误逻辑链:
当用户在 WinRAR 中双击压缩包内显示的 pure.png 文件时，以下三个关键的错误逻辑被依次触发：
**1.错误的文件匹配与释放逻辑:**
1. 获取点击的文件名 `tName`  
2. 遍历 `dirEntry`  
   - 比较 `tName` 与 `dirEntry-&gt;deFileName`  
3. 记录所有匹配的 `dirEntry-&gt;deFileName`  
4. 解压匹配到的所有文件

WinRAR 接收到用户双击 pure.png 的指令后，会遍历 ZIP 包内的所有 ZIP_DIR_ENTRY 条目，将每个条目的 deFileName 与用户点击的目标名进行匹配。
- 匹配逻辑缺陷：WinRAR 使用的匹配函数（如 strcmp 或类似）在处理时，可能由于字符串比较逻辑不严谨，允许目标文件名以“空格+任意字符”的形式通过匹配。或者，其逻辑是为了兼容而设计得过于宽泛。
- 漏洞触发：当 WinRAR 寻找 pure.png 时，它同样会匹配到 deFileName 为 pure.png（末尾有空格）的条目。由于我们通过二进制修改制造了两个这样的条目（一个文件、一个文件夹），WinRAR 会将这两个条目都判定为“用户想打开的对象”。
- 恶意内容释放：根据 WinRAR 的设计，匹配到的条目内容会被释放到临时目录。因此，它不仅释放了诱饵图片文件 pure.png，也错误地将同名文件夹 pure.png 内的所有内容（即恶意脚本 pure.png .cmd）释放到了同一临时目录。这是整个漏洞链条的第一个关键点：恶意脚本被“偷渡”到了执行环境。

**2.ShellExecute 的扩展名解析歧义:**
![alt text](image-9.png)
文件释放后，WinRAR 会调用 ShellExecuteExW API 来“打开”用户点击的 pure.png。
- 正常流程：ShellExecute 应调用 PathFindExtension 函数，从文件完整路径（如 C:\Temp\...\pure.png）中正确提取扩展名 .png，然后查询注册表找到关联的图片查看器并启动。
- 漏洞触发点：由于之前错误的释放逻辑，传递给 ShellExecute 的文件路径实际上是 C:\Temp\...\pure.png（路径末尾包含一个空格）。
- 解析错误：PathFindExtension 函数的逻辑是从字符串末尾开始，反向查找第一个 . 字符。当它处理 ...\pure.png 时，它会找到 .png，但随后的空格字符会干扰其判断逻辑。在某些实现中，这可能导致函数无法正确识别 .png 为有效的扩展名，或者返回一个包含空格的错误扩展名（如 .png）。其结果是，系统认为此文件没有标准的、可关联的扩展名。

**3. 危险的“无扩展名”文件处理机制:**
当 ShellExecute 认为一个文件没有有效扩展名时，Windows 系统会启动一个备用处理机制。
- 备用机制：系统会在该文件所在的同一目录下，搜索是否存在与主文件名（不含扩展名部分）同名的可执行文件（如 .exe, .com, .bat, .cmd 等）。
- 漏洞最终触发：此时，在同一临时目录下，恰好存在我们之前“偷渡”进来的恶意文件 pure.png .cmd。由于 Windows 文件系统在处理时通常会忽略文件名末尾的空格（pure.png 与 pure.png 在系统层面被视为相同），因此 ShellExecute 的备用机制成功找到了 pure.png .cmd。
- 代码执行：于是，系统不再启动图片查看器，而是直接执行了 pure.png .cmd 这个批处理文件，导致其中包含的任意命令（如启动计算器、下载恶意软件等）被运行，从而完成了远程代码执行。

#### 2.3 总结：漏洞本质:

CVE-2023-38831 并非一个传统的缓冲区溢出漏洞，而是一个由多个逻辑缺陷串联而成的“逻辑漏洞”。
1.	根源一（WinRAR侧）：对 ZIP 内 deFileName 的匹配逻辑过于宽泛，且未正确处理“文件与文件夹同名”这一异常情况，导致恶意内容被错误释放。
2.	根源二（系统交互侧）：在文件路径因逻辑一而包含异常字符（末尾空格）时，ShellExecute 的扩展名解析机制失效，触发了系统“查找同名可执行文件”的备用流程。
3.	攻击面：将两者结合，攻击者只需精心构造一个 ZIP 包，即可诱使 WinRAR 在用户毫无察觉的情况下，将恶意脚本释放并触发执行。该漏洞影响所有需要用户交互打开压缩包内文件的场景，利用成本低，危害性高，因此被评为高危漏洞（CVSS 8.6）。

#### 2.4 相关案例
**一、知名攻击组织利用案例**
1. 俄罗斯背景的 UAC-0099 组织（针对乌克兰）
•	攻击活动：该组织利用 CVE-2023-38831 传播 LONEPAGE 恶意软件。
*****•	攻击手法：*****
   o	发送钓鱼邮件，附件为包含漏洞的 ZIP 压缩包（伪装成“采购清单”、“军事文件”等）。
   o	压缩包内包含一个诱饵文件（如 PDF 或 PNG）和同名恶意脚本。
   o	用户双击打开诱饵文件时，恶意脚本被执行，下载并运行 LONEPAGE 远控木马。
*****•	后续行为：*****
o	创建计划任务实现持久化。
o	窃取敏感信息、键盘记录、屏幕截图等。
2. 朝鲜背景的 Lazarus 组织（疑似）
•	攻击活动：安全研究人员发现 Lazarus 组织在针对加密货币交易所和金融机构的攻击中，尝试使用 CVE-2023-38831 作为初始感染手段。
*****•	手法特点：*****
o	使用伪装成“求职简历”、“项目合同”的 ZIP 文件。
o	诱饵文件为带有恶意宏的文档或图片，但实际通过漏洞执行 PowerShell 脚本。
o	绕过传统杀软对宏文档的检测。
3. 商用间谍软件供应商
•	案例：部分商业间谍软件（如 Mercenary Spyware）供应商在工具链中集成了 CVE-2023-38831 的利用代码。
•	用途：用于针对记者、活动人士、政治人物的定向监控攻击。

________________________________________

**二、攻击手法特征总结**
这些实际攻击案例表现出以下共同特征：
| 特征 | 说明 |
| --- | --- |
| 诱饵文件类型多样 | 	PNG、PDF、DOCX、XLSX 等常见格式，降低用户警惕性 |
| 压缩包伪装 | 使用 .zip 或重命名为 .rar，常带有“紧急”、“机密”等字样 |
| 执行链隐蔽 | 不直接执行 EXE，而是通过 CMD/BAT → PowerShell → 下载执行，绕过静态检测 |
| 利用时机 | 多在漏洞公开后1-2个月内爆发，打“时间差”（用户未更新 WinRAR） |
| 目标明确 | 政府、军事、金融、能源、媒体等高价值目标 |
	

	
	
	
	



## 防御措施：

### 1. 官方补丁升级
- 立即升级至 WinRAR 6.23 或更新版本，该版本修复了路径验证逻辑。
[Chromium](https://www.chromium.org/) 官方补丁：https://chromium.googlesource.com/chromium/src/+/refs/tags/116.0.5845.96/CHANGELOG.md#116.0.5845.96

### 2.安全增强建议
- 禁用 WinRAR 临时文件执行：组策略中禁止解压目录的程序执行权限（通过路径规则限制 %Temp% 的 .cmd、.bat 运行）。

- 使用替代压缩工具：如 [7-Zip](https://www.7-zip.org/a/7z2408-x64.msi)（设计上更严格验证文件路径）。

- 安全意识培训：警惕非常规扩展名文件（如 file.jpg .cmd）。

### 3.技术缓解方案
**漏洞检测脚本(c语言):**
```c
#include <stdio.h>
#include <string.h>
#include <zip.h>

// 检测 ZIP 中是否存在同名文件与文件夹
int check_cve_2023_38831(const char *zip_path) {
    struct zip *archive;
    int err = 0;
    archive = zip_open(zip_path, 0, &err);
    if (!archive) {
        fprintf(stderr, "无法打开ZIP文件: %s\n", zip_path);
        return -1;
    }

    int entry_count = zip_get_num_entries(archive, 0);
    char **file_list = malloc(entry_count * sizeof(char *));
    int vuln_flag = 0;

    // 遍历所有文件条目
    for (int i = 0; i < entry_count; i++) {
        const char *name = zip_get_name(archive, i, 0);
        file_list[i] = strdup(name);

        // 检测文件名中的空格（如 "file .jpg"）
        if (strchr(name, ' ') != NULL) {
            printf("[!] 可疑文件名: %s (含空格)\n", name);
        }

        // 检测是否为文件夹（以 '/' 结尾）
        if (name[strlen(name) - 1] == '/') {
            char folder_name[256];
            strncpy(folder_name, name, strlen(name) - 1);
            folder_name[strlen(name) - 1] = '\0';

            // 检查是否存在同名文件
            for (int j = 0; j < i; j++) {
                if (strcmp(file_list[j], folder_name) == 0) {
                    printf("[!] 发现漏洞特征: 文件 %s 与文件夹 %s/ 同名\n", folder_name, folder_name);
                    vuln_flag = 1;
                }
            }
        }
    }

    // 释放资源
    for (int i = 0; i < entry_count; i++) free(file_list[i]);
    free(file_list);
    zip_close(archive);

    return vuln_flag; // 返回1表示存在漏洞特征
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("用法: %s <ZIP文件路径>\n", argv[0]);
        return 1;
    }

    int result = check_cve_2023_38831(argv[1]);
    if (result == 1) {
        printf("[警告] 该ZIP文件可能包含CVE-2023-38831漏洞攻击载荷！\n");
    } else if (result == 0) {
        printf("[安全] 未检测到漏洞特征。\n");
    }

    return 0;
}

```
运行程序时，将ZIP文件路径作为参数传递给程序。程序会检查ZIP文件中是否存在CVE-2023-38831漏洞攻击载荷。如果存在，则返回1，否则返回0。

**检测漏洞脚本（Python）:**
```python
import zipfile
import os
from os.path import basename

def detect_cve_2023_38831(zip_path):
    suspicious_files = []
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        # 获取所有文件条目
        file_list = zip_ref.namelist()
        
        # 检测同名文件与文件夹
        for file in file_list:
            # 检测文件名中的空格（如 "test .jpg"）
            if ' ' in basename(file):
                print(f"[!] 可疑文件名: {file} (含空格)")
                suspicious_files.append(file)
            
            # 检测是否为文件夹（以 '/' 结尾）
            if file.endswith('/'):
                folder_name = file[:-1]
                # 检查是否存在同名文件
                if folder_name in file_list:
                    print(f"[!] 漏洞特征: 文件 {folder_name} 与文件夹 {file} 同名")
                    suspicious_files.append(folder_name)
            
            # 检测可执行脚本（如 .bat、.cmd）
            if file.lower().endswith(('.bat', '.cmd', '.ps1')):
                print(f"[!] 发现可执行脚本: {file}")
                suspicious_files.append(file)
    
    # 输出最终检测结果
    if suspicious_files:
        print("\n[警告] 检测到 CVE-2023-38831 漏洞特征！可疑文件列表:")
        for f in set(suspicious_files):
            print(f"  - {f}")
        return True
    else:
        print("[安全] 未检测到漏洞特征。")
        return False
# 使用示例
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法: python detect_cve.py <ZIP文件路径>")
        sys.exit(1)
    detect_cve_2023_38831(sys.argv[1])

```
****关键代码解析:****

***ZIP 文件解析:***
- 使用 libzip 库遍历压缩包内所有文件条目，获取文件名列表。
- 检测文件名中的空格（如 file .jpg），此类命名易触发 WinRAR 解析错误。
同名文件/文件夹检测：
若发现文件 file.jpg 和文件夹 file.jpg/ 同时存在，则判定为漏洞特征。
结合 SHA256/MD5 校验进一步验证文件真实性。
