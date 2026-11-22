# 实验 1A 网络嗅探器

一个用于学习抓包和网络协议的 Windows 桌面程序，使用 Tkinter 显示报文，通过 Npcap 实时采集。支持 HTTP、TCP、UDP、IPv4、IPv6、ICMP 和 ICMPv6 的筛选及字段查看，也能按端点追踪双向 TCP 流，并按本机 PID 查找实时采集时匹配到的连接。

## 从源码运行

1. 安装带 Tcl/Tk 的 Python 3.10 或更高版本，双击 **启动嗅探器.cmd**。启动时可在界面中分析仓库附带的 34 包回环样例。
2. 要实时抓包，请从 [Npcap 官网](https://npcap.com/#download) 安装驱动，打开程序后点 **刷新接口 → 回环实测**。程序会生成并抓取本机测试流量。
3. 要手动验证，在 **本机回环** 上点 **开始抓包**，双击 **生成本机流量.cmd**，完成后点 **停止**。用 **协议筛选**、**字段解析**、**TCP 流追踪** 和 **进程归属** 查看结果。

## 测试和便携版

运行自动化测试。

~~~powershell
python -B -m unittest discover -s tests -v
~~~

使用 Windows x64 Python 和 Tcl/Tk 构建便携版。

~~~powershell
python -m pip install pyinstaller==6.22.3
python build_windows.py
~~~

构建完成后在 `发布` 文件夹中找到 ZIP。常见运行问题见 [Windows 使用说明](Windows使用说明.txt)。

## 许可证

项目源代码采用 [MIT 许可证](LICENSE)。
