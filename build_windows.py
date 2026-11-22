"""在含 Tk 的 Windows x64 Python 3.10+ 环境安装 pyinstaller==6.22.3 后运行。"""

from pathlib import Path
import subprocess
import sys
import sysconfig
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile


def main():
    if sys.version_info < (3, 10) or sysconfig.get_platform() != "win-amd64":
        raise SystemExit("请使用 Windows x64 Python 3.10 或更高版本构建。")
    import tkinter  # PyInstaller 需要构建用 Python 自带 Tcl/Tk。

    root = Path(__file__).resolve().parent
    output = root / "发布"
    output.mkdir(exist_ok=True)
    archive_name = "实验1A-Windows-x64.zip"
    exe_name = "实验1A嗅探器"
    with TemporaryDirectory(prefix="build-", dir=output) as temporary:
        work = Path(temporary)
        subprocess.run([
            sys.executable, "-m", "PyInstaller", "--onefile", "--windowed", "--noupx",
            "--name", exe_name, "--distpath", str(work / "dist"),
            "--workpath", str(work / "work"), "--specpath", str(work),
            "--add-data", f"{root / '验收样例' / '本机回环.pcap'}:验收样例",
            str(root / "src" / "gui.py"),
        ], cwd=root, check=True)
        archive = work / archive_name
        with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
            bundle.write(work / "dist" / f"{exe_name}.exe", f"{exe_name}.exe")
            bundle.write(root / "Windows使用说明.txt", "Windows使用说明.txt")
            # python.org Windows 安装包的完整许可也涵盖 Tcl、Tk 和 OpenSSL。
            bundle.write(Path(sys.base_prefix) / "LICENSE.txt", "许可/Python及随附组件.txt")
        archive.replace(output / archive_name)
    print(output / archive_name)


if __name__ == "__main__":
    main()
