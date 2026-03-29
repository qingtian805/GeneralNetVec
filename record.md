Linux 上，抓包程序需要权限才能访问 socket，有两种解决方法：
1. 用 root 权限运行，但这样会让 Python 生成所有者为 root 的 \_\_pycache__
2. 赋予 cap_net_raw 权限(见https://wiki.archlinux.org/title/Capabilities)，这样又会有两种方案：
    * 赋予 Python 解释器
        - 如果使用 conda 环境，直接赋予环境中 Python 即可
        - 如果使用 venv 环境，则需要要么直接赋予系统 Python 权限，或创建一个单独的解释器
    * 赋予单个脚本，shebang：`#!/path/to/python`