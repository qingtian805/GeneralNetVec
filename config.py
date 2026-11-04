import json
import os
from net_vec import cfg as netvec_cfg

_dump_paramters = {"indent": 4}

class Config:
    def _read_config(self, config_path: str):
        """从指定为是读取设置并应用"""
        if not os.path.exists(config_path):
            print("Config: config file not exists, writing a template...")
            self._template(config_path)
            return

        with open(config_path, "r") as f:
            config: dict = json.load(f)

        for key in config.keys():
            self.__dict__[key] = config[key]

    def _template(self, config_path: str):
        """在目标位置写入一个模板文件

        相当于直接使用所有下层模块的默认设置
        """
        self.vec_cfg = netvec_cfg.get_paramters()

        with open(config_path, "w") as f:
            json.dump(self.__dict__, f, **_dump_paramters)

    def __init__(
            self,
            config_path: str = "config.json"):
        """全局设置类
        从指定文件中读取设置，并在底层模块的应用这些设置

        :param config_path: 目标设置文件
        """

        self.vec_cfg: dict = None

        self._read_config(config_path)
