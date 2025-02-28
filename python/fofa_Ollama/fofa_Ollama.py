"""
FOFA 查询与导出工具

描述:
    本脚本用于通过 FOFA API 查询指定语法（如 `app="Ollama"`）的结果，并导出符合条件的链接。
    支持自定义查询语句和导出条数，同时会检查每个链接是否为有效的 Ollama 服务，并将结果保存到本地文件。

功能:
    1. 通过 FOFA API 查询指定语法的结果。
    2. 检查查询结果中的链接是否为有效的 Ollama 服务。
    3. 将有效的 Ollama 服务链接及其模型信息保存到本地文件。
    4. 支持自定义查询语句和导出条数。

使用示例:
    python3 fofa_Ollama.py -q  -n 100
    python3 fofa_Ollama.py --query  --number 500

参数:
    -q, --query    FOFA 查询语句（默认：'app="Ollama"'）
    -n, --number   导出条数（默认：500）

作者: ruoji
时间: 2025-02-28
Github:https://github.com/RuoJi6
版本: 1.0
"""
import base64
from datetime import datetime
import requests
import argparse
import os


fofa_key = "" # fofa_key 需要配置这个key!!!!!!!!!!!!!!!!!!!!!!!!!


class Colorpr:
    @staticmethod
    def color_red(test):
        return f"\033[1;31m{test}\033[0m"

    @staticmethod
    def color_red_bd(test):
        return f"[\033[1;31m+\033[0m] {test}"

    @staticmethod
    def color_blue_bd(test):
        return f"[\033[34m-\033[0m] {test}"

    @staticmethod
    def color_blue(test):
        return f"\033[34m{test}\033[0m"

    @staticmethod
    def color_yellow(test):
        return f"\033[33m{test}\033[0m"

    @staticmethod
    def color_purple(test):
        return f"\033[35m{test}\033[0m"

def formatted_time():
    """
    功能描述: 返回系统当前时间 time:2024-12-07 19:15:31
    参数:
    返回值:
    异常描述:
    调用演示:
        time_data = self.formatted_time()
    """
    # 获取当前时间
    now = datetime.now()
    # 定义时间格式
    time_format = "%Y-%m-%d %H:%M:%S"
    # 按照定义的格式对当前时间进行格式化
    return str(now.strftime(time_format)).replace('http://', '').replace('https://', '').replace('/', '').replace('.', '_').replace(':','_').replace('-', '_').replace(' ', '_')

def get_base64(value_b64encode=None, value_b64decode=None):
    """
    功能描述: 加密解密base64
    参数:
        value_b64encode : 加密
        value_b64decode : 解密
    返回值:
    异常描述:
    调用演示:
        fofa = self.get_config('fofa')
    """
    if value_b64encode is not None:
        # 进行Base64编码
        return base64.b64encode(value_b64encode.encode('utf-8')).decode('utf-8')
    elif value_b64decode is not None:
        # 进行Base64解密
        return base64.b64decode(value_b64decode).decode('utf-8')


def fofa_query(query,number):
    number = int(number)
    value_list = 0
    data_list = []
    fofa_user_info = requests.get(f'https://fofa.info/api/v1/info/my?key={fofa_key}')
    if fofa_user_info.json()['error'] is not True:
        i = 1
        while True:
            qbase64 = get_base64(query)
            data = requests.get(
                f"https://fofa.info/api/v1/search/all?&key={fofa_key}&qbase64={qbase64}&fields=link&page={i}&size={number}")

            if data.json()['error'] is not True:
                i = i + 1
                value_list = value_list + len(data.json()['results'])
                data_list.extend(data.json()['results'])
            else:
                print(f"[{Colorpr.color_blue('-')}]FOFA ERROR:" + data.json()["errmsg"])
                break
            print(f"[{Colorpr.color_red('+')}]导出fofa条数:{value_list}")
            if value_list >= number:
                break
        return data_list
    else:
        print(f"[{Colorpr.color_blue('-')}]FOFA ERROR:" + fofa_user_info.json()["errmsg"])
        if fofa_user_info.json()["errmsg"] == '[-700] 账号无效':
            print(f"[{Colorpr.color_blue('-')}]配置FOFA KEY")
        exit(0)


def fofa_check(fofa_data):
    file_time_name = formatted_time()+".txt"
    for url in fofa_data:
        try:
            fofa_url_data = requests.get(url=url + "/api/tags", timeout=30, verify=False)
            fofa_url_data_json = fofa_url_data.json()
            if len(fofa_url_data_json['models']):
                print(f"[{Colorpr.color_red('+')}]Ollama: "+ url + " 模型数量：" +str(len(fofa_url_data_json['models'])))
                with open(file_time_name, "a") as fOllama:
                    fOllama.write(url + '\n')
                    for models in fofa_url_data_json['models']:
                        fOllama.write(str(models)+ '\n')
                    fOllama.write("---------------------------------------\n\n")
        except Exception as e:
            print(f"[{Colorpr.color_blue('-')}]不存在:" + str(e))
    if os.path.exists(file_time_name): print(f"[{Colorpr.color_red('+')}]保存为：{file_time_name}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="FOFA导出")
    parser.add_argument(
        "-q",
        "--query",
        default='app="Ollama"',
        help="FOFA查询Ollama",
    )
    parser.add_argument(
        "-n",
        "--number",
        default=500,
        help="导出条数[默认500]",
    )

    # 解析命令行参数
    args = parser.parse_args()
    if args.query:
        if os.path.exists("fofa_link.txt"):
            os.remove("fofa_link.txt")
        print(f"[{Colorpr.color_red('+')}]语法:"+args.query)
        print(f"[{Colorpr.color_red('+')}]条数:" + str(args.number))
        fofa_data_list = fofa_query(args.query,args.number)
        fofa_check(fofa_data_list)
