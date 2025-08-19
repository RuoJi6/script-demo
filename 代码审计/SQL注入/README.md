# SQL注入检测工具 (sql_injection_checker.py)

## 💉 工具概述

`sql_injection_checker.py` 是一个专门用于检测PHP代码中SQL注入漏洞的安全审计工具。它能够识别使用了SQL语句但没有使用 `pe_dbhold()` 过滤函数的文件，帮助发现潜在的SQL注入安全风险。

## 🎯 主要功能

### 1. SQL函数检测
检测各种数据库操作函数：

#### MySQL相关函数
```php
'mysql_query', 'mysqli_query', 'mysql_real_escape_string'
'mysqli_prepare', 'mysql_prepare'
```

#### 其他数据库函数
```php
'pg_query'      // PostgreSQL
'sqlite_query'  // SQLite  
'mssql_query'   // SQL Server
```

#### PDO相关函数
```php
'PDO::query', 'PDO::prepare', 'PDO::exec'
```

#### 自定义数据库函数
```php
'db_query', 'db_select', 'db_insert', 'db_update', 'db_delete'
```

### 2. SQL语句模式检测
使用正则表达式检测SQL语句关键词：

```sql
-- 基本SQL操作
SELECT ... FROM ...
INSERT INTO ...
UPDATE ... SET ...
DELETE FROM ...

-- DDL操作
CREATE TABLE ...
DROP TABLE ...
ALTER TABLE ...

-- 字符串中的SQL语句
"SELECT * FROM users WHERE id = $id"
'INSERT INTO logs VALUES (...)'
```

### 3. 危险变量拼接检测
识别直接将用户输入拼接到SQL语句的危险模式：

```php
// 变量拼接模式
$var . "SELECT ..."
"SELECT ..." . $variable
$_GET['id'] . "SELECT ..."

// 超全局变量直接拼接
$_GET['param'] . "INSERT INTO ..."
$_POST['data'] . "UPDATE ..."
$_REQUEST['input'] . "DELETE FROM ..."
```

### 4. 过滤函数验证
检查是否使用了安全的过滤函数：
- `pe_dbhold()` - 项目特定的数据库转义函数

## 🚀 使用方法

### 基本使用
```bash
python sql_injection_checker.py
```

### 交互式操作
1. 输入要检测的目录路径
2. 选择输出文件名（可选）
3. 等待扫描完成

### 示例
```bash
$ python sql_injection_checker.py
SQL注入漏洞检测工具
========================================
检测目标：使用SQL语句但未使用 pe_dbhold() 过滤函数的文件

请输入要检测的目录路径: /var/www/html/project
输出文件名 (默认: sql_injection_report.txt): 
开始扫描目录: /var/www/html/project
正在检测SQL注入漏洞...
🚨 高风险: /var/www/html/project/admin/user.php
⚠️  中风险: /var/www/html/project/api/search.php
```

## 📊 风险等级分类

### 高风险 🚨
- **条件**：有SQL语句 + 无过滤函数 + 有危险变量拼接
- **特征**：用户输入直接拼接到SQL语句中
- **示例**：
```php
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysql_query($sql);
```

### 中风险 ⚠️
- **条件1**：有SQL语句 + 无过滤函数 + 无危险拼接
- **条件2**：有过滤函数但仍有危险拼接
- **示例**：
```php
// 情况1：静态SQL但无过滤
$sql = "SELECT * FROM users WHERE status = 1";
mysql_query($sql);

// 情况2：有过滤但仍有风险
$id = pe_dbhold($_GET['id']);
$sql = "SELECT * FROM users WHERE name = '" . $_POST['name'] . "'";
```

### 低风险 ⚡
- **条件**：有SQL语句 + 有过滤函数 + 无危险拼接
- **示例**：
```php
$id = pe_dbhold($_GET['id']);
$sql = "SELECT * FROM users WHERE id = " . $id;
mysql_query($sql);
```

## 📋 输出报告

### 报告内容
生成的 `sql_injection_report.txt` 包含：

1. **统计信息**
   - 扫描目录和文件数量
   - 各风险等级的文件统计
   - 检测到的漏洞总数

2. **详细漏洞信息**
   - 文件路径和风险等级
   - 使用的SQL函数列表
   - 发现的SQL语句（带行号）
   - 危险的变量拼接（带行号）
   - 是否使用过滤函数

### 报告示例
```
SQL注入漏洞检测报告
============================================================
扫描目录: /var/www/html/project
总计PHP文件数: 156
存在SQL注入风险的文件数: 12
高风险文件数: 5
中风险文件数: 7
============================================================

检测到的SQL注入漏洞:
----------------------------------------

文件: /var/www/html/project/admin/user.php
风险等级: 高风险
使用的SQL函数: mysql_query, mysqli_query
发现的SQL语句:
  行 25: $sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
  行 30: mysql_query($sql);
危险的变量拼接:
  行 25: $sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
是否使用过滤函数 pe_dbhold: 否
----------------------------------------
```

## 🔧 检测原理

### 1. 文件扫描
- 递归遍历指定目录
- 只检查PHP相关文件（.php, .phtml, .php3, .php4, .php5）
- 逐行分析代码内容

### 2. SQL语句识别
```python
# SQL语句正则模式
SQL_PATTERNS = [
    r'\bSELECT\s+.*\s+FROM\s+',
    r'\bINSERT\s+INTO\s+',
    r'\bUPDATE\s+.*\s+SET\s+',
    r'\bDELETE\s+FROM\s+',
    # 字符串中的SQL
    r'["\']SELECT\s+.*\s+FROM\s+.*["\']',
]
```

### 3. 危险拼接检测
```python
# 危险拼接模式
DANGEROUS_PATTERNS = [
    r'\$\w+\s*\.\s*["\']SELECT\s+',
    r'["\']SELECT\s+.*["\']?\s*\.\s*\$\w+',
    r'\$_GET\[.*\].*["\']SELECT\s+',
    r'\$_POST\[.*\].*["\']SELECT\s+',
]
```

### 4. 过滤函数检测
检查代码中是否包含 `pe_dbhold` 函数调用。

## ⚙️ 配置选项

### 自定义SQL函数
在 `SQL_FUNCTIONS` 列表中添加项目特定的数据库函数：
```python
SQL_FUNCTIONS = [
    'mysql_query', 'mysqli_query',
    'custom_db_query',    # 添加自定义函数
    'project_db_select',  # 项目特定函数
]
```

### 自定义过滤函数
修改 `FILTER_FUNCTION` 变量：
```python
FILTER_FUNCTION = 'your_escape_function'  # 替换为项目使用的过滤函数
```

### 添加危险模式
在 `DANGEROUS_PATTERNS` 中添加新的危险拼接模式：
```python
DANGEROUS_PATTERNS.append(r'your_custom_dangerous_pattern')
```

## 🛡️ 修复建议

### 1. 使用预处理语句（推荐）
```php
// PDO预处理
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);

// MySQLi预处理
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
```

### 2. 使用过滤函数
```php
// 使用项目的过滤函数
$safe_id = pe_dbhold($_GET['id']);
$sql = "SELECT * FROM users WHERE id = " . $safe_id;

// 类型转换
$safe_id = intval($_GET['id']);
$sql = "SELECT * FROM users WHERE id = " . $safe_id;
```

### 3. 输入验证
```php
// 白名单验证
$allowed_fields = ['id', 'name', 'email'];
if (!in_array($_GET['field'], $allowed_fields)) {
    die('Invalid field');
}

// 正则验证
if (!preg_match('/^[0-9]+$/', $_GET['id'])) {
    die('Invalid ID format');
}
```

## ⚠️ 注意事项

1. **误报可能**：某些动态SQL可能被误判为危险
2. **人工验证**：建议对检测结果进行人工确认
3. **测试环境**：先在测试环境中验证修复效果
4. **备份代码**：修复前请备份原始代码

## 🔄 最佳实践

1. **定期检测**：集成到代码审查流程中
2. **配合其他工具**：结合SQLMap等工具进行深入测试
3. **开发规范**：建立安全编码规范，禁止直接拼接SQL
4. **培训开发人员**：提高团队的安全意识

这个工具能够快速识别项目中的SQL注入风险点，是代码安全审计的重要组成部分！
