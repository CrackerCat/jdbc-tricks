# dump-mysql-properties


## 项目概述
用于分析 MySQL Connector/J 各个版本中的安全相关属性设置。特别关注那些可能导致安全风险的默认配置，如 autoDeserialize 和 allowLoadLocalInfile 属性。

autoDeserialize 设为 true 可能导致反序列化漏洞

allowLoadLocalInfile 设为 true 可能允许恶意SQL查询读取客户端机器上的文件

## 项目结构

```yaml
mysql-security-analysis/
├── dump-mysql.py      # 克隆仓库并提取各版本属性文件
├── extract.py         # 解析属性文件并生成摘要CSV
├── get-tag.py         # 根据安全条件过滤版本
├── mysql_properties/  # 提取的属性文件（运行后生成）
└── mysql_properties_summary.csv  # 生成的分析结果（运行后生成）
```

## 基础使用


要自定义查询条件，编辑 get-tag.py 中的 target_properties 字典：
```yaml
target_properties = {
    "autoDeserialize": "DEFAULT_VALUE_TRUE",
    "allowLoadLocalInfile": "DEFAULT_VALUE_TRUE",
}
```


## 输出示例

```yaml
符合条件的 MySQL 版本及其设置：
======================================================================
版本标签             属性名                      默认值               文件类型
----------------------------------------------------------------------
5.1.38              autoDeserialize            DEFAULT_VALUE_TRUE    ConnectionPropertiesImpl
5.1.39              allowLoadLocalInfile       DEFAULT_VALUE_TRUE    ConnectionPropertiesImpl
...

共找到 X 个符合条件的版本
```