# jdbc-tricks
《深入JDBC安全：特殊URL构造与不出网反序列化利用技术揭秘》对应研究总结项目

## 0x01 项目结构
```-
jdbc-tricks/
├── LICENSE
├── README.md
├── dump-mysql-properties mysql驱动默认安全属性分析
├── jdbc-test-case jdbc测试集
```

## 0x02 Trick 列表
会议前暂时只公布一部分已知trick

### MYSQL Tricks
- default properties ：默认属性绕过
- multi host ：多host写法绕过
- space between ：键值插入空格绕过
- tab between  ：键值插入 \t 等制表符绕过
- upper case ：键值大写绕过

todo

### PG


## 0x03 真实世界漏洞案例

会议前暂不公开


