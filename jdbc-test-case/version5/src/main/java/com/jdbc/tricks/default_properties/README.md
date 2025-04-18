# mysql jdbc 5.1.16 无配置文件读取

MySQL JDBC 5.1.16 版本存在一个特殊的文件读取漏洞利用方式，无需在连接 URL 中添加额外参数即可实现。 \
此版本的关键特性是 allowLoadLocalInfile 参数默认设置为 true，这意味着客户端自动允许本地文件加载操作。然而，默认的 max_allowed_packet 值为 -1，这个负值会导致客户端无法正确处理文件读取包。\
值得注意的是，在 ConnectionImpl 类的实现中有一个重要机制：客户端会在连接建立过程中从服务器获取 max_allowed_packet 值并应用到自身配置中。这是为了确保客户端与服务器使用一致的包大小限制。\
利用这个机制，攻击者可以在模拟 MySQL 服务器回应变量请求时，返回一个适当的 max_allowed_packet 值，从而使客户端能够处理文件读取操作。这种方法的优势在于不需要在 JDBC 连接 URL 中设置该参数，可以有效避开网络流量监控设备的检测。\
当这两个条件（allowLoadLocalInfile 为 true 和适当的 max_allowed_packet 值）同时满足时，就可以成功触发文件读取功能，而无需任何额外的 URL 参数配置。
![](https://p.ipic.vip/vmol7u.png)

附录：bypass_max_allowed_packet.py