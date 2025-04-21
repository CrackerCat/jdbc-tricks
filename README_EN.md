# jdbc-tricks

## Deep Dive into JDBC Security: Special URL Construction and Non-Networked Deserialization Exploitation Techniques Revealed

![JDBC](https://img.shields.io/badge/JDBC-Security-red)
![MySQL](https://img.shields.io/badge/MySQL-Driver-blue)
![Research](https://img.shields.io/badge/Security-Research-green)

This project summarizes JDBC security research findings, focusing on special URL construction techniques and methods for
non-networked deserialization exploitation.

Presentation PPT attachment:
[Deep Dive into JDBC Security: Special URL Construction and Non-Networked Deserialization Exploitation Techniques Revealed.pptx](深入JDBC安全：特殊URL构造与不出网反序列化利用技术揭秘.pptx)

## Project Structure

```-
jdbc-tricks/
├── LICENSE
├── README.md
├── dump-mysql-properties/ MySQL driver default security property analysis
├── jdbc-test-case/ # JDBC test case collection
```

## 🔍 Tricks List

### MYSQL Driver Tricks

Known tricks:

- default properties: Default property bypass
    - [DefaultProperties.java](jdbc-test-case/mysql-driver/version8/src/main/java/com/jdbc/tricks/default_properties/DefaultProperties.java)
- multi host: Multiple host syntax bypass
    - [Connection URL Syntax](https://dev.mysql.com/doc/connector-j/en/connector-j-reference-jdbc-url-format.html#connector-j-url-user-credentials)
    - [AllowLoadLocal_MultiHostInjectionBypass.java](jdbc-test-case/mysql-driver/version8/src/main/java/com/jdbc/tricks/multi_host/AllowLoadLocal_MultiHostInjectionBypass.java)
- space between: Key-value space insertion bypass
    - [AllowLoadLocal_SpaceBetweenKeyValueBypass.java](jdbc-test-case/mysql-driver/version8/src/main/java/com/jdbc/tricks/space_between/AllowLoadLocal_SpaceBetweenKeyValueBypass.java)
- tab between: Key-value tab character insertion bypass
    - [AllowLoadLocal_TabBetweenKeyValueBypass.java](jdbc-test-case/mysql-driver/version8/src/main/java/com/jdbc/tricks/space_between/AllowLoadLocal_TabBetweenKeyValueBypass.java)
- upper case: Key-value uppercase bypass
    - [AllowLoadLocal_TrueUpperCaseBypass.java](jdbc-test-case/mysql-driver/version8/src/main/java/com/jdbc/tricks/upper_case/AllowLoadLocal_TrueUpperCaseBypass.java)

Conference public content:

- no-outbound: jdbc non-networked exploitation
    - [no-outbound/README.md](jdbc-test-case/mysql-driver/no-outbound/README.md)
- multi-host and equalsIgnoreCase bypass
    - [AllowLoadLocal_MultiHost_equalsIgnoreCase_bypass](jdbc-test-case/mysql-driver/version8/src/main/java/com/jdbc/tricks/multi_host/AllowLoadLocal_MultiHost_equalsIgnoreCase_bypass.java)
    - [equalsIgnoreCase bypass key fuzz case](jdbc-test-case/mysql-driver/version8/src/main/java/com/jdbc/tricks/multi_host/fuzzCase1.java)
- other-between
    - [AllowLoadLocal_OtherBetweenKeyValueBypass.java](jdbc-test-case/mysql-driver/version8/src/main/java/com/jdbc/tricks/space_between/AllowLoadLocal_OtherBetweenKeyValueBypass.java)
    - [Whitespace character fuzz case](jdbc-test-case/mysql-driver/version8/src/main/java/com/jdbc/tricks/space_between/fuzzCase2.java)
- QuoteBypass
    - [QuoteBypass.java](jdbc-test-case/mysql-driver/version5/src/main/java/com/jdbc/tricks/quote_bypass/QuoteBypass.java)

Non-conference public content:

- bypass_max_allowed_packet 5.1.16 version example
    - [Bypassing max_allowed_packet parameter](jdbc-test-case/mysql-driver/version5/src/main/java/com/jdbc/tricks/default_properties/README.md)
    - [DefaultProperties.java](jdbc-test-case/mysql-driver/version5/src/main/java/com/jdbc/tricks/default_properties/DefaultProperties.java)
    - [bypass_max_allowed_packet.py](jdbc-test-case/mysql-driver/version5/src/main/java/com/jdbc/tricks/default_properties/bypass_max_allowed_packet.py)

### Other Driver Tricks

> TODO

## 🔥 Real-World Vulnerability Cases

Case outline:
[real-world-case/README.md](real-world-case/README.md)

- 2025-04-20 L0ne1y contributed case collection
  [real-world-case/2025-04-20-L0ne1y](real-world-case/2025-04-20-L0ne1y)

## 🤝 Contribution Guidelines

Contributions of new JDBC security research findings are welcome! Please follow these steps:

1. Fork this project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yulate/jdbc-tricks&type=Date)](https://www.star-history.com/#yulate/jdbc-tricks&Date)

## 📄 License

This project follows the provisions of the [LICENSE](LICENSE) file in the project root.

---

⚠️ **Disclaimer**: This project is for security research and educational purposes only. Please conduct testing in
legally authorized environments.