import os
import re
import csv


def extract_property_definitions(file_path, file_type):
    """从属性定义文件中提取属性名、默认值和其他信息"""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        content = file.read()

    properties = []

    if file_type == "PropertyDefinitions":
        # 适用于新版本的模式
        pattern = re.compile(
            r"new\s+(?:Boolean|Integer|String)PropertyDefinition\(\s*"
            r"PropertyKey\.(\w+),\s*"  # 提取属性名
            r"([^,]+),\s*"  # 提取默认值
            r"(\w+),\s*"  # 提取运行时修改性
            r".*?\)",  # 忽略剩余部分
            re.DOTALL
        )

        for match in pattern.findall(content):
            property_name = match[0]
            default_value = match[1].strip()
            runtime_modifiable = match[2].strip()
            properties.append({
                "PropertyName": property_name,
                "DefaultValue": default_value,
                "RuntimeModifiable": runtime_modifiable,
                "FileType": file_type
            })

    elif file_type == "ConnectionPropertiesImpl":
        # 适用于MySQL 5的模式
        pattern = re.compile(
            r"private\s+(?:Boolean|Integer|String)ConnectionProperty\s+(\w+)\s*=\s*new\s+(?:Boolean|Integer|String)ConnectionProperty\(\s*"
            r'"([^"]+)",\s*'  # 属性名（字符串）
            r"(?:/\$NON-NLS-1\$\s*)?"
            r"(true|false|[0-9]+|\"[^\"]*\"),\s*"  # 默认值
            r".*?"  # 忽略中间部分
            r"\);",  # 结束
            re.DOTALL
        )

        for match in pattern.findall(content):
            variable_name = match[0]
            property_name = match[1]
            # 处理默认值（转换为标准格式）
            default_value = match[2].lower()
            if default_value == "true":
                default_value = "DEFAULT_VALUE_TRUE"
            elif default_value == "false":
                default_value = "DEFAULT_VALUE_FALSE"
            elif default_value.isdigit():
                default_value = f"DEFAULT_VALUE_{default_value}"
            else:
                default_value = f"DEFAULT_VALUE_{default_value}"

            properties.append({
                "PropertyName": property_name,
                "DefaultValue": default_value,
                "RuntimeModifiable": "UNKNOWN",  # MySQL 5没有显式指定运行时可修改性
                "FileType": file_type
            })

    return properties


def process_all_files(input_dir, output_file):
    """处理所有属性定义文件并保存结果"""
    with open(output_file, "w", encoding="utf-8", newline='') as outfile:
        fieldnames = ["Tag", "PropertyName", "DefaultValue", "RuntimeModifiable", "FileType"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        # 遍历所有版本标签目录
        for tag in os.listdir(input_dir):
            tag_dir = os.path.join(input_dir, tag)
            if not os.path.isdir(tag_dir):
                continue

            # 检查该目录中的属性文件
            for file_type in ["PropertyDefinitions", "ConnectionPropertiesImpl"]:
                file_path = os.path.join(tag_dir, f"{file_type}.java")
                if os.path.exists(file_path):
                    try:
                        properties = extract_property_definitions(file_path, file_type)
                        for prop in properties:
                            row = {
                                "Tag": tag,
                                "PropertyName": prop["PropertyName"],
                                "DefaultValue": prop["DefaultValue"],
                                "RuntimeModifiable": prop["RuntimeModifiable"],
                                "FileType": prop["FileType"]
                            }
                            writer.writerow(row)
                        print(f"已处理 {tag} 的 {file_type}.java")
                    except Exception as e:
                        print(f"处理 {file_path} 时出错: {str(e)}")


# 输入和输出路径
input_dir = "mysql_properties"  # 存放属性定义文件的目录
output_file = "mysql_properties_summary.csv"  # 输出结果文件

# 处理所有文件
process_all_files(input_dir, output_file)
print(f"提取完成。结果已保存到 {output_file}")