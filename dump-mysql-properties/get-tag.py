import csv


def filter_property_definitions(csv_file, target_properties, condition_type="and"):
    """
    从 CSV 文件中提取满足条件的属性和默认值，并列出对应的版本标签。
    :param csv_file: 输入的 CSV 文件路径
    :param target_properties: 需要过滤的属性名和默认值字典
    :param condition_type: 条件类型，"and" 表示并且，"or" 表示或者
    :return: 符合条件的版本标签集合及对应的属性设置
    """
    results = {}

    with open(csv_file, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        # 按版本分组记录满足条件的属性
        version_properties = {}

        for row in reader:
            tag = row["Tag"]
            property_name = row["PropertyName"]
            default_value = row["DefaultValue"]
            file_type = row["FileType"]

            # 初始化版本属性记录
            if tag not in version_properties:
                version_properties[tag] = {}

            # 检查是否是目标属性
            for target_prop in target_properties:
                if property_name == target_prop:
                    version_properties[tag][property_name] = {
                        "DefaultValue": default_value,
                        "FileType": file_type
                    }

        # 分析满足条件的版本
        for tag, props in version_properties.items():
            if condition_type == "and":
                # 并且条件：所有目标属性都必须存在且满足默认值条件
                if all(prop in props for prop in target_properties):
                    if all(props[prop]["DefaultValue"] == target_properties[prop] for prop in target_properties):
                        results[tag] = props
            elif condition_type == "or":
                # 或者条件：任意一个目标属性满足条件即可
                matching_props = {}
                for prop in target_properties:
                    if prop in props and props[prop]["DefaultValue"] == target_properties[prop]:
                        matching_props[prop] = props[prop]

                if matching_props:
                    results[tag] = matching_props

    return results


# 输入和输出路径
csv_file = "mysql_properties_summary.csv"  # 输入的 CSV 文件

# 指定需要过滤的属性和默认值
target_properties = {
    "autoDeserialize": "DEFAULT_VALUE_TRUE",
    "allowLoadLocalInfile": "DEFAULT_VALUE_TRUE",
}

# 选择条件类型："and" 或者 "or"
condition_type = "or"  # 或者条件

# 过滤并输出结果
filtered_versions = filter_property_definitions(csv_file, target_properties, condition_type)

# 输出符合条件的版本标签
if filtered_versions:
    print("符合条件的 MySQL 版本及其设置：")
    print("=" * 70)
    print(f"{'版本标签':<20} {'属性名':<25} {'默认值':<20} {'文件类型'}")
    print("-" * 70)

    for tag in sorted(filtered_versions.keys()):
        for prop_name, details in filtered_versions[tag].items():
            print(f"{tag:<20} {prop_name:<25} {details['DefaultValue']:<20} {details['FileType']}")

    print(f"\n共找到 {len(filtered_versions)} 个符合条件的版本")
else:
    print("没有找到符合条件的 MySQL 版本。")
