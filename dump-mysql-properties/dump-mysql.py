import os
import subprocess
import shutil

# 克隆仓库
repo_url = "https://github.com/mysql/mysql-connector-j.git"
repo_dir = "mysql-connector-j"

if not os.path.exists(repo_dir):
    subprocess.run(["git", "clone", repo_url, repo_dir])

os.chdir(repo_dir)

# 获取所有 tag
tags = subprocess.run(["git", "tag"], capture_output=True, text=True).stdout.splitlines()

# 创建输出目录
output_dir = "../mysql_properties"
os.makedirs(output_dir, exist_ok=True)


def find_property_files(directory):
    """递归搜索属性定义文件"""
    property_files = {}

    for root, _, files in os.walk(directory):
        for file in files:
            if file == "PropertyDefinitions.java":
                property_files["PropertyDefinitions"] = os.path.join(root, file)
            elif file == "ConnectionPropertiesImpl.java":
                property_files["ConnectionPropertiesImpl"] = os.path.join(root, file)

    return property_files


for tag in tags:
    print(f"处理版本标签: {tag}")
    try:
        subprocess.run(["git", "checkout", tag], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 搜索属性定义文件
        property_files = find_property_files(".")

        tag_dir = os.path.join(output_dir, tag)
        os.makedirs(tag_dir, exist_ok=True)

        # 复制找到的文件
        for file_type, file_path in property_files.items():
            if file_path:
                dest_file = os.path.join(tag_dir, f"{file_type}.java")
                shutil.copy(file_path, dest_file)
                print(f"已复制 {file_path} 到 {dest_file}")

        if not property_files:
            print(f"在版本 {tag} 中未找到属性定义文件")

    except Exception as e:
        print(f"处理版本 {tag} 时出错: {str(e)}")

os.chdir("..")