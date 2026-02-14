import xml.etree.ElementTree as ET
from pathlib import Path
import json

# ========== 工具函数 ==========

def strip_namespace(root):
    """
    去掉所有元素标签中的命名空间前缀，方便用简短标签名查找
    """
    for elem in root.iter():
        if "}" in elem.tag:
            elem.tag = elem.tag.split("}", 1)[1]
    return root


def safe_find_text(root, path: str):
    """
    安全查找文本内容，如果不存在则返回 None
    """
    node = root.find(path)
    if node is not None and node.text:
        return node.text.strip()
    return None


def load_rules(path: str = "rules.json") -> dict:
    """
    从 JSON 文件加载规则
    """
    rules_file = Path(path)
    if not rules_file.exists():
        raise FileNotFoundError(f"找不到规则文件：{rules_file}")
    with open(rules_file, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_fields(root, field_paths: dict) -> dict:
    """
    根据规则里的 XPath 提取字段值
    """
    result = {}
    for field_name, xpath in field_paths.items():
        if field_name.lower() == "currency":
            node = root.find(xpath)
            value = node.get("Ccy") if node is not None and node.get("Ccy") else None
        else:
            value = safe_find_text(root, xpath)
        result[field_name] = value
    return result


def validate_required_fields(fields: dict, required_field_names) -> list:
    """
    校验必填字段是否缺失，返回缺失字段名列表
    """
    missing = []
    for name in required_field_names:
        value = fields.get(name)
        # 空字符串 / None 都算缺失
        if value is None or (isinstance(value, str) and value.strip() == ""):
            missing.append(name)
    return missing

def build_validation_result(fields: dict, missing_required: list) -> dict:
    """
    构建结构化校验结果，供 UI / API 使用
    """
    result = {
        "status": "VALID",
        "errors": [],
        "warnings": [],
        "parsed_fields": fields
    }

    if missing_required:
        result["status"] = "INVALID"
        for field in missing_required:
            error = {
                "code": f"MISSING_{field.upper()}",
                "field": field,
                "level": "ERROR",
                "message": f"{field} is mandatory for pacs.008"
            }
            result["errors"].append(error)

    return result


# ========== 主流程 ==========

def validate_iso20022_file(file_path: str, rules: dict):
    """
    对单个 ISO20022 报文做解析 + 必填字段校验
    """
    file = Path(file_path)

    if not file.exists():
        print(f"[错误] 找不到文件：{file}")
        return

    try:
        tree = ET.parse(file)
    except ET.ParseError as e:
        print(f"[错误] XML 解析失败：{e}")
        return

    root = tree.getroot()
    root = strip_namespace(root)

    print("✅ XML 文件加载成功")
    print(f"根节点标签：{root.tag}\n")

    required_paths = rules.get("required_fields", {})
    optional_paths = rules.get("optional_fields", {})

    # 解析字段（先把必填的都拿出来）
    fields = extract_fields(root, required_paths)

    # 必填字段校验
    missing = validate_required_fields(fields, required_paths.keys())
    validation_result = build_validation_result(fields, missing)

    print("\n📦 校验结果（结构化）：")
    print(f"Status: {validation_result['status']}")

    if validation_result["errors"]:
       print("Errors:")
       for err in validation_result["errors"]:
           print(f"  - [{err['code']}] {err['message']}")
    else:
        print("No errors found.")

    # （可选）你也可以顺带解析 optional 字段，后面用来做“建议补充”提示：
    if optional_paths:
        optional_values = extract_fields(root, optional_paths)
        print("\nℹ 部分可选字段（仅展示，不做强制校验）：")
        for k, v in optional_values.items():
            print(f"  - {k}: {v}")


if __name__ == "__main__":
    # 1. 加载规则
    rules = load_rules("rules.json")

    # 2. 列出你要校验的文件
    files = [
        "sample1.xml",
        # "sample2.xml",
        # "sample3.xml",
    ]

    for f in files:
        print("=" * 60)
        print(f"开始校验文件：{f}")
        validate_iso20022_file(f, rules)
        print("\n")
