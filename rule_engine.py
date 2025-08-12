import re
import ast
import random
import logging


SIZE_UNIT_RE = re.compile(r"(\d+(?:\.\d+)?)([KMG]B)?", re.I)
SIZE_WITH_UNIT_RE = re.compile(r"\d+(?:\.\d+)?\s*[KMG]B", re.I)

def compile_rule_expr(expr: str, allowed_names=None):
    """
    编译规则表达式字符串为函数，输入上下文字典返回bool。
    支持多变量，单位（KB, MB, GB）转换仅针对size变量。
    """
    if not expr or not expr.strip():
        # 空表达式，始终返回True
        return lambda context: True

    if allowed_names is None:
        allowed_names = {"size"}

    # 先替换单位为数字，只替换size相关的单位表达式
    def size_to_bytes(s: str) -> int:
        units = {"KB": 1024, "MB": 1024**2, "GB": 1024**3}
        match = SIZE_UNIT_RE.match(s.strip())
        if not match:
            raise ValueError(f"无法解析大小单位: {s}")
        num = float(match.group(1))
        unit = match.group(2).upper() if match.group(2) else None
        return int(num * units.get(unit, 1))

    # 只替换表达式中size相关的带单位数字
    def replace_size_units(match):
        token = match.group(0)
        # 仅替换包含size的表达式中的单位数字
        # 这里简单替换所有单位数字，后续可优化
        return str(size_to_bytes(token))

    expr = SIZE_WITH_UNIT_RE.sub(replace_size_units, expr)

    allowed_ops = {
        ast.And, ast.Or, ast.Not,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod,
        ast.BitAnd, ast.BitOr,
    }

    # 解析表达式为AST
    try:
        expr_ast = ast.parse(expr, mode='eval')
    except Exception as e:
        raise ValueError(f"表达式解析失败: {e}")

    # 安全检查
    class SafeVisitor(ast.NodeVisitor):
        def visit_Name(self, node):
            if node.id not in allowed_names:
                raise ValueError(f"不允许的变量名: {node.id}")

        def visit_Call(self, node):
            raise ValueError("不允许函数调用")

        def visit_Attribute(self, node):
            raise ValueError("不允许属性访问")

        def generic_visit(self, node):
            # 针对操作符节点，检查操作符类型是否允许
            if isinstance(node, (ast.BinOp, ast.BoolOp, ast.UnaryOp)):
                if type(node.op) not in allowed_ops:
                    raise ValueError(f"不允许的操作符: {type(node.op).__name__}")
            super().generic_visit(node)

    SafeVisitor().visit(expr_ast)

    # 编译为代码对象
    code = compile(expr_ast, "<string>", "eval")

    # 返回函数，传入上下文字典context
    def rule_func(context: dict) -> bool:
        # 只传入允许的变量，防止安全问题
        safe_context = {k: context.get(k) for k in allowed_names}
        return eval(code, {}, safe_context)

    return rule_func

def select_node(context: dict = None, rules: list = None, target_nodes: dict = None) -> dict:
    """
    根据上下文字典和规则集选择符合条件的节点，返回选中的节点字典。
    参数rules和target_nodes由外部传入，避免依赖config。
    """
    if not rules:
        logging.error("没有可用的目标节点配置")
        return None

    # 计算每个节点的总权重，节点权重为所有匹配规则集的use权重之和
    node_total_weights = {}

    for rule_set in rules:
        mode = rule_set.get("mode", "and")
        rule_funcs = rule_set.get("rules", [])
        node_weights = rule_set.get("node_weights", {})

        try:
            # 如果context为None且规则集有规则函数，跳过该规则集
            if context is None and rule_funcs:
                continue

            results = [rule(context if context is not None else {}) for rule in rule_funcs]
            match = False
            # rules为空时，视为匹配全部请求
            if not rule_funcs:
                match = True
            else:
                if mode == "and":
                    match = all(results)
                elif mode == "or":
                    match = any(results)
                elif mode == "not":
                    match = not any(results)
            if match:
                for node, weight in node_weights.items():
                    node_total_weights[node] = node_total_weights.get(node, 0) + weight
        except Exception as e:
            logging.warning(f"规则表达式解析失败，规则集 {rule_set.get('rule_name', '')}，错误: {e}")

    if not node_total_weights:
        logging.warning("没有符合规则的目标节点，使用所有启用节点，权重均为1")
        # 所有启用节点权重设为1
        for rule_set in rules:
            for node in rule_set.get("node_weights", {}).keys():
                node_total_weights[node] = 1

    total_weight = sum(node_total_weights.values())
    r = random.uniform(0, total_weight)
    upto = 0
    selected_node = None
    for node, weight in node_total_weights.items():
        if upto + weight >= r:
            selected_node = node
            break
        upto += weight
    if selected_node is None:
        selected_node = next(iter(node_total_weights.keys()))

    # 返回节点信息
    # 直接从target_nodes获取启用节点信息
    if target_nodes:
        for node_name, node_info in target_nodes.items():
            if node_name == selected_node:
                return node_info

    return None