import ast
import networkx as nx
from itertools import product


def build_cfg(file_path, function_name="authenticate_user"):
    with open(file_path, "r") as f:
        code = f.read()

    tree = ast.parse(code)
    G = nx.DiGraph()

    func = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            func = node
            break
    
    if func is None:
        raise ValueError(f"Function {function_name} not found")

    entry = "Entry"
    exit_node = "Exit"
    G.add_node(entry, label=entry)
    G.add_node(exit_node, label=exit_node)

    current = entry
    node_counter = 0

    def create_node(label, prefix):
        nonlocal node_counter
        node_counter += 1
        return f"{prefix}_{node_counter}", label

    def process_statements(statements, parent_node):
        nonlocal current
        last_node = parent_node
        for stmt in statements:
            if isinstance(stmt, ast.If):

                test_node, test_label = create_node(ast.unparse(stmt.test), "If")
                G.add_node(test_node, label=test_label)
                G.add_edge(last_node, test_node)

                true_exit = None
                for true_stmt in stmt.body:
                    true_node, true_label = create_node(ast.unparse(true_stmt), "T")
                    G.add_node(true_node, label=true_label)
                    if true_exit is None:
                        G.add_edge(test_node, true_node, label="True")
                    else:
                        G.add_edge(true_exit, true_node)
                    true_exit = true_node
                    
                    if isinstance(true_stmt, ast.Return):
                        G.add_edge(true_node, exit_node)
                    elif isinstance(true_stmt, ast.If):
                        process_statements([true_stmt], true_node)
       
                false_exit = None
                if stmt.orelse:
                    for false_stmt in stmt.orelse:
                        false_node, false_label = create_node(ast.unparse(false_stmt), "F")
                        G.add_node(false_node, label=false_label)
                        if false_exit is None:
                            G.add_edge(test_node, false_node, label="False")
                        else:
                            G.add_edge(false_exit, false_node)
                        false_exit = false_node
                        
                        if isinstance(false_stmt, ast.Return):
                            G.add_edge(false_node, exit_node)
                        elif isinstance(false_stmt, ast.If):
                            process_statements([false_stmt], false_node)
                else:
                    false_exit = test_node
           
                if true_exit and not isinstance(stmt.body[-1], (ast.Return, ast.If)):
                    G.add_edge(true_exit, false_exit)
                    current = false_exit
                elif false_exit:
                    current = false_exit
                else:
                    current = test_node
                last_node = current

            elif isinstance(stmt, ast.Assign):
                assign_node, assign_label = create_node(ast.unparse(stmt), "A")
                G.add_node(assign_node, label=assign_label)
                G.add_edge(last_node, assign_node)
                last_node = assign_node
                current = assign_node

            elif isinstance(stmt, ast.Return):
                ret_node, ret_label = create_node(ast.unparse(stmt), "R")
                G.add_node(ret_node, label=ret_label)
                G.add_edge(last_node, ret_node)
                G.add_edge(ret_node, exit_node)
                last_node = exit_node
                current = exit_node

    process_statements(func.body, entry)

    if current != exit_node and not any(exit_node in G[current].values()):
        G.add_edge(current, exit_node)

    return G, entry, exit_node


def print_condition_combinations():

    conditions = [
        "not_username",
        "not_password",
        "username_not_in_db",
        "attempts_ge_3",
        "password_mismatch"
    ]

    combinations = list(product([False, True], repeat=len(conditions)))

    header = "| {:^6} | ".format("Case") + " | ".join(f"{name:^18}" for name in conditions) + " |"
    separator = "|" + "-" * (len(header) - 2) + "|"

    print(separator)
    print(header)
    print(separator)

    for i, combo in enumerate(combinations, 1):
        row = "| {:>6} | ".format(i) + " | ".join(f"{str(val):^18}" for val in combo) + " |"
        print(row)

    print(separator)



if __name__ == "__main__":
    G, entry, exit_node = build_cfg("auth.py")

    cc = G.number_of_edges() - G.number_of_nodes() + 2
    print(f"Цикломатична складність: {cc}")

    paths = list(nx.all_simple_paths(G, source=entry, target=exit_node))

    print("\nШляхи виконання (all_simple_paths):")
    for i, path in enumerate(paths, 1):
        print(f"Шлях {i}: {path}")

    nx.drawing.nx_pydot.write_dot(G, "cfg.dot")

    print("\nТаблиця всіх комбінацій умов (Truth Table):")
    print_condition_combinations()
