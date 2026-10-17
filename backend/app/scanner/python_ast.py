import ast
import sys
from dataclasses import dataclass, asdict
import json


@dataclass
class CryptoFinding:
    file: str
    line: int
    column: int
    primitive: str
    library: str
    key_size: int | None
    quantum_vulnerable: bool
    evidence: str


class CryptoScanner(ast.NodeVisitor):
    """
    Walk through a Python AST and look for RSA key generation.
    """

    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[CryptoFinding] = []

    def visit_Call(self, node: ast.Call):
        """
        Look for function calls such as:

            RSA.generate(2048)
        """

        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "RSA"
                and node.func.attr == "generate"
            ):
                key_size = self._get_first_integer_argument(node)

                finding = CryptoFinding(
                    file=self.filename,
                    line=node.lineno,
                    column=node.col_offset,
                    primitive="RSA",
                    library="PyCryptodome",
                    key_size=key_size,
                    quantum_vulnerable=True,
                    evidence="RSA.generate(...)",
                )

                self.findings.append(finding)

        self.generic_visit(node)

    @staticmethod
    def _get_first_integer_argument(node: ast.Call) -> int | None:
        """
        Extract the first integer argument from a function call.

        Example:

            RSA.generate(2048)

        returns:

            2048
        """

        if not node.args:
            return None

        argument = node.args[0]

        if isinstance(argument, ast.Constant):
            if isinstance(argument.value, int):
                return argument.value

        return None


def scan_file(filename: str) -> list[CryptoFinding]:
    """
    Read a Python source file and scan it for cryptographic usage.
    """

    with open(filename, "r", encoding="utf-8") as source_file:
        source = source_file.read()

    tree = ast.parse(source, filename=filename)

    scanner = CryptoScanner(filename)
    scanner.visit(tree)

    return scanner.findings


def main():
    if len(sys.argv) != 2:
        print("Usage: python python_ast.py <python_file>")
        sys.exit(1)

    filename = sys.argv[1]

    findings = scan_file(filename)

    output = [asdict(finding) for finding in findings]

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()