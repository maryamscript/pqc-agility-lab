import ast
import json
import sys
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class CryptoFinding:
    file: str
    line: int
    column: int
    primitive: str
    library: str
    key_size: Optional[int]
    curve: Optional[str]
    quantum_vulnerable: bool
    evidence: str


class CryptoScanner(ast.NodeVisitor):
    """
    Static scanner for detecting quantum-vulnerable
    public-key cryptography in Python source code.

    Currently detects:
        - PyCryptodome RSA
        - cryptography RSA
        - cryptography ECC
    """

    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[CryptoFinding] = []

        # Track common import aliases.
        self.rsa_aliases = {"RSA"}
        self.ec_aliases = {"ec"}
        self.rsa_module_aliases = {"rsa"}

    # ------------------------------------------------------------------
    # Import handling
    # ------------------------------------------------------------------

    def visit_Import(self, node: ast.Import):
        """
        Track imports such as:

            import Crypto.PublicKey.RSA as RSA
            import cryptography.hazmat.primitives.asymmetric.ec as ec
        """

        for alias in node.names:
            imported_name = alias.name
            local_name = alias.asname or imported_name.split(".")[-1]

            if imported_name == "Crypto.PublicKey.RSA":
                self.rsa_aliases.add(local_name)

            elif imported_name == "cryptography.hazmat.primitives.asymmetric.ec":
                self.ec_aliases.add(local_name)

            elif imported_name == "cryptography.hazmat.primitives.asymmetric.rsa":
                self.rsa_module_aliases.add(local_name)

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """
        Track imports such as:

            from Crypto.PublicKey import RSA

            from cryptography.hazmat.primitives.asymmetric import ec

            from cryptography.hazmat.primitives.asymmetric import rsa
        """

        module = node.module or ""

        for alias in node.names:
            local_name = alias.asname or alias.name

            if module == "Crypto.PublicKey" and alias.name == "RSA":
                self.rsa_aliases.add(local_name)

            elif (
                module == "cryptography.hazmat.primitives.asymmetric"
                and alias.name == "ec"
            ):
                self.ec_aliases.add(local_name)

            elif (
                module == "cryptography.hazmat.primitives.asymmetric"
                and alias.name == "rsa"
            ):
                self.rsa_module_aliases.add(local_name)

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Function-call detection
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call):
        """
        Inspect function calls for known cryptographic operations.
        """

        # --------------------------------------------------------------
        # PyCryptodome RSA
        #
        # Example:
        #
        #     RSA.generate(2048)
        #
        # --------------------------------------------------------------

        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.rsa_aliases
                and node.func.attr == "generate"
            ):
                key_size = self._get_integer_argument(
                    node,
                    keyword_names={"bits", "key_size"},
                )

                finding = CryptoFinding(
                    file=self.filename,
                    line=node.lineno,
                    column=node.col_offset,
                    primitive="RSA",
                    library="PyCryptodome",
                    key_size=key_size,
                    curve=None,
                    quantum_vulnerable=True,
                    evidence="RSA.generate(...)",
                )

                self.findings.append(finding)

        # --------------------------------------------------------------
        # cryptography RSA
        #
        # Example:
        #
        #     rsa.generate_private_key(
        #         public_exponent=65537,
        #         key_size=2048
        #     )
        #
        # --------------------------------------------------------------

        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.rsa_module_aliases
                and node.func.attr == "generate_private_key"
            ):
                key_size = self._get_integer_argument(
                    node,
                    keyword_names={"key_size"},
                )

                finding = CryptoFinding(
                    file=self.filename,
                    line=node.lineno,
                    column=node.col_offset,
                    primitive="RSA",
                    library="cryptography",
                    key_size=key_size,
                    curve=None,
                    quantum_vulnerable=True,
                    evidence="rsa.generate_private_key(...)",
                )

                self.findings.append(finding)

        # --------------------------------------------------------------
        # Elliptic Curve Cryptography
        #
        # Example:
        #
        #     ec.generate_private_key(ec.SECP256R1())
        #
        # --------------------------------------------------------------

        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.ec_aliases
                and node.func.attr == "generate_private_key"
            ):
                curve = self._get_curve_name(node)

                finding = CryptoFinding(
                    file=self.filename,
                    line=node.lineno,
                    column=node.col_offset,
                    primitive="ECC",
                    library="cryptography",
                    key_size=None,
                    curve=curve,
                    quantum_vulnerable=True,
                    evidence="ec.generate_private_key(...)",
                )

                self.findings.append(finding)

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Argument extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _get_integer_argument(
        node: ast.Call,
        keyword_names: set[str],
    ) -> Optional[int]:
        """
        Extract an integer argument from a function call.

        Supports:

            RSA.generate(2048)

        and:

            rsa.generate_private_key(key_size=2048)
        """

        # Check positional arguments first.
        for argument in node.args:
            if isinstance(argument, ast.Constant):
                if isinstance(argument.value, int):
                    return argument.value

        # Check keyword arguments.
        for keyword in node.keywords:
            if keyword.arg in keyword_names:
                if isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, int):
                        return keyword.value.value

        return None

    @staticmethod
    def _get_curve_name(node: ast.Call) -> Optional[str]:
        """
        Extract the curve name from:

            ec.generate_private_key(ec.SECP256R1())

        Returns:

            SECP256R1
        """

        if not node.args:
            return None

        first_argument = node.args[0]

        if isinstance(first_argument, ast.Call):
            if isinstance(first_argument.func, ast.Attribute):
                return first_argument.func.attr

        return None


# ----------------------------------------------------------------------
# File scanning
# ----------------------------------------------------------------------


def scan_file(filename: str) -> list[CryptoFinding]:
    """
    Read a Python file, parse it into an AST,
    and return all crypto findings.
    """

    with open(filename, "r", encoding="utf-8") as source_file:
        source = source_file.read()

    tree = ast.parse(source, filename=filename)

    scanner = CryptoScanner(filename)
    scanner.visit(tree)

    return scanner.findings


# ----------------------------------------------------------------------
# Command-line interface
# ----------------------------------------------------------------------


def main():
    """
    Command-line usage:

        python app/scanner/python_ast.py ../examples/vulnerable_app.py
    """

    if len(sys.argv) != 2:
        print("Usage: python app/scanner/python_ast.py <python_file>")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        findings = scan_file(filename)

    except FileNotFoundError:
        print(f"Error: file not found: {filename}")
        sys.exit(1)

    except SyntaxError as error:
        print(
            f"Error: could not parse {filename} "
            f"at line {error.lineno}: {error.msg}"
        )
        sys.exit(1)

    output = [asdict(finding) for finding in findings]

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()