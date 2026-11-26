
import ast
import yaml

from fastapi import APIRouter, HTTPException

from app.models import ScanRequest
from app.scanner.python_ast import CryptoScanner
from app.risk.cbom import create_cbom, create_policy


router = APIRouter(tags=["Scanner"])


@router.post("/scan")
def scan_source(request: ScanRequest):

    try:
        tree = ast.parse(
            request.source_code,
            filename=request.filename
        )

    except SyntaxError as error:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid Python syntax at line {error.lineno}"
        )

    scanner = CryptoScanner(request.filename)

    scanner.visit(tree)

    findings = scanner.findings

    cbom = create_cbom(findings)

    policy = create_policy(cbom)

    policy_yaml = yaml.safe_dump(
        policy,
        sort_keys=False
    )

    return {
        "status": "success",
        "filename": request.filename,
        "cbom": cbom,
        "policy": policy,
        "policy_yaml": policy_yaml
    }
