from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List, Optional

app = FastAPI()


class Action(BaseModel):
    owner: str
    name: str
    ref: str


class Workflow(BaseModel):
    trigger: str
    permissions: Dict[str, str]
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[Action]
    environmentApproval: Optional[bool] = None


class Image(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Workflow
    image: Image


@app.post("/release-gate")
def release_gate(req: ReleaseRequest):
    violations = []

    # 1. Permissions must be EXACTLY least privilege
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    if req.workflow.permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull requests must use pull_request
    if req.event == "pull_request":
        if req.workflow.trigger != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests, matrix and failFast
    if (
        req.workflow.testsPassed is not True
        or req.workflow.matrixComplete is not True
        or req.workflow.failFast is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    for action in req.workflow.actions:
        if action.owner.lower() == "actions":
            # actions/* may use version tags
            continue

        # Third-party actions require exactly 40 lowercase hex characters
        ref = action.ref
        if not (
            len(ref) == 40
            and all(c in "0123456789abcdef" for c in ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Docker image checks
    if req.image.multiStage is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if req.image.runsAsRoot is not False:
        violations.append("ROOT_RUNTIME")

    if req.image.secretMode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if req.image.criticalVulnerabilities != 0:
        violations.append("CRITICAL_CVE")

    if req.image.digestPinned is not True:
        violations.append("UNPINNED_IMAGE")

    # 6. Production requirements
    if req.target == "production":
        if not (
            req.event == "push"
            and req.ref == "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if req.workflow.environmentApproval is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if len(violations) == 0 else "block",
        "violations": violations
    }
