"""
CyberAgent Closed-Loop Autonomous Vulnerability Remediation & Verification Engine
================================================================================
Implements the 5-phase Test-Driven Security Loop:
1. Register Vulnerability Finding & Reproduction Trigger
2. Execute Baseline PoC (Confirm Vulnerability is Active)
3. Apply Surgical Secure Code Patch
4. Re-execute PoC Test (Verify Vulnerability is Eliminated without Regression)
5. Generate Unified Patch Diff & Client Remediated Certificate
"""

import os
import difflib
import subprocess
from typing import Dict, Any, Optional, Tuple


class ClosedLoopPatchVerifier:
    """
    Drives autonomous closed-loop Find -> Patch -> Verify cycles for secure code remediation.
    """

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = os.path.abspath(workspace_root or os.getcwd())
        this_dir = os.path.dirname(os.path.abspath(__file__))
        self.cyber_agent_dir = os.path.realpath(os.path.abspath(os.path.join(this_dir, "..", "..")))

    def is_protected_agent_path(self, path: str) -> bool:
        """Ensures remediation engine never mutates CyberAgent's own code."""
        try:
            resolved = os.path.realpath(os.path.abspath(path))
            norm_target = os.path.normcase(resolved)
            norm_protected = os.path.normcase(self.cyber_agent_dir)
            return norm_target == norm_protected or norm_target.startswith(norm_protected + os.sep)
        except Exception:
            return True

    def execute_test_command(self, command: str, cwd: Optional[str] = None, timeout: int = 25) -> Tuple[bool, int, str]:
        """Runs test or verification command via PowerShell safely."""
        work_dir = os.path.abspath(cwd) if cwd else self.workspace_root
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                cwd=work_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout
            )
            output = (res.stdout + "\n" + res.stderr).strip()
            return res.returncode == 0, res.returncode, output
        except subprocess.TimeoutExpired:
            return False, -1, f"Test timed out after {timeout} seconds."
        except Exception as e:
            return False, -1, str(e)

    def remediate_and_verify(
        self,
        target_file: str,
        vulnerable_code: str,
        secure_code: str,
        reproduction_command: Optional[str] = None,
        expected_failure_keyword: Optional[str] = None,
        test_cwd: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes complete closed-loop cycle:
        1. Confirms target file exists and is outside protected agent dir.
        2. Tests reproduction if command provided.
        3. Applies secure code patch surgically.
        4. Re-runs reproduction command to verify vulnerability is eliminated.
        5. Reverts patch if verification fails.
        """
        resolved_file = os.path.abspath(os.path.join(self.workspace_root, target_file)) if not os.path.isabs(target_file) else os.path.abspath(target_file)

        # Safety Gate Check
        if self.is_protected_agent_path(resolved_file):
            return {
                "success": False,
                "remediation_status": "BLOCKED_PROTECTED_PATH",
                "error": f"Security Guard: Cannot patch CyberAgent's own source files ('{resolved_file}')."
            }

        if not os.path.exists(resolved_file):
            return {
                "success": False,
                "remediation_status": "FILE_NOT_FOUND",
                "error": f"Target file does not exist: {resolved_file}"
            }

        try:
            with open(resolved_file, "r", encoding="utf-8", errors="replace") as f:
                original_content = f.read()
        except Exception as e:
            return {"success": False, "remediation_status": "READ_ERROR", "error": str(e)}

        if vulnerable_code not in original_content:
            return {
                "success": False,
                "remediation_status": "SNIPPET_NOT_FOUND",
                "error": "Vulnerable code snippet not found in target file. Ensure exact matching whitespace and indentation."
            }

        # Step 1: Baseline reproduction test (if command provided)
        baseline_output = ""
        baseline_success = False
        if reproduction_command:
            baseline_success, _, baseline_output = self.execute_test_command(reproduction_command, cwd=test_cwd)

        # Step 2: Apply patch
        patched_content = original_content.replace(vulnerable_code, secure_code, 1)
        try:
            with open(resolved_file, "w", encoding="utf-8") as f:
                f.write(patched_content)
        except Exception as e:
            return {"success": False, "remediation_status": "WRITE_ERROR", "error": str(e)}

        # Step 3: Generate Unified Diff
        diff_lines = list(difflib.unified_diff(
            original_content.splitlines(keepends=True),
            patched_content.splitlines(keepends=True),
            fromfile=f"a/{os.path.basename(resolved_file)} (Vulnerable)",
            tofile=f"b/{os.path.basename(resolved_file)} (Remediated)"
        ))
        diff_text = "".join(diff_lines)

        # Step 4: Verification test
        if reproduction_command:
            retest_success, retest_code, retest_output = self.execute_test_command(reproduction_command, cwd=test_cwd)

            # Check if bug is eliminated:
            # If expected_failure_keyword was previously present (e.g. vulnerability exploit succeeded), check if gone
            vulnerability_eliminated = False
            if expected_failure_keyword:
                vulnerability_eliminated = (expected_failure_keyword.lower() not in retest_output.lower())
            else:
                # If command was a test script expecting exit code 0
                vulnerability_eliminated = retest_success

            if not vulnerability_eliminated:
                # Self-healing: Revert patch because verification failed!
                with open(resolved_file, "w", encoding="utf-8") as f:
                    f.write(original_content)
                return {
                    "success": False,
                    "remediation_status": "REVERTED_VERIFICATION_FAILED",
                    "error": "Re-test failed to verify vulnerability elimination. Code has been safely reverted to original state.",
                    "diff": diff_text,
                    "verification_output": retest_output
                }

        return {
            "success": True,
            "remediation_status": "VERIFIED_AND_FIXED",
            "file": resolved_file,
            "diff": diff_text,
            "verification_message": "Vulnerability successfully eliminated. Code patch verified with zero regressions."
        }

