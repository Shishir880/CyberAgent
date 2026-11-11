"""
CyberAgent Core System & Coding Toolset
======================================
Provides system capabilities for:
- PowerShell / Terminal command execution
- Directory management & listing
- File reading with line numbering
- Writing & surgical bug patching
- Recursive code search across files
"""

import os
import subprocess
from typing import Dict, Any, Optional


class SystemToolsMixin:
    """Mixin implementing core operating system and file operations."""

    def run_command(self, command: str, cwd: Optional[str] = None, timeout: int = 60) -> Dict[str, Any]:
        """Executes a terminal/PowerShell command on the system."""
        # Immutable Security Guard: Prevent any command from mutating or deleting CyberAgent code
        if hasattr(self, "check_command_safety"):
            is_blocked, reason = self.check_command_safety(command, cwd)
            if is_blocked:
                return {
                    "success": False,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Security Guard: Command execution blocked. {reason}"
                }

        work_dir = self._resolve_path(cwd) if cwd else self.workspace_root
        try:
            process = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                cwd=work_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout
            )
            return {
                "success": process.returncode == 0,
                "exit_code": process.returncode,
                "stdout": process.stdout.strip(),
                "stderr": process.stderr.strip()
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds."
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e)
            }

    def create_folder(self, folder_path: str) -> Dict[str, Any]:
        """Creates a directory and all intermediate parent folders."""
        if hasattr(self, "is_protected_path") and self.is_protected_path(folder_path):
            return {
                "success": False,
                "error": f"Security Guard: Operation denied. Creating directories within CyberAgent's project folder ('{folder_path}') is strictly forbidden."
            }
        target = self._resolve_path(folder_path)
        try:
            os.makedirs(target, exist_ok=True)
            return {"success": True, "path": target, "message": f"Folder created successfully: {folder_path}"}
        except Exception as e:
            return {"success": False, "path": target, "error": str(e)}

    def read_file(self, file_path: str, start_line: int = 1, end_line: Optional[int] = None) -> Dict[str, Any]:
        """Reads content of a file with line numbers for inspection."""
        target = self._resolve_path(file_path)
        if not os.path.exists(target):
            return {"success": False, "error": f"File not found: {file_path}"}
        if os.path.isdir(target):
            return {"success": False, "error": f"Path is a directory, not a file: {file_path}"}

        try:
            with open(target, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            total_lines = len(lines)
            s_idx = max(1, start_line) - 1
            e_idx = min(total_lines, end_line) if end_line else total_lines

            selected_lines = lines[s_idx:e_idx]
            numbered = [f"{i+1:4d} | {line.rstrip()}" for i, line in enumerate(selected_lines, start=s_idx)]

            return {
                "success": True,
                "file_path": target,
                "total_lines": total_lines,
                "start_line": s_idx + 1,
                "end_line": e_idx,
                "content": "\n".join(numbered)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def write_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Writes or completely overwrites a file with new content."""
        if hasattr(self, "is_protected_path") and self.is_protected_path(file_path):
            return {
                "success": False,
                "error": f"Security Guard: Operation denied. CyberAgent is strictly prohibited from editing or overwriting files in its own project folder ('{file_path}')."
            }
        target = self._resolve_path(file_path)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                f.write(content)
            return {
                "success": True,
                "file_path": target,
                "bytes_written": len(content.encode("utf-8")),
                "message": f"Successfully written to {file_path}"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def edit_file(self, file_path: str, target_snippet: str, replacement_snippet: str) -> Dict[str, Any]:
        """Surgically replaces a specific code block in an existing file to fix a bug."""
        if hasattr(self, "is_protected_path") and self.is_protected_path(file_path):
            return {
                "success": False,
                "error": f"Security Guard: Operation denied. CyberAgent is strictly prohibited from editing or modifying code in its own project folder ('{file_path}')."
            }
        target = self._resolve_path(file_path)
        if not os.path.exists(target):
            return {"success": False, "error": f"File not found: {file_path}"}

        try:
            with open(target, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            if target_snippet not in content:
                return {
                    "success": False,
                    "error": "Target snippet was not found in the file. Ensure indentation and exact code match."
                }

            count = content.count(target_snippet)
            if count > 1:
                return {
                    "success": False,
                    "error": f"Target snippet appears {count} times. Provide a larger unique context block."
                }

            new_content = content.replace(target_snippet, replacement_snippet, 1)
            with open(target, "w", encoding="utf-8") as f:
                f.write(new_content)

            return {
                "success": True,
                "file_path": target,
                "message": f"Successfully patched code in {file_path}"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_directory(self, dir_path: str = ".") -> Dict[str, Any]:
        """Lists directory contents with file sizes and directory flags."""
        target = self._resolve_path(dir_path)
        if not os.path.exists(target):
            return {"success": False, "error": f"Directory not found: {dir_path}"}
        if not os.path.isdir(target):
            return {"success": False, "error": f"Path is not a directory: {dir_path}"}

        try:
            entries = []
            for item in sorted(os.listdir(target)):
                full = os.path.join(target, item)
                is_dir = os.path.isdir(full)
                size = 0 if is_dir else os.path.getsize(full)
                entries.append({
                    "name": item,
                    "is_dir": is_dir,
                    "size_bytes": size,
                    "type": "directory" if is_dir else "file"
                })
            return {"success": True, "path": target, "entries": entries}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def search_code(self, query: str, dir_path: str = ".") -> Dict[str, Any]:
        """Searches files across a directory for a specific query or keyword."""
        target = self._resolve_path(dir_path)
        matches = []
        try:
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ["__pycache__", "node_modules", "vendor", "dist", "build"]]
                for f in files:
                    f_path = os.path.join(root, f)
                    try:
                        with open(f_path, "r", encoding="utf-8", errors="ignore") as file_obj:
                            for lno, line in enumerate(file_obj, 1):
                                if query.lower() in line.lower():
                                    rel = os.path.relpath(f_path, self.workspace_root)
                                    matches.append({
                                        "file": rel,
                                        "line_number": lno,
                                        "line_content": line.strip()
                                    })
                                    if len(matches) >= 35:
                                        break
                    except Exception:
                        continue
                if len(matches) >= 35:
                    break

            return {"success": True, "query": query, "match_count": len(matches), "matches": matches}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # -------------------------------------------------------------------------
    # Autonomous Python Exploit & Custom PoC Script Execution Engine
    # -------------------------------------------------------------------------
    def execute_python_code(self, code: str, script_name: Optional[str] = None, timeout: int = 45) -> Dict[str, Any]:
        """
        Autonomously writes, executes, and validates a custom Python script or exploit PoC.
        Allows CyberAgent to generate bespoke exploit logic, multithreaded network scanners,
        deep fuzzers, or payload decoders, run them in the workspace sandbox, and capture full stdout/stderr.
        """
        import sys
        import time
        import tempfile

        # Sanitize script name
        if not script_name:
            script_name = f"poc_exploit_{int(time.time())}.py"
        elif not script_name.endswith(".py"):
            script_name += ".py"

        # Save inside workspace/scratch or workspace root
        target_dir = os.path.join(self.workspace_root, "scratch")
        os.makedirs(target_dir, exist_ok=True)
        script_path = os.path.join(target_dir, script_name)

        # Safety Guard: Ensure it does not target CyberAgent codebase
        if hasattr(self, "is_protected_path") and self.is_protected_path(script_path):
            return {
                "success": False,
                "error": "Security Gatekeeper: Execution script cannot be written inside CyberAgent directory."
            }

        try:
            # Write script to disk
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(code)

            # Execute python script
            python_bin = sys.executable or "python"
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"

            start_t = time.time()
            proc = subprocess.run(
                [python_bin, script_path],
                cwd=target_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=env
            )
            exec_duration = round(time.time() - start_t, 3)

            return {
                "success": proc.returncode == 0,
                "exit_code": proc.returncode,
                "script_path": script_path,
                "duration_seconds": exec_duration,
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip()
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "exit_code": -1,
                "script_path": script_path,
                "error": f"Script execution timed out after {timeout} seconds."
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": -1,
                "script_path": script_path,
                "error": f"Failed to execute Python script: {str(e)}"
            }

