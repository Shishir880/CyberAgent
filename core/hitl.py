"""
CyberAgent - Human-in-the-Loop (HITL) Security Gatekeeper
==========================================================
Provides interactive human oversight and authorization for sensitive, destructive,
or offensive operations:
- Prompting operator with Accept, Reject, Always Allow Tool, or Always Allow All choices
- Preventing unintended command execution, codebase mutation, or live server exploit probes
- Returning graceful feedback to the LLM agent when an action is rejected
"""

import sys
import json
from typing import Dict, Any, Set, Tuple, Optional, Callable
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.prompt import Prompt


DEFAULT_SENSITIVE_TOOLS: Dict[str, str] = {
    "run_command": "Executing terminal / PowerShell command on host system",
    "write_file": "Creating or overwriting code/file on disk",
    "edit_file": "Surgically modifying codebase file",
    "verify_target_vulnerability": "Sending active exploit / PoC probe to live target",
    "run_full_pentest_audit": "Running automated 5-phase offensive penetration test",
    "audit_login_security": "Sending multiple brute-force login attempts"
}


class HITLManager:
    """
    Manages Human-in-the-Loop (HITL) authorization for CyberAgent.

    Supported user decisions:
    - [y / accept]: Allow this single tool execution.
    - [r / reject]: Deny this tool execution and inform the agent.
    - [a / always]: Whitelist this specific tool for all subsequent calls in this session.
    - [all]: Whitelist ALL tools for the remainder of this session (fully autonomous).
    """

    def __init__(
        self,
        enabled: bool = True,
        sensitive_tools: Optional[Dict[str, str]] = None,
        auto_approve_all: bool = False
    ):
        self.enabled: bool = enabled
        self.sensitive_tools: Dict[str, str] = dict(sensitive_tools or DEFAULT_SENSITIVE_TOOLS)
        self.always_allowed_tools: Set[str] = set()
        self.auto_approve_all: bool = auto_approve_all

    def needs_approval(self, tool_name: str, args: Optional[Dict[str, Any]] = None) -> bool:
        """Determines whether a given tool execution requires human authorization."""
        if not self.enabled:
            return False
        if self.auto_approve_all:
            return False
        if tool_name in self.always_allowed_tools:
            return False
        return tool_name in self.sensitive_tools

    def request_approval(
        self,
        console: Optional[Console],
        tool_name: str,
        args: Dict[str, Any],
        approval_callback: Optional[Callable[[str, Dict[str, Any]], Tuple[bool, str]]] = None
    ) -> Tuple[bool, str]:
        """
        Prompts the human operator for authorization to execute the specified tool.

        Returns:
            Tuple[bool, str]: (is_approved, status_or_feedback_message)
        """
        console = console or Console()

        # If a custom callback is provided (e.g. from automated tests or external GUI/API)
        if approval_callback is not None:
            return approval_callback(tool_name, args)

        # In non-interactive environments (pipes/redirected stdin without tty)
        if not sys.stdin.isatty():
            return True, "Auto-approved: non-interactive environment."

        description = self.sensitive_tools.get(tool_name, "Potentially sensitive system action")

        # Format parameters for clean visual review
        try:
            params_str = json.dumps(args, indent=2, ensure_ascii=False)
        except Exception:
            params_str = str(args)

        content = (
            f"[bold red]Action:[/bold red] {description}\n"
            f"[bold cyan]Tool Name:[/bold cyan] [bold white]{tool_name}[/bold white]\n\n"
            f"[bold white]Parameters to execute:[/bold white]\n"
            f"[green]{params_str}[/green]"
        )

        console.print()
        console.print(Panel(
            content,
            title="[bold yellow]⚠️  Human-in-the-Loop Authorization Required[/bold yellow]",
            subtitle="[dim]Accept [y] | Reject [r] | Always allow this tool [a] | Always allow all [all][/dim]",
            border_style="yellow"
        ))

        while True:
            try:
                choice = Prompt.ask(
                    "[bold yellow]Authorize execution?[/bold yellow] [bold green][y][/bold green] Accept / [bold red][r][/bold red] Reject / [bold cyan][a][/bold cyan] Always this tool / [bold magenta][all][/bold magenta] All-time allow",
                    choices=["y", "r", "a", "all", "yes", "no", "reject", "accept", "always"],
                    default="y"
                ).strip().lower()

                if choice in ("y", "yes", "accept"):
                    console.print(f"[bold green]✔ Accepted: Executing '{tool_name}'...[/bold green]")
                    return True, "Approved by human operator."

                elif choice in ("r", "no", "reject"):
                    reason = Prompt.ask("[bold red]Enter rejection reason for agent (optional)[/bold red]", default="Denied by human operator.")
                    feedback = reason.strip() or "Denied by human operator."
                    console.print(f"[bold red]✖ Rejected: '{tool_name}' canceled by operator.[/bold red]")
                    return False, feedback

                elif choice in ("a", "always"):
                    self.always_allowed_tools.add(tool_name)
                    console.print(f"[bold cyan]⚡ Tool '{tool_name}' is now ALWAYS ALLOWED for this session.[/bold cyan]")
                    return True, f"Always allowed for tool '{tool_name}' by human operator."

                elif choice == "all":
                    self.auto_approve_all = True
                    console.print("[bold magenta]🚀 ALL TOOLS are now ALWAYS ALLOWED for the remainder of this session (Autonomous Mode).[/bold magenta]")
                    return True, "Always allowed all tools by human operator."

            except (KeyboardInterrupt, EOFError):
                console.print("\n[bold red]✖ Authorization aborted: rejecting execution.[/bold red]")
                return False, "Authorization aborted by user interrupt."

    def allow_tool(self, tool_name: str) -> None:
        """Whitelists a specific tool so it will no longer trigger HITL approval."""
        self.always_allowed_tools.add(tool_name)

    def disallow_tool(self, tool_name: str) -> None:
        """Removes a tool from the session whitelist."""
        self.always_allowed_tools.discard(tool_name)

    def allow_all(self) -> None:
        """Whitelists all tools for the session."""
        self.auto_approve_all = True

    def reset_always_allowed(self) -> None:
        """Resets all whitelisted tools and global allow-all state."""
        self.always_allowed_tools.clear()
        self.auto_approve_all = False

    def set_enabled(self, enabled: bool) -> None:
        """Enables or disables Human-in-the-Loop protection globally."""
        self.enabled = enabled

    def add_sensitive_tool(self, tool_name: str, description: str) -> None:
        """Registers an additional tool as sensitive."""
        self.sensitive_tools[tool_name] = description

    def remove_sensitive_tool(self, tool_name: str) -> None:
        """Removes a tool from the sensitive tools list."""
        self.sensitive_tools.pop(tool_name, None)

    def get_status(self) -> Dict[str, Any]:
        """Returns the current status of Human-in-the-Loop."""
        return {
            "enabled": self.enabled,
            "auto_approve_all": self.auto_approve_all,
            "sensitive_tools_count": len(self.sensitive_tools),
            "sensitive_tools": list(self.sensitive_tools.keys()),
            "always_allowed_tools": list(self.always_allowed_tools)
        }
