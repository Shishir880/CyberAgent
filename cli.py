"""
CyberAgent - Command Line Interface (CLI)
Interactive Autonomous Software Engineer & Cyber Assistant
"""

import os
import sys

# Ensure UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from cyber_agent.config import AgentConfig, PROVIDER_PRESETS
from cyber_agent.agent import CyberAgent


def print_banner(console: Console, config: AgentConfig):
    console.clear()
    banner = """
   ⚡ [bold cyan]CYBERAGENT - AUTONOMOUS AI SOFTWARE ENGINEER[/bold cyan] ⚡
   [dim]Commands: PowerShell Execution | Code Search | Surgical Bug Patching | Directory Creation[/dim]
    """
    console.print(Panel(banner, border_style="cyan"))

    # Status Table
    tbl = Table(show_header=False, box=None, padding=(0, 2))
    tbl.add_row("[bold white]API Provider:[/bold white]", f"[bold green]{config.provider.upper()}[/bold green] ({config.base_url})")
    tbl.add_row("[bold white]Active Model:[/bold white]", f"[bold yellow]{config.model}[/bold yellow]")
    tbl.add_row("[bold white]Workspace Root:[/bold white]", f"[bold magenta]{config.workspace_root}[/bold magenta]")
    tbl.add_row("[bold white]API Key Status:[/bold white]", "[bold green]Configured[/bold green]" if config.api_key else "[bold red]Not set[/bold red]")
    hitl_str = "[bold green]Active (Sensitive Operations)[/bold green]" if getattr(config, "hitl_enabled", True) else "[bold yellow]Disabled (Autonomous Mode)[/bold yellow]"
    tbl.add_row("[bold white]Human-in-the-Loop:[/bold white]", hitl_str)
    console.print(Panel(tbl, title="[bold]Agent Environment Status[/bold]", border_style="blue"))
    console.print("[dim]Type your objective below or type [bold cyan]/help[/bold cyan] for settings.[/dim]\n")


def print_help(console: Console):
    tbl = Table(title="CyberAgent Commands", border_style="cyan")
    tbl.add_column("Command", style="bold yellow")
    tbl.add_column("Description", style="white")

    tbl.add_row("/provider <name>", "Switch API: ollama, gemini, deepseek, anthropic, groq, openai, openrouter")
    tbl.add_row("/model <name>", "Switch model: e.g. qwen2.5:3b, gpt-4o, deepseek-chat, llama-3.3-70b")
    tbl.add_row("/key <api_key>", "Set your API key for the current provider")
    tbl.add_row("/workspace <path>", "Change target workspace directory")
    tbl.add_row("/browser [gui|headless]", "Toggle live visible Chromium window on desktop vs silent background")
    tbl.add_row("/browse <url> [--gui]", "Navigate web page with autonomous browser (add '--gui' to view live)")
    tbl.add_row("/screenshot [name]", "Autonomous Browser: capture full-page screenshot into screenshots/")
    tbl.add_row("/memory", "Show fast Short-Term Working Memory (RAM, 0ms overhead)")
    tbl.add_row("/memory <query>", "Deep search permanent Long-Term Memory (NLTK Stemming + Vector Embeddings)")
    tbl.add_row("/memory save", "Commit session short-term findings into permanent Long-Term SQLite storage")
    tbl.add_row("/dossier <target>", "View complete intelligence dossier on target (e.g. /dossier bizmatepro.xyz)")
    tbl.add_row("/team <mission>", "Launch Multi-Agent Swarm (Recon + Exploit + Defender sub-agents)")
    tbl.add_row("/swarm <mission>", "Alias for /team collaborative multi-agent mode")
    tbl.add_row("/tools", "Interactive Tool Selector (toggle tools 1-36, 'all', 'none', or presets)")
    tbl.add_row("/tools mouse", "Open native desktop popup to click & select tools with mouse (GUI)")
    tbl.add_row("/status", "Display current configuration")
    tbl.add_row("/clear", "Clear screen and redraw banner")
    tbl.add_row("exit / quit", "Exit CyberAgent")
    console.print(tbl)


def interactive_tool_selector(console: Console, agent: CyberAgent):
    """Interactive command-line tool selection menu with checkboxes and presets."""
    all_defs = agent.all_tool_definitions
    tool_names = [td["function"]["name"] for td in all_defs]

    # Current enabled set
    active_defs = agent.get_active_tool_definitions()
    enabled_set = set(td["function"]["name"] for td in active_defs)

    def print_menu():
        tbl = Table(title="🔧 CyberAgent Terminal Tool Selector", border_style="cyan")
        tbl.add_column("#", style="bold yellow", width=4)
        tbl.add_column("Status", width=9)
        tbl.add_column("Tool Name", style="bold white", width=28)
        tbl.add_column("Description", style="dim white")

        for idx, tname in enumerate(tool_names, 1):
            is_on = tname in enabled_set
            status_badge = "[bold green][✔] ON [/bold green]" if is_on else "[dim][ ] OFF[/dim]"
            
            desc = ""
            for td in all_defs:
                if td["function"]["name"] == tname:
                    desc = td["function"].get("description", "")[:60] + "..."
                    break

            tbl.add_row(str(idx), status_badge, tname, desc)

        console.print(tbl)
        console.print(f"[bold cyan]Active Tools: {len(enabled_set)}/{len(tool_names)} Enabled[/bold cyan]")
        console.print("[dim]Commands: Type numbers to toggle (e.g. '1, 3, 5' or '12') | 'all' (select all) | 'none' (deselect all)[/dim]")
        console.print("[dim]Presets: 'minimal' (fast 3 tools) | 'pentest' (offensive) | 'search' (web search) | 'done' (save & exit)[/dim]")
        console.print("[dim]Mouse Mode: Type 'mouse' or 'gui' to open a mouse-clickable popup window![/dim]\n")

    print_menu()

    while True:
        try:
            choice = Prompt.ask("[bold yellow]Tool Selector ❯[/bold yellow]").strip().lower()
            if not choice or choice in ("done", "exit", "q", "save"):
                if not enabled_set:
                    console.print("[yellow]⚠️ At least one tool should be active! Enabling minimal core tools.[/yellow]")
                    enabled_set = {"run_command", "read_file", "write_file"}
                agent.set_enabled_tools(list(enabled_set))
                console.print(f"[bold green]✔ Saved! {len(enabled_set)} tools are now active in CyberAgent.[/bold green]\n")
                break

            if choice in ("mouse", "gui", "window", "popup"):
                from cyber_agent.gui_selector import launch_mouse_tool_selector
                selected = launch_mouse_tool_selector(
                    currently_enabled=list(enabled_set),
                    all_tools=tool_names
                )
                if selected is not None:
                    enabled_set = set(selected)
                    agent.set_enabled_tools(list(enabled_set))
                    console.print(f"[bold green]✔ Mouse selection applied! {len(enabled_set)} tools are now active in CyberAgent.[/bold green]\n")
                    break
                else:
                    console.print("[dim]Mouse selection closed without saving. Returning to terminal selector.[/dim]")
                    print_menu()
                    continue

            if choice in ("all", "select all"):
                enabled_set = set(tool_names)
                console.print("[bold green]✔ Selected ALL 36 tools.[/bold green]")
                print_menu()
                continue

            if choice in ("none", "deselect all", "clear"):
                enabled_set.clear()
                console.print("[bold yellow]✔ Deselected all tools.[/bold yellow]")
                print_menu()
                continue

            if choice in ("minimal", "fast"):
                enabled_set = {"run_command", "read_file", "write_file"}
                console.print("[bold green]✔ Switched to FAST MINIMAL preset (3 tools: run_command, read_file, write_file).[/bold green]")
                print_menu()
                continue

            if choice in ("pentest", "hack"):
                enabled_set = {
                    "crawl_attack_surface", "run_full_pentest_audit", "fuzz_web_endpoints",
                    "verify_target_vulnerability", "audit_login_security", "detect_waf_fingerprint",
                    "audit_account_enumeration", "extract_sensitive_leaks", "audit_form_csrf_security",
                    "probe_service_ports", "audit_php_threats"
                }
                console.print(f"[bold green]✔ Switched to PENTEST preset ({len(enabled_set)} offensive tools).[/bold green]")
                print_menu()
                continue

            if choice in ("search", "web"):
                enabled_set = {"search_internet", "scrape_web_page", "browser_navigate", "crawl_attack_surface", "calculate_datetime"}
                console.print(f"[bold green]✔ Switched to WEB & SEARCH preset ({len(enabled_set)} tools).[/bold green]")
                print_menu()
                continue

            if choice == "list":
                print_menu()
                continue

            # Parse numbers separated by commas or spaces
            parts = [p.strip() for p in choice.replace(",", " ").split() if p.strip()]
            toggled_any = False
            for p in parts:
                if p.isdigit():
                    num = int(p)
                    if 1 <= num <= len(tool_names):
                        tname = tool_names[num - 1]
                        if tname in enabled_set:
                            enabled_set.remove(tname)
                            console.print(f"[red]✖ Disabled:[/red] #{num} {tname}")
                        else:
                            enabled_set.add(tname)
                            console.print(f"[green]✔ Enabled:[/green] #{num} {tname}")
                        toggled_any = True
                    else:
                        console.print(f"[red]Invalid number #{num}. Range is 1 to {len(tool_names)}.[/red]")
                else:
                    matches = [t for t in tool_names if p in t]
                    if len(matches) == 1:
                        tname = matches[0]
                        if tname in enabled_set:
                            enabled_set.remove(tname)
                            console.print(f"[red]✖ Disabled:[/red] {tname}")
                        else:
                            enabled_set.add(tname)
                            console.print(f"[green]✔ Enabled:[/green] {tname}")
                        toggled_any = True
                    else:
                        console.print(f"[yellow]Unknown option '{p}'. Type numbers, 'all', 'none', 'minimal', or 'done'.[/yellow]")

            if toggled_any:
                console.print(f"[dim]Active Tools: {len(enabled_set)}/{len(tool_names)} (Type 'list' to show table again, 'done' to save)[/dim]")

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow]Tool selection saved.[/bold yellow]")
            agent.set_enabled_tools(list(enabled_set) if enabled_set else None)
            break


def main():
    console = Console()
    config = AgentConfig()

    # One-shot command line argument execution
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        task = " ".join(sys.argv[1:])
        agent = CyberAgent(config=config, console=console)
        agent.run_task(task)
        return

    print_banner(console, config)
    agent = CyberAgent(config=config, console=console)

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]CyberAgent ❯[/bold cyan]").strip()
            if not user_input:
                continue

            if user_input.lower() in ["exit", "quit", "q"]:
                console.print("[bold yellow]Exiting CyberAgent. Goodbye![/bold yellow]")
                break

            if user_input.startswith("gsk_"):
                config.set_provider("groq", api_key=user_input, model="llama-3.3-70b-versatile")
                console.print(f"[bold green]✔ Groq API Key detected & configured! Provider set to GROQ | Active Model: {config.model}[/bold green]")
                agent = CyberAgent(config=config, console=console)
                continue
            elif user_input.startswith("sk-or-"):
                config.set_provider("openrouter", api_key=user_input)
                console.print(f"[bold green]✔ OpenRouter API Key detected & configured! Provider set to OPENROUTER | Active Model: {config.model}[/bold green]")
                agent = CyberAgent(config=config, console=console)
                continue
            elif user_input.startswith("AIza"):
                config.set_provider("gemini", api_key=user_input)
                console.print(f"[bold green]✔ Google Gemini API Key detected & configured! Provider set to GEMINI | Active Model: {config.model}[/bold green]")
                agent = CyberAgent(config=config, console=console)
                continue
            elif user_input.startswith("sk-ant-"):
                config.set_provider("anthropic", api_key=user_input)
                console.print(f"[bold green]✔ Anthropic API Key detected & configured! Provider set to ANTHROPIC | Active Model: {config.model}[/bold green]")
                agent = CyberAgent(config=config, console=console)
                continue

            if user_input.startswith("/"):
                parts = user_input.split(maxsplit=1)
                cmd = parts[0].lower()
                arg = parts[1].strip() if len(parts) > 1 else ""

                if cmd == "/help":
                    print_help(console)
                elif cmd == "/clear":
                    print_banner(console, config)
                elif cmd == "/status":
                    print_banner(console, config)
                elif cmd == "/provider":
                    if not arg:
                        console.print(f"[bold red]Specify provider: {', '.join(PROVIDER_PRESETS.keys())}[/bold red]")
                    else:
                        success = config.set_provider(arg)
                        if success:
                            console.print(f"[bold green]Switched to provider: {arg.upper()} (Default Model: {config.model})[/bold green]")
                            agent = CyberAgent(config=config, console=console)
                        else:
                            console.print(f"[bold red]Unknown provider '{arg}'. Options: {', '.join(PROVIDER_PRESETS.keys())}[/bold red]")
                elif cmd == "/model":
                    if not arg:
                        console.print("[bold red]Specify model name, e.g. /model llama-3.3-70b-versatile or /model qwen2.5:3b[/bold red]")
                    elif arg.startswith("gsk_"):
                        # User accidentally passed Groq API key into /model
                        config.set_provider("groq", api_key=arg, model="llama-3.3-70b-versatile")
                        console.print("[bold yellow]⚡ Detected Groq API Key! Automatically set API key and switched provider to GROQ.[/bold yellow]")
                        console.print(f"[bold green]✔ Active Provider: GROQ | Active Model: {config.model}[/bold green]")
                        agent = CyberAgent(config=config, console=console)
                    elif arg.startswith("sk-or-"):
                        config.set_provider("openrouter", api_key=arg)
                        console.print("[bold yellow]⚡ Detected OpenRouter API Key! Switched provider to OPENROUTER.[/bold yellow]")
                        console.print(f"[bold green]✔ Active Provider: OPENROUTER | Active Model: {config.model}[/bold green]")
                        agent = CyberAgent(config=config, console=console)
                    elif arg.startswith("sk-") and len(arg) > 35:
                        config.set_provider("openai", api_key=arg)
                        console.print("[bold yellow]⚡ Detected OpenAI API Key! Switched provider to OPENAI.[/bold yellow]")
                        console.print(f"[bold green]✔ Active Provider: OPENAI | Active Model: {config.model}[/bold green]")
                        agent = CyberAgent(config=config, console=console)
                    elif arg.startswith("qwen") or (":" in arg and not arg.startswith("http")):
                        if config.provider != "ollama":
                            config.set_provider("ollama", model=arg)
                            console.print(f"[bold green]🔄 Auto-switched provider to OLLAMA (Local) for model '{arg}'![/bold green]")
                            agent = CyberAgent(config=config, console=console)
                        else:
                            config.model = arg
                            config.save()
                            console.print(f"[bold green]Active model set to: {arg} (Provider: OLLAMA)[/bold green]")
                            agent = CyberAgent(config=config, console=console)
                    else:
                        # Auto-switch provider if model name is clearly Groq and user has Groq key
                        if config.provider == "ollama" and (arg.startswith("llama-3") or arg.startswith("mixtral") or arg.startswith("deepseek-r1")):
                            if getattr(config, "api_key", "").startswith("gsk_"):
                                config.provider = "groq"
                                config.base_url = PROVIDER_PRESETS["groq"]["base_url"]
                                console.print("[bold cyan]🔄 Auto-switched provider to GROQ for this model.[/bold cyan]")
                        config.model = arg
                        config.save()
                        console.print(f"[bold green]Active model set to: {arg} (Provider: {config.provider.upper()})[/bold green]")
                        agent = CyberAgent(config=config, console=console)
                elif cmd == "/key":
                    if not arg:
                        console.print("[bold red]Specify your API key, e.g. /key gsk_... or /key sk-...[/bold red]")
                    else:
                        key_val = arg.strip()
                        if key_val.startswith("gsk_"):
                            config.set_provider("groq", api_key=key_val, model="llama-3.3-70b-versatile")
                            console.print(f"[bold green]✔ Auto-detected Groq API Key! Switched provider to GROQ (Model: {config.model})[/bold green]")
                        elif key_val.startswith("sk-or-"):
                            config.set_provider("openrouter", api_key=key_val)
                            console.print(f"[bold green]✔ Auto-detected OpenRouter API Key! Switched provider to OPENROUTER (Model: {config.model})[/bold green]")
                        elif key_val.startswith("AIza"):
                            config.set_provider("gemini", api_key=key_val)
                            console.print(f"[bold green]✔ Auto-detected Google Gemini API Key! Switched provider to GEMINI (Model: {config.model})[/bold green]")
                        elif key_val.startswith("sk-ant-"):
                            config.set_provider("anthropic", api_key=key_val)
                            console.print(f"[bold green]✔ Auto-detected Anthropic API Key! Switched provider to ANTHROPIC (Model: {config.model})[/bold green]")
                        else:
                            config.api_key = key_val
                            config.save()
                            console.print(f"[bold green]API key updated successfully for {config.provider.upper()}![/bold green]")
                        agent = CyberAgent(config=config, console=console)
                elif cmd == "/workspace":
                    if not arg or not os.path.exists(arg):
                        console.print("[bold red]Valid directory path required.[/bold red]")
                    else:
                        config.workspace_root = os.path.abspath(arg)
                        config.save()
                        console.print(f"[bold green]Workspace set to: {config.workspace_root}[/bold green]")
                        agent = CyberAgent(config=config, console=console)
                elif cmd == "/memory":
                    from cyber_agent.memory_engine import get_short_term_memory
                    st_mem = get_short_term_memory()

                    if not arg:
                        # Display Short-Term Working Memory (Default, ultra-fast RAM)
                        st_summary = st_mem.get_summary()
                        content = f"[bold green]⚡ Short-Term Working Memory (Active Session - RAM)[/bold green]\n"
                        content += f"• Active Target: [bold yellow]{st_summary['active_target'] or 'None yet'}[/bold yellow]\n"
                        content += f"• Session Findings: [bold cyan]{st_summary['total_findings']}[/bold cyan]\n"
                        content += f"• Session Actions: [bold magenta]{st_summary['total_actions']}[/bold magenta]\n"
                        content += f"• Latency Mode: [bold green]Fast RAM (0ms overhead, No disk/vector lag)[/bold green]\n\n"

                        if st_summary['findings']:
                            content += "[bold white]Recent Findings in Current Session:[/bold white]\n"
                            for f in st_summary['findings'][-5:]:
                                content += f"  • [[cyan]{f['category']}[/cyan]] {f['content'][:90]}...\n"
                            content += "\n"

                        content += "[dim]Long-Term Memory Commands:[/dim]\n"
                        content += "[dim]• '/memory <search_term>' : Query permanent SQLite + Vector embeddings[/dim]\n"
                        content += "[dim]• '/memory save'          : Flush current session findings into permanent Long-Term SQLite[/dim]\n"
                        content += "[dim]• '/memory long'          : View permanent Long-Term database overview[/dim]\n"
                        content += "[dim]• '/memory clear'         : Clear current short-term session memory[/dim]"
                        console.print(Panel(content, title="[bold blue]🧠 Memory Manager[/bold blue]", border_style="blue"))

                    elif arg.lower() in ["clear", "reset"]:
                        st_mem.clear()
                        console.print("[bold green]🧹 Short-term session memory cleared successfully.[/bold green]")

                    elif arg.lower() in ["save", "sync", "flush"]:
                        from cyber_agent.memory_engine import get_memory_engine
                        mem = get_memory_engine()
                        saved_count = st_mem.sync_to_long_term(mem)
                        console.print(f"[bold green]💾 Successfully committed {saved_count} session findings to permanent Long-Term SQLite memory![/bold green]")

                    elif arg.lower() in ["long", "stats", "overview"]:
                        from cyber_agent.memory_engine import get_memory_engine
                        mem = get_memory_engine()
                        summary = mem.get_overview_summary()
                        console.print(Panel(
                            f"[bold cyan]🧠 Permanent Long-Term Cognitive Memory (SQLite)[/bold cyan]\n"
                            f"• Total Tracked Targets: [bold yellow]{summary['total_targets_tracked']}[/bold yellow]\n"
                            f"• Total Findings Stored: [bold green]{summary['total_findings_stored']}[/bold green]\n"
                            f"• Total Audits Recorded: [bold magenta]{summary['total_audits_executed']}[/bold magenta]\n"
                            f"• Database Path: [dim]{mem.db_path}[/dim]",
                            border_style="magenta"
                        ))

                    else:
                        # Deep Long-Term Recall
                        from cyber_agent.memory_engine import get_memory_engine
                        mem = get_memory_engine()
                        console.print(f"[dim]Searching permanent Long-Term memory for '{arg}' using NLTK Stemming & Vector embeddings...[/dim]")
                        matches = mem.recall(query=arg, top_k=6)
                        if matches:
                            tbl = Table(title=f"Permanent Long-Term Memory Matches for: '{arg}'", border_style="cyan")
                            tbl.add_column("Target", style="bold yellow")
                            tbl.add_column("Category", style="cyan")
                            tbl.add_column("Finding Content", style="white")
                            tbl.add_column("Relevance", style="green")
                            for m in matches:
                                tbl.add_row(m.get("target") or "-", m.get("category"), m.get("content")[:80] + ("..." if len(m.get("content", "")) > 80 else ""), str(m.get("relevance_score")))
                            console.print(tbl)
                        else:
                            console.print(f"[yellow]No permanent memory matches found for '{arg}'.[/yellow]")
                elif cmd == "/dossier":
                    if not arg:
                        console.print("[bold red]Please specify a target, e.g. /dossier demo.testfire.net[/bold red]")
                    else:
                        from cyber_agent.memory_engine import get_memory_engine
                        mem = get_memory_engine()
                        dossier = mem.get_target_dossier(arg)
                        if dossier:
                            tbl = Table(title=f"Security Dossier: {dossier['target']}", border_style="green")
                            tbl.add_column("Property", style="bold cyan")
                            tbl.add_column("Value", style="white")
                            tbl.add_row("First Discovered", dossier.get("first_seen"))
                            tbl.add_row("Last Scanned", dossier.get("last_seen"))
                            tbl.add_row("Latest Score / Grade", f"{dossier.get('latest_score')}/100 (Grade: {dossier.get('latest_grade')})")
                            tbl.add_row("Active WAF", str(dossier.get("waf")))
                            tbl.add_row("Open Ports", ", ".join(map(str, dossier.get("open_ports", []))) or "None")
                            tbl.add_row("Confirmed Vulns", ", ".join(dossier.get("verified_vulnerabilities", [])) or "None")
                            tbl.add_row("Total Findings", str(dossier.get("total_recorded_findings", 0)))
                            tbl.add_row("Notes", dossier.get("notes") or "-")
                            console.print(tbl)
                        else:
                            console.print(f"[yellow]No security dossier found for target '{arg}'.[/yellow]")
                elif cmd == "/browser":
                    from cyber_agent.browser_controller import get_browser_controller
                    bc = get_browser_controller(workspace_root=config.workspace_root)
                    if arg.lower() in ["gui", "visible", "show", "window"]:
                        bc.set_headless(False)
                        console.print("[bold green]🖥️ Browser Mode: VISIBLE GUI WINDOW (Chromium will open live on your screen!)[/bold green]")
                    elif arg.lower() in ["headless", "hide", "silent", "bg"]:
                        bc.set_headless(True)
                        console.print("[bold cyan]🕶️ Browser Mode: HEADLESS (Chromium will run silently in background)[/bold cyan]")
                    elif arg.lower() in ["close", "quit", "exit"]:
                        bc.close()
                        console.print("[bold yellow]Browser session closed.[/bold yellow]")
                    else:
                        mode_str = "HEADLESS (Silent Background)" if bc.headless else "VISIBLE GUI WINDOW (On Desktop)"
                        console.print(Panel(
                            f"[bold cyan]🌐 Autonomous Browser Status[/bold cyan]\n"
                            f"• Current Mode: [bold yellow]{mode_str}[/bold yellow]\n\n"
                            f"[dim]Commands:[/dim]\n"
                            f"• '/browser gui'      : Open real visible Chromium window on your screen\n"
                            f"• '/browser headless' : Run silently in the background (Default)\n"
                            f"• '/browser close'    : Close active browser instance",
                            border_style="blue"
                        ))
                elif cmd == "/browse":
                    if not arg:
                        console.print("[bold red]Please specify a URL to browse, e.g. /browse http://demo.testfire.net[/bold red]\n[dim]Tip: Add '--gui' to watch the browser open on your screen: /browse http://demo.testfire.net --gui[/dim]")
                    else:
                        target_url = arg
                        force_gui = False
                        if "--gui" in target_url or "--visible" in target_url:
                            force_gui = True
                            target_url = target_url.replace("--gui", "").replace("--visible", "").strip()

                        from cyber_agent.browser_controller import get_browser_controller
                        bc = get_browser_controller(workspace_root=config.workspace_root)
                        if force_gui:
                            bc.set_headless(False)

                        mode_label = "VISIBLE GUI WINDOW" if not bc.headless else "Headless (Background)"
                        console.print(f"[dim]Navigating to {target_url} with Playwright Chromium ({mode_label})...[/dim]")
                        nav_res = bc.navigate(target_url)
                        if nav_res.get("success"):
                            tip = "\n\n[dim]💡 Tip: To see the actual browser window open on your screen, run: '/browser gui' or add '--gui'![/dim]" if bc.headless else "\n\n[bold green]🖥️ Live browser window is open on your desktop screen.[/bold green]"
                            console.print(Panel(
                                f"[bold green]🌐 Page Loaded:[/bold green] {nav_res.get('title')}\n"
                                f"[bold white]Final URL:[/bold white] {nav_res.get('final_url')} (Status: {nav_res.get('status_code')})\n\n"
                                f"[bold cyan]Text Preview:[/bold cyan]\n{nav_res.get('content_preview')[:400]}...\n\n"
                                f"[dim]Interactive Elements: {len(nav_res.get('interactive_elements', {}).get('links_sample', []))} links, {len(nav_res.get('interactive_elements', {}).get('inputs', []))} inputs, {len(nav_res.get('interactive_elements', {}).get('buttons', []))} buttons.[/dim]"
                                f"{tip}",
                                title="[bold blue]Autonomous Browser[/bold blue]",
                                border_style="blue"
                            ))
                        else:
                            console.print(f"[bold red]Navigation failed: {nav_res.get('error')}[/bold red]")
                elif cmd == "/screenshot":
                    from cyber_agent.browser_controller import get_browser_controller
                    bc = get_browser_controller(workspace_root=config.workspace_root)
                    ss_res = bc.capture_screenshot(arg if arg else None)
                    if ss_res.get("success"):
                        console.print(f"[bold green]📸 Screenshot captured ({ss_res.get('file_size_kb')} KB): {ss_res.get('screenshot_path')}[/bold green]")
                    else:
                        console.print(f"[bold red]Screenshot capture failed: {ss_res.get('error')}[/bold red]")
                elif cmd in ("/team", "/swarm"):
                    if not arg:
                        console.print("[bold red]Please specify a mission objective, e.g.:[/bold red]")
                        console.print("[dim]/team Audit targetcorp.com, verify SQLi, and generate hardening report[/dim]")
                    else:
                        from cyber_agent.core.orchestrator import SwarmOrchestrator
                        orchestrator = SwarmOrchestrator(config=config, console=console)
                        orchestrator.run_collaborative_mission(arg)
                elif cmd == "/hitl":
                    sub = arg.lower()
                    if not sub or sub == "status":
                        st = agent.hitl.get_status()
                        htbl = Table(title="🛡️ Human-in-the-Loop (HITL) Gatekeeper Status", border_style="cyan")
                        htbl.add_column("Setting", style="bold yellow")
                        htbl.add_column("Value", style="white")
                        htbl.add_row("HITL Gatekeeper", "[bold green]Enabled[/bold green]" if st["enabled"] else "[bold red]Disabled[/bold red]")
                        htbl.add_row("Auto-Approve All", "[bold magenta]Active (Full Autonomous)[/bold magenta]" if st["auto_approve_all"] else "[bold green]Inactive (Safe Mode)[/bold green]")
                        htbl.add_row("Sensitive Tools Requiring Approval", ", ".join(st["sensitive_tools"]))
                        htbl.add_row("Always Allowed (Session Whitelist)", ", ".join(st["always_allowed_tools"]) if st["always_allowed_tools"] else "[dim]None (prompts for each)[/dim]")
                        console.print(htbl)
                        console.print("[dim]Options: /hitl on | /hitl off | /hitl all | /hitl reset[/dim]")
                    elif sub in ("on", "enable"):
                        agent.hitl.set_enabled(True)
                        config.hitl_enabled = True
                        config.save()
                        console.print("[bold green]✔ Human-in-the-Loop ENABLED. Sensitive operations (run_command, write/edit file, exploits) will prompt for your authorization.[/bold green]")
                    elif sub in ("off", "disable"):
                        agent.hitl.set_enabled(False)
                        config.hitl_enabled = False
                        config.save()
                        console.print("[bold yellow]⚡ Human-in-the-Loop DISABLED. Agent will run in full autonomous mode without prompting.[/bold yellow]")
                    elif sub in ("all", "allow-all", "always"):
                        agent.hitl.allow_all()
                        console.print("[bold magenta]🚀 ALL TOOLS are now ALWAYS ALLOWED for the remainder of this session.[/bold magenta]")
                    elif sub == "reset":
                        agent.hitl.reset_always_allowed()
                        console.print("[bold green]✔ Session whitelisted tools and auto-approve flags have been reset.[/bold green]")
                    else:
                        console.print("[yellow]Usage: /hitl [on | off | status | all | reset][/yellow]")
                elif cmd == "/tools":
                    sub = arg.lower().strip()
                    if not sub or sub in ("select", "menu"):
                        interactive_tool_selector(console, agent)
                    elif sub in ("mouse", "gui", "window", "popup"):
                        from cyber_agent.gui_selector import launch_mouse_tool_selector
                        currently_enabled = [td["function"]["name"] for td in agent.get_active_tool_definitions()]
                        all_tools = [td["function"]["name"] for td in agent.all_tool_definitions]
                        selected = launch_mouse_tool_selector(currently_enabled=currently_enabled, all_tools=all_tools)
                        if selected is not None:
                            agent.set_enabled_tools(selected)
                            console.print(f"[bold green]✔ Mouse selection saved! {len(selected)} tools are now active in CyberAgent.[/bold green]")
                        else:
                            console.print("[dim]Mouse selection closed without changes.[/dim]")
                    elif sub in ("all", "full", "select all"):
                        agent.set_enabled_tools(None)
                        console.print(f"[bold green]✔ All {len(agent.all_tool_definitions)} tools are now ACTIVE and enabled.[/bold green]")
                    elif sub in ("none", "clear", "deselect all"):
                        agent.set_enabled_tools(["run_command", "read_file", "write_file"])
                        console.print("[bold yellow]✔ Reset to 3 minimal core tools (run_command, read_file, write_file).[/bold yellow]")
                    elif sub in ("minimal", "fast", "3"):
                        agent.set_enabled_tools(["run_command", "read_file", "write_file"])
                        console.print("[bold green]✔ FAST MINIMAL preset enabled (3 tools active: run_command, read_file, write_file). Super-fast inference![/bold green]")
                    elif sub in ("pentest", "hack"):
                        agent.set_enabled_tools([
                            "crawl_attack_surface", "run_full_pentest_audit", "fuzz_web_endpoints",
                            "verify_target_vulnerability", "audit_login_security", "detect_waf_fingerprint",
                            "audit_account_enumeration", "extract_sensitive_leaks", "audit_form_csrf_security",
                            "probe_service_ports", "audit_php_threats", "enumerate_subdomains",
                            "audit_jwt_security", "generate_security_payload", "lookup_whois_and_ip"
                        ])
                        console.print(f"[bold green]✔ PENTEST preset enabled ({len(agent.get_active_tool_definitions())} offensive tools active).[/bold green]")
                    elif sub in ("search", "web"):
                        agent.set_enabled_tools(["search_internet", "scrape_web_page", "browser_navigate", "crawl_attack_surface", "calculate_datetime", "enumerate_subdomains", "lookup_whois_and_ip"])
                        console.print(f"[bold green]✔ WEB & SEARCH preset enabled ({len(agent.get_active_tool_definitions())} tools active).[/bold green]")
                    elif sub in ("status", "list"):
                        active_count = len(agent.get_active_tool_definitions())
                        total_tools = len(agent.all_tool_definitions)
                        console.print(f"\n[bold cyan]🔧 Active Tools Profile: {active_count}/{total_tools} Tools Enabled[/bold cyan]")
                        console.print("[dim]Commands: '/tools only 1, 2' | '/tools pentest' | '/tools web' | '/tools all'[/dim]")
                    elif sub.startswith("only ") or sub.startswith("set "):
                        target_items = [p.strip() for p in sub.split(maxsplit=1)[1].replace(",", " ").split() if p.strip()]
                        tool_names = [td["function"]["name"] for td in agent.all_tool_definitions]
                        selected = []
                        for item in target_items:
                            if item.isdigit() and 1 <= int(item) <= len(tool_names):
                                selected.append(tool_names[int(item) - 1])
                            else:
                                matches = [t for t in tool_names if item in t]
                                if matches:
                                    selected.extend(matches)
                        if selected:
                            unique_sel = list(set(selected))
                            agent.set_enabled_tools(unique_sel)
                            console.print(f"[bold green]✔ Custom profile active! Only {len(unique_sel)} tools enabled: {', '.join(unique_sel)}[/bold green]")
                        else:
                            console.print("[red]No matching tools found. Usage: /tools only 1, 2 or /tools only search_internet[/red]")
                    elif sub.startswith("on ") or sub.startswith("enable "):
                        target_items = [p.strip() for p in sub.split(maxsplit=1)[1].replace(",", " ").split() if p.strip()]
                        tool_names = [td["function"]["name"] for td in agent.all_tool_definitions]
                        current = set(td["function"]["name"] for td in agent.get_active_tool_definitions())
                        for item in target_items:
                            if item.isdigit() and 1 <= int(item) <= len(tool_names):
                                current.add(tool_names[int(item) - 1])
                            else:
                                for t in tool_names:
                                    if item in t: current.add(t)
                        agent.set_enabled_tools(list(current))
                        console.print(f"[bold green]✔ Enabled tool(s)! Total active now: {len(current)}/36[/bold green]")
                    elif sub.startswith("off ") or sub.startswith("disable "):
                        target_items = [p.strip() for p in sub.split(maxsplit=1)[1].replace(",", " ").split() if p.strip()]
                        tool_names = [td["function"]["name"] for td in agent.all_tool_definitions]
                        current = set(td["function"]["name"] for td in agent.get_active_tool_definitions())
                        for item in target_items:
                            if item.isdigit() and 1 <= int(item) <= len(tool_names):
                                current.discard(tool_names[int(item) - 1])
                            else:
                                for t in tool_names:
                                    if item in t: current.discard(t)
                        agent.set_enabled_tools(list(current))
                        console.print(f"[bold yellow]✔ Disabled tool(s)! Total active now: {len(current)}/36[/bold yellow]")
                    else:
                        console.print("[yellow]Usage: /tools (opens interactive menu) or /tools [only 1, 2 | on <name> | off <name> | all | minimal][/yellow]")
                else:
                    console.print(f"[bold red]Unknown command: {cmd}. Type /help for assistance.[/bold red]")
                continue

            # Run autonomous agentic task
            agent.run_task(user_input)

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow]Session ended.[/bold yellow]")
            break
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")


if __name__ == "__main__":
    main()
