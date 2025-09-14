#!/usr/bin/env python3
# JoelanSec — Beginner-friendly security learning toolkit (Termux/Linux)
# By default includes passive recon + a safe, in-scope-only TCP port check.

import sys, json, socket
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path

# UI
try:
    from rich import print
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.text import Text
except Exception:
    print("[red]Missing 'rich'. Install: pip install rich[/red]")
    sys.exit(1)

# Optional deps
try:
    import requests
except Exception:
    requests = None

try:
    import whois as pywhois
except Exception:
    pywhois = None

try:
    import dns.resolver as dnsresolver
except Exception:
    dnsresolver = None

APP_NAME = "JoelanSec"
CONFIG_DIR = Path.home() / ".joelansec"
CONFIG_PATH = CONFIG_DIR / "config.json"
SCOPE_PATH  = CONFIG_DIR / "scope.txt"

console = Console()

def banner():
    title = Text(f"{APP_NAME}", style="bold cyan")
    sub = Text("Beginner-friendly security learning toolkit", style="dim")
    console.print(Panel.fit(Text.assemble(title, "\n", sub), border_style="cyan"))

def ensure_setup():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        console.print(Panel.fit(
            "Use this toolkit ONLY on systems you own or have explicit, written permission to test.\n"
            "Some features are active and require targets to be listed in scope.txt.",
            title="Read me", style="yellow"))
        agreed = Prompt.ask("Type 'I AGREE' to continue", default="")
        if agreed.strip() != "I AGREE":
            console.print("[red]You must type I AGREE to proceed.[/red]")
            sys.exit(1)
        CONFIG_PATH.write_text(json.dumps(
            {"agreed": True, "timestamp": datetime.utcnow().isoformat()+"Z"},
            indent=2))
    if not SCOPE_PATH.exists():
        SCOPE_PATH.write_text(
            "# One authorized target per line.\n"
            "# Use IPv4/IPv6 CIDR (e.g., 192.0.2.0/24) or domains (example.com)\n"
        )

def in_scope(host: str) -> bool:
    try:
        entries = []
        if SCOPE_PATH.exists():
            entries = [l.strip() for l in SCOPE_PATH.read_text().splitlines()
                       if l.strip() and not l.strip().startswith("#")]
        if not entries:
            return False
        host = host.strip()
        # If IP address, check against CIDR ranges
        try:
            ip = ip_address(host)
            for e in entries:
                try:
                    if ip in ip_network(e, strict=False):
                        return True
                except Exception:
                    continue
            return False
        except ValueError:
            # Domain/hostname suffix match
            host = host.lower().rstrip(".")
            for e in entries:
                e = e.lower().rstrip(".")
                if "/" in e:
                    continue
                if host == e or host.endswith("." + e):
                    return True
            return False
    except Exception:
        return False

def wait_key():
    console.print("\n[dim]Press Enter to return to menu...[/dim]")
    try:
        input()
    except KeyboardInterrupt:
        pass

def whois_lookup():
    console.clear(); banner()
    if not pywhois:
        console.print("[red]python-whois not installed. pip install python-whois[/red]")
        return wait_key()
    domain = Prompt.ask("Domain (e.g., example.com)")
    try:
        w = pywhois.whois(domain)
        table = Table(title=f"WHOIS: {domain}", show_lines=True)
        table.add_column("Field", style="cyan"); table.add_column("Value", style="white")
        for key in ["domain_name","registrar","creation_date","expiration_date","name_servers","status","emails"]:
            val = w.get(key)
            if isinstance(val, (list, tuple, set)):
                val = ", ".join(map(str, val))
            table.add_row(key, str(val))
        console.print(table)
    except Exception as e:
        console.print(f"[red]WHOIS error:[/red] {e}")
    wait_key()

def dns_lookup():
    console.clear(); banner()
    if not dnsresolver:
        console.print("[red]dnspython not installed. pip install dnspython[/red]")
        return wait_key()
    domain = Prompt.ask("Domain (e.g., example.com)")
    record_types = ["A","AAAA","MX","TXT","NS","CNAME"]
    table = Table(title=f"DNS records for {domain}", show_lines=True)
    table.add_column("Type", style="cyan"); table.add_column("Answer", style="white")
    try:
        for rtype in record_types:
            try:
                answers = dnsresolver.resolve(domain, rtype, lifetime=5)
                for r in answers:
                    table.add_row(rtype, r.to_text())
            except Exception:
                pass
        console.print(table)
    except Exception as e:
        console.print(f"[red]DNS error:[/red] {e}")
    wait_key()

def http_headers():
    console.clear(); banner()
    if not requests:
        console.print("[red]requests not installed. pip install requests[/red]")
        return wait_key()
    url = Prompt.ask("URL (include http/https)", default="https://example.com")
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        table = Table(title=f"HTTP GET {resp.url}", show_lines=True)
        table.add_column("Header", style="cyan"); table.add_column("Value", style="white")
        for k, v in resp.headers.items():
            table.add_row(k, v)
        console.print(f"Status: [bold]{resp.status_code}[/bold] in {resp.elapsed.total_seconds():.2f}s")
        console.print(table)
        server = resp.headers.get("Server","?")
        powered = resp.headers.get("X-Powered-By","?")
        console.print(f"\n[dim]Server:[/dim] [green]{server}[/green]  [dim]Powered-By:[/dim] [green]{powered}[/green]")
    except Exception as e:
        console.print(f"[red]Request error:[/red] {e}")
    wait_key()

def robots_txt():
    console.clear(); banner()
    if not requests:
        console.print("[red]requests not installed. pip install requests[/red]")
        return wait_key()
    base = Prompt.ask("Site (domain or URL)", default="https://example.com")
    if not base.startswith("http"):
        base = "https://" + base
    url = base.rstrip("/") + "/robots.txt"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            console.print(Panel(resp.text, title=f"robots.txt from {url}", border_style="green"))
        else:
            console.print(f"[yellow]No robots.txt (HTTP {resp.status_code})[/yellow]")
    except Exception as e:
        console.print(f"[red]Fetch error:[/red] {e}")
    wait_key()

def tcp_port_check():
    console.clear(); banner()
    host = Prompt.ask("Target host/IP for TCP port check")
    if not in_scope(host):
        console.print(Panel.fit("Target is not in scope. Add it to ~/.joelansec/scope.txt first.",
                                title="Not authorized", border_style="red"))
        return wait_key()
    ports = [21,22,23,25,53,80,110,139,143,443,445,3389,3306,8080,8443,5900,6379,11211,9000]
    timeout = 0.7
    services = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",
                139:"netbios",143:"imap",443:"https",445:"smb",3389:"rdp",3306:"mysql",
                8080:"http-alt",8443:"https-alt",5900:"vnc",6379:"redis",11211:"memcached",9000:"http-alt"}
    table = Table(title=f"TCP Port check for {host}", show_lines=True)
    table.add_column("Port", style="cyan")
    table.add_column("State", style="white")
    table.add_column("Service (guess)", style="magenta")

    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                state = "[green]open[/green]"
        except Exception:
            state = "[dim]closed/filtered[/dim]"
        table.add_row(str(p), state, services.get(p,"?"))

    console.print(table)
    console.print("[dim]This is a lightweight TCP connect check, not a full scan.[/dim]")
    wait_key()

def menu():
    console.clear(); banner()
    console.print("Pick an option:")
    console.print(" [cyan]1[/cyan] WHOIS lookup (passive)")
    console.print(" [cyan]2[/cyan] DNS records (passive)")
    console.print(" [cyan]3[/cyan] HTTP headers & tech hints (passive)")
    console.print(" [cyan]4[/cyan] robots.txt viewer (passive)")
    console.print(" [cyan]5[/cyan] TCP port check (active; requires scope)")
    console.print(" [cyan]0[/cyan] Exit")
    choice = Prompt.ask("\nChoice", choices=["1","2","3","4","5","0"], default="1")
    if choice == "1": whois_lookup()
    elif choice == "2": dns_lookup()
    elif choice == "3": http_headers()
    elif choice == "4": robots_txt()
    elif choice == "5": tcp_port_check()
    elif choice == "0":
        console.print("Bye!"); sys.exit(0)

def main():
    try:
        ensure_setup()
        while True:
            menu()
    except KeyboardInterrupt:
        console.print("\nGoodbye!"); sys.exit(0)

if __name__ == "__main__":
    main()
