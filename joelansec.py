#!/usr/bin/env python3
# JoelanSec — Beginner-friendly security learning toolkit (Termux/Linux)
# Passive recon + safe, in-scope-only active checks. Now with auto-save,
# results viewer, and an nmap wrapper that respects scope.txt.

import sys, json, socket, subprocess, shutil, re
from datetime import datetime
from ipaddress import ip_address, ip_network, ip_interface
from pathlib import Path

# UI
try:
    from rich import print
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
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
RESULTS_DIR = CONFIG_DIR / "results"

console = Console()
CONFIG = {"agreed": False, "auto_save": True}

def banner():
    title = Text(f"{APP_NAME}", style="bold cyan")
    sub = Text("Beginner-friendly security learning toolkit", style="dim")
    console.print(Panel.fit(Text.assemble(title, "\n", sub), border_style="cyan"))

def load_config():
    global CONFIG
    if CONFIG_PATH.exists():
        try:
            CONFIG.update(json.loads(CONFIG_PATH.read_text()))
        except Exception:
            pass
    # defaults
    CONFIG.setdefault("auto_save", True)
    return CONFIG

def save_config():
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(CONFIG, indent=2))
    except Exception as e:
        console.print(f"[red]Failed to save config:[/red] {e}")

def ensure_setup():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    load_config()
    if not CONFIG.get("agreed"):
        console.print(Panel.fit(
            "Use this toolkit ONLY on systems you own or have explicit, written permission to test.\n"
            "Active features require targets to be listed in scope.txt.",
            title="Read me", style="yellow"))
        agreed = Prompt.ask("Type 'I AGREE' to continue", default="")
        if agreed.strip() != "I AGREE":
            console.print("[red]You must type I AGREE to proceed.[/red]")
            sys.exit(1)
        CONFIG["agreed"] = True
        CONFIG["agreed_at"] = datetime.utcnow().isoformat()+"Z"
        save_config()
    if not SCOPE_PATH.exists():
        SCOPE_PATH.write_text(
            "# One authorized target per line.\n"
            "# Use IPv4/IPv6 CIDR (e.g., 192.168.1.0/24) or domains (example.com)\n"
        )

def slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r'^[a-z]+://', '', s)  # remove scheme if present
    s = s.replace('/', '-')
    return re.sub(r'[^a-z0-9._-]+', '-', s)[:80] or "target"

def save_result(kind: str, target: str, content: str, meta: dict | None = None, ext: str = "txt"):
    try:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        slug = slugify(target or "na")
        base = f"{ts}_{kind}_{slug}"
        txt_path = RESULTS_DIR / f"{base}.{ext}"
        meta_path = RESULTS_DIR / f"{base}.json"
        txt_path.write_text(content if isinstance(content, str) else str(content))
        meta_data = {"kind": kind, "target": target, "timestamp": ts, "file": str(txt_path)}
        if meta:
            meta_data.update(meta)
        meta_path.write_text(json.dumps(meta_data, indent=2))
        console.print(f"[green]Saved:[/green] {txt_path}")
    except Exception as e:
        console.print(f"[red]Save failed:[/red] {e}")

def maybe_save(kind: str, target: str, content: str, meta: dict | None = None, ext: str = "txt"):
    auto = CONFIG.get("auto_save", True)
    if auto:
        save_result(kind, target, content, meta, ext)
    else:
        do = Confirm.ask("Save these results to file?", default=False)
        if do:
            save_result(kind, target, content, meta, ext)

def in_scope(host: str) -> bool:
    try:
        entries = []
        if SCOPE_PATH.exists():
            entries = [l.strip() for l in SCOPE_PATH.read_text().splitlines()
                       if l.strip() and not l.strip().startswith("#")]
        if not entries:
            return False
        host = host.strip()
        # If IP address
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
        with console.capture() as cap:
            console.print(table)
        out = cap.get()
        console.print(out)
        maybe_save("whois", domain, out, meta={"fields": ["domain_name","registrar","creation_date","expiration_date","name_servers","status","emails"]})
    except Exception as e:
        console.print(f("[red]WHOIS error:[/red] {e}"))
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
    errors = []
    try:
        for rtype in record_types:
            try:
                answers = dnsresolver.resolve(domain, rtype, lifetime=5)
                for r in answers:
                    table.add_row(rtype, r.to_text())
            except Exception as ex:
                errors.append((rtype, str(ex)))
        with console.capture() as cap:
            console.print(table)
        out = cap.get()
        console.print(out)
        maybe_save("dns", domain, out, meta={"types": record_types, "errors": errors})
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
        with console.capture() as cap:
            console.print(f"Status: [bold]{resp.status_code}[/bold] in {resp.elapsed.total_seconds():.2f}s")
            console.print(table)
            server = resp.headers.get("Server","?")
            powered = resp.headers.get("X-Powered-By","?")
            console.print(f"\n[dim]Server:[/dim] [green]{server}[/green]  [dim]Powered-By:[/dim] [green]{powered}[/green]")
        out = cap.get()
        console.print(out)
        meta = {"status": resp.status_code, "final_url": resp.url, "elapsed_s": resp.elapsed.total_seconds()}
        maybe_save("http_headers", url, out, meta=meta)
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
            with console.capture() as cap:
                console.print(Panel(resp.text, title=f"robots.txt from {url}", border_style="green"))
            out = cap.get()
            console.print(out)
            maybe_save("robots", url, out, meta={"status": resp.status_code})
        else:
            msg = f"No robots.txt (HTTP {resp.status_code}) from {url}"
            console.print(f"[yellow]{msg}[/yellow]")
            maybe_save("robots", url, msg + "\n", meta={"status": resp.status_code})
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

    with console.capture() as cap:
        console.print(table)
        console.print("[dim]This is a lightweight TCP connect check, not a full scan.[/dim]")
    out = cap.get()
    console.print(out)
    maybe_save("tcp_check", host, out, meta={"ports": ports})
    wait_key()

def nmap_scan():
    console.clear(); banner()
    if shutil.which("nmap") is None:
        console.print("[red]nmap not found.[/red] Install it:\n- Termux: pkg install nmap\n- Debian/Ubuntu: sudo apt install nmap")
        return wait_key()
    target = Prompt.ask("Target (host/IP/domain)")
    if not in_scope(target):
        console.print(Panel.fit("Target is not in scope. Add it to ~/.joelansec/scope.txt first.",
                                title="Not authorized", border_style="red"))
        return wait_key()
    console.print("Profiles:")
    console.print("  [cyan]1[/cyan] Quick service scan (top 1000 ports, -sV)")
    console.print("  [cyan]2[/cyan] Custom ports (comma-separated, e.g., 22,80,443)")
    prof = Prompt.ask("Choose", choices=["1","2"], default="1")
    ports = None
    if prof == "2":
        ports = Prompt.ask("Ports (comma-separated, e.g., 22,80,443)", default="22,80,443").strip()

    args = ["nmap", "-sV", "--reason", "-T4"]
    if ports:
        args += ["-p", ports]
    args.append(target)

    console.print(f"[dim]Running:[/dim] {' '.join(args)}")
    try:
        with console.status("Scanning... this may take a bit"):
            proc = subprocess.run(args, capture_output=True, text=True, timeout=900)
        out = proc.stdout or ""
        err = proc.stderr or ""
        if proc.returncode not in (0, 1):  # nmap returns 1 for some host-down cases
            console.print(f"[yellow]nmap exited with code {proc.returncode}[/yellow]")
        content = out if out.strip() else err
        if not content.strip():
            content = "(no output)"
        console.print(Panel.fit(content, title="nmap output", border_style="blue"))
        maybe_save("nmap", target, content, meta={"cmd": " ".join(args), "returncode": proc.returncode})
    except subprocess.TimeoutExpired:
        console.print("[red]nmap timed out[/red]")
    except Exception as e:
        console.print(f"[red]nmap error:[/red] {e}")
    wait_key()

def view_saved_results():
    console.clear(); banner()
    files = sorted(RESULTS_DIR.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        console.print("[yellow]No saved results yet.[/yellow]")
        return wait_key()
    console.print("Saved results (newest first):")
    for i, f in enumerate(files[:50], 1):
        console.print(f" [cyan]{i:2}[/cyan] {f.name}")
    pick = Prompt.ask("Enter number to view (or 0 to return)", default="0")
    try:
        idx = int(pick)
        if idx <= 0:
            return
        f = files[idx-1]
        text = f.read_text(errors="ignore")
        console.print(Panel.fit(text, title=f.name, border_style="green"))
    except Exception as e:
        console.print(f"[red]Invalid selection:[/red] {e}")
    wait_key()

def toggle_auto_save():
    CONFIG["auto_save"] = not CONFIG.get("auto_save", True)
    save_config()
    state = "ON" if CONFIG["auto_save"] else "OFF"
    console.print(f"Auto-save is now [bold]{state}[/bold].")
    wait_key()

def menu():
    console.clear(); banner()
    state = "ON" if CONFIG.get("auto_save", True) else "OFF"
    console.print("Pick an option:")
    console.print(" [cyan]1[/cyan] WHOIS lookup (passive)")
    console.print(" [cyan]2[/cyan] DNS records (passive)")
    console.print(" [cyan]3[/cyan] HTTP headers & tech hints (passive)")
    console.print(" [cyan]4[/cyan] robots.txt viewer (passive)")
    console.print(" [cyan]5[/cyan] TCP port check (active; requires scope)")
    console.print(" [cyan]6[/cyan] nmap scan (active; requires scope)")
    console.print(" [cyan]7[/cyan] View saved results")
    console.print(f" [cyan]8[/cyan] Toggle auto-save (currently {state})")
    console.print(" [cyan]0[/cyan] Exit")
    choice = Prompt.ask("\nChoice", choices=["1","2","3","4","5","6","7","8","0"], default="1")
    if choice == "1": whois_lookup()
    elif choice == "2": dns_lookup()
    elif choice == "3": http_headers()
    elif choice == "4": robots_txt()
    elif choice == "5": tcp_port_check()
    elif choice == "6": nmap_scan()
    elif choice == "7": view_saved_results()
    elif choice == "8": toggle_auto_save()
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
