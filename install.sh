#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
app="joelansec.py"
venv="$here/.venv"

echo "==> Detecting environment..."
if command -v pkg >/dev/null 2>&1; then
  envtype="termux"
  echo "Detected Termux."
elif command -v apt >/dev/null 2>&1; then
  envtype="debian"
  echo "Detected Debian/Ubuntu-like system."
else
  echo "Unsupported environment. Install Python3, pip, and nmap manually."
  exit 1
fi

echo "==> Installing system packages..."
if [ "$envtype" = "termux" ]; then
  pkg update -y
  pkg install -y python git nmap
else
  sudo apt update -y
  sudo apt install -y python3 python3-venv python3-pip git nmap
fi

echo "==> Creating virtual environment..."
if [ "$envtype" = "termux" ]; then
  python -m venv "$venv"
  . "$venv/bin/activate"
  python -m pip install --upgrade pip wheel setuptools
else
  python3 -m venv "$venv"
  . "$venv/bin/activate"
  python -m pip install --upgrade pip wheel setuptools
fi

echo "==> Installing Python dependencies..."
pip install -r "$here/requirements.txt"

echo "==> Creating launcher..."
if [ "$envtype" = "termux" ]; then
  bin_path="$PREFIX/bin/joelansec"
  cat > "$bin_path" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
. "$venv/bin/activate" 2>/dev/null || true
python "$here/$app" "\$@"
EOF
  chmod +x "$bin_path"
  echo "Launcher created: joelansec (in \$PATH)"
else
  mkdir -p "$HOME/.local/bin"
  bin_path="$HOME/.local/bin/joelansec"
  cat > "$bin_path" <<EOF
#!/usr/bin/env bash
. "$venv/bin/activate" 2>/dev/null || true
python "$here/$app" "\$@"
EOF
  chmod +x "$bin_path"
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;; # already in PATH
    *) echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"; echo "Added ~/.local/bin to PATH. Run: source ~/.bashrc";;
  esac
  echo "Launcher created: $bin_path"
fi

echo "==> Done. Start the app with: joelansec"
