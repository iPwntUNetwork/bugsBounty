#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${HOME}/.local/bin"
mkdir -p "$BIN"
printf '#!/usr/bin/env bash\nexport PYTHONPATH="%s:$PYTHONPATH"\nexec python3 "%s/bugsBounty.py" "$@"\n' "$DIR" "$DIR" > "$BIN/bugsBounty"
chmod +x "$BIN/bugsBounty"
echo "Installed bugsBounty -> $BIN/bugsBounty"
