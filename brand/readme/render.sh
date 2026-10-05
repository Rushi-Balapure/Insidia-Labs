#!/usr/bin/env bash
# Renders the README artwork in src/ to 2x PNGs. Needs Google Chrome or Chromium.
set -euo pipefail
cd "$(dirname "$0")"
chrome="${CHROME:-$(command -v google-chrome || command -v chromium || command -v chromium-browser)}"

render() {
  local name=$1 width=$2 height=$3
  for theme in dark light; do
    "$chrome" --headless=new --disable-gpu --hide-scrollbars --allow-file-access-from-files \
      --default-background-color=00000000 --force-device-scale-factor=2 \
      --window-size="$width,$height" --screenshot="$PWD/$name-$theme.png" \
      "file://$PWD/src/$name.html?$theme" 2>/dev/null
  done
}

render hero 1280 440
render flow 1280 520
