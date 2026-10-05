# Insidia Labs colour kit

All brand colours were measured from the logo file with code (`work/colors.py`): k-means clustering (k=9) on the logo's coloured pixels (navy centre circle and anti-aliased edges excluded), plus the brightest and darkest 0.5% of pixels for the end stops. The navy is the median of the original background and the centre circle (they match exactly). The neutrals at the bottom are **derived** from the navy (same hue, different lightness), not sampled, and are intended for website UI.

## Brand colours (sampled)

| Name | Hex | RGB | Role | How it was measured |
|---|---|---|---|---|
| Insidia Navy | `#101028` | (16, 16, 40) | Primary background; centre circle | median of original background and of the centre circle |
| White | `#FFFFFF` | (255, 255, 255) | Centre "I"; text on navy | median of the centre glyph |
| Sunburst | `#F6C13F` | (246, 193, 63) | Brightest highlight / gradient start (shield top-right) | brightest 0.5% of logo pixels |
| Amber | `#F4AF3C` | (244, 175, 60) | Gradient stop | k-means cluster (8.1% of logo pixels) |
| Tangerine | `#F09437` | (240, 148, 55) | Gradient stop | k-means cluster (13.1%) |
| Orange | `#ED7B39` | (237, 123, 57) | Primary accent (largest colour area) | k-means cluster (19.1%) |
| Coral | `#EA654D` | (234, 101, 77) | Gradient stop | k-means cluster (12.7%) |
| Rose | `#E95169` | (233, 81, 105) | Gradient stop | k-means cluster (11.3%) |
| Magenta | `#E33D86` | (227, 61, 134) | Secondary accent | k-means cluster (13.0%) |
| Berry | `#B93486` | (185, 52, 134) | Gradient stop | k-means cluster (8.3%) |
| Plum | `#8D307C` | (141, 48, 124) | Gradient stop | k-means cluster (9.5%) |
| Deep Purple | `#542970` | (84, 41, 112) | Gradient end / shadows | k-means cluster (4.8%) |
| Indigo Shadow | `#35225B` | (53, 34, 91) | Darkest stop (facet shadow by the circle) | darkest 0.5% of interior logo pixels |

## Website neutrals (derived from Insidia Navy)

| Name | Hex | RGB | Role | Derivation |
|---|---|---|---|---|
| Navy 800 (surface) | `#181839` | (24, 24, 57) | Cards / raised surfaces on navy | navy hue 240°, lightness 16%, saturation 40% |
| Navy 700 (border) | `#2E2E56` | (46, 46, 86) | Borders, dividers on navy | navy hue, L 26%, S 30% |
| Navy 300 (muted text) | `#B2B2D1` | (178, 178, 209) | Secondary text on navy | navy hue, L 76%, S 25% |
| Navy 600 (text on light) | `#454573` | (69, 69, 115) | Secondary text on white | navy hue, L 36%, S 25% |
| Navy 50 (light surface) | `#F6F6FB` | (246, 246, 251) | Light-mode page background | navy hue, L 97.5%, S 35% |

## Brand gradient

The upper orbital ring's gradient, fitted from the logo pixels (top to bottom):

| Offset | Colour |
|---|---|
| 0% | `#F2A239` |
| 14% | `#EF8636` |
| 29% | `#EC6F42` |
| 43% | `#EA5562` |
| 57% | `#E73E86` |
| 71% | `#D0378A` |
| 86% | `#B23385` |
| 100% | `#953080` |

CSS: see `tokens.css` (`--insidia-gradient`). A shorter gradient for buttons or hero accents uses the sampled stops Sunburst, Orange, Magenta and Deep Purple (`--insidia-gradient-short`).

## WCAG 2.x contrast (computed)

| Foreground | Background | Ratio | Result |
|---|---|---|---|
| White `#FFFFFF` | Insidia Navy `#101028` | 18.64:1 | AAA |
| Navy 300 (muted text) `#B2B2D1` | Insidia Navy `#101028` | 9.04:1 | AAA |
| White `#FFFFFF` | Navy 800 (surface) `#181839` | 17.09:1 | AAA |
| Orange `#ED7B39` | Insidia Navy `#101028` | 6.65:1 | AA |
| Sunburst `#F6C13F` | Insidia Navy `#101028` | 11.20:1 | AAA |
| Magenta `#E33D86` | Insidia Navy `#101028` | 4.68:1 | AA |
| Insidia Navy `#101028` | White `#FFFFFF` | 18.64:1 | AAA |
| Navy 600 (text on light) `#454573` | White `#FFFFFF` | 8.93:1 | AAA |
| Insidia Navy `#101028` | Navy 50 (light surface) `#F6F6FB` | 17.30:1 | AAA |
| Insidia Navy `#101028` | Orange `#ED7B39` | 6.65:1 | AA |
| White `#FFFFFF` | Orange `#ED7B39` | 2.80:1 | Fail |
| White `#FFFFFF` | Magenta `#E33D86` | 3.98:1 | AA large text / UI only |
| Orange `#ED7B39` | White `#FFFFFF` | 2.80:1 | Fail |

Notes: AA body text needs 4.5:1, AAA needs 7:1, and large text (24px+, or 18.66px+ bold) or UI components need 3:1. For buttons, use navy text on Orange; white on Orange or Magenta is below 4.5:1.
