# Insidia Labs brand kit

Built from the logo Rushi approved. This is mark v2 (approved Oct 4, 2026): the hole in the purple bottom tip and the notch in the shield's bottom edge, just below the iris ring, are now filled by extending the neighbouring gradients. The thin band above the lower ring is intentional. The centre glyph is a white capital **I** (a plain bold bar centred in the navy circle). Every file in this kit uses it, and none of them contains the earlier "1".

## Files

### logo/
| File | What it is |
|---|---|
| `insidia-mark.svg` | Master mark, a true vector: traced outlines, fitted gradient fills, circles and ellipses. No embedded bitmaps or fonts. viewBox 2248×1630. |
| `insidia-mark-512.png`, `-1024.png`, `-2048.png` | Transparent PNG exports, named by width in px. |
| `insidia-mark-small.svg` | Simplified small-size variant: shield panel, iris ring, navy circle and I, without the orbital rings, top cap or bottom tip. Square. Use it below about 48 px. |

### lockups/
| File | Use |
|---|---|
| `insidia-labs-horizontal-light.svg` / `.png` | Mark left, wordmark right. Navy text, transparent background. For white or light backgrounds. |
| `insidia-labs-horizontal-dark.svg` / `.png` | White text on an Insidia Navy (#101028) panel. |
| `insidia-labs-horizontal-dark-transparent.svg` / `.png` | White text, transparent background. For placing on the navy site header. |
| `insidia-labs-stacked-light / -dark / -dark-transparent` | Mark above, wordmark centred below. Same three variants as above. |

PNGs come at 1200 and 2400 px wide. The wordmark text is converted to outlines, so the SVGs don't need any installed font.

### favicons/
| File | Notes |
|---|---|
| `favicon.svg` | Simplified variant, for modern browsers. |
| `favicon.ico` | Contains 16, 32 and 48 px. 16 and 32 use the simplified variant; 48 uses the full mark. |
| `favicon-16.png`, `favicon-32.png` | Simplified variant. At 16 px the I is drawn 1.6× wider than in the master so it stays crisp white instead of blurring to grey. |
| `apple-touch-icon.png` | 180 px, full mark on navy. |
| `android-chrome-192.png`, `android-chrome-512.png` | Full mark on navy, inside the maskable safe zone. |
| `site.webmanifest` | Name, icons, and theme/background colour #101028. |

HTML head snippet:
```html
<link rel="icon" href="/favicon.ico" sizes="48x48">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#101028">
```

### colors/
| File | What it is |
|---|---|
| `palette.md` | Every colour with name, hex, RGB, role and how it was measured, plus the brand gradient stops and computed WCAG contrast ratios. |
| `tokens.css` | CSS custom properties, including `--insidia-gradient` (the upper ring's gradient) and `--insidia-gradient-short`. |
| `tailwind.colors.js` | The same colours for Tailwind (`theme.extend.colors.insidia`, plus `backgroundImage`). |
| `palette.png` | Swatch sheet. |

### fonts/
`Sora-SemiBold.ttf` and `Sora-Regular.ttf` are static instances of Sora, cut from the Google Fonts variable font. `OFL.txt` is the SIL Open Font License 1.1. On the website you can load Sora from Google Fonts with weights 400 and 600.

### brand-sheet.png
A one-page overview: the mark on navy and on white, all lockups, the palette, the gradient and the typeface.

## Usage rules
- **Clear space:** leave at least ¼ of the mark's height empty on every side. The lockup files already include it.
- **Minimum size:** use the full mark at 48 px tall or larger on screen (about 12 mm in print). Below that, use `insidia-mark-small.svg`. Keep the horizontal lockup at least 160 px wide and the stacked lockup at least 110 px wide.
- **Gradient:** never recolour, flatten, re-order or swap the gradient. Don't apply effects, outlines or shadows. Don't stretch the mark or rotate it.
- **Centre:** the navy circle and the white I always stay as they are, on both light and dark backgrounds.
- **Wordmark:** "Insidia" is set in Sora SemiBold and "Labs" in Sora Regular, both in one colour (white on dark, #101028 on light). Don't retype it; use the outlined files.
- **Accessibility:** for text, use white or Navy 300 on navy and navy on white. For buttons, use navy text on Orange (6.65:1). White on Orange (2.80:1) fails WCAG. See `colors/palette.md`.

## Trademark
The Insidia Labs name and logo are trademarks of Insidia Labs. They are not covered by the Apache-2.0 license on the rest of this repository. You may use the mark to refer to Insidia Labs. You may not use it in a way that suggests your product or service is Insidia Labs, or as your own logo.
