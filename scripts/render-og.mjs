#!/usr/bin/env node
/**
 * Render site/og.svg → site/og.png at 1200x630 (the canonical Open Graph
 * image size, also the Twitter `summary_large_image` size). Sharp does
 * the SVG → PNG conversion using its bundled librsvg, so no headless
 * browser is required.
 *
 * Run after editing og.svg:
 *   npm run render:og
 */
import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import sharp from 'sharp'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SITE = path.join(__dirname, '..', 'site')

const svg = await readFile(path.join(SITE, 'og.svg'))
const png = await sharp(svg, { density: 200 })
  .resize(1200, 630, { fit: 'fill' })
  .png({ compressionLevel: 9 })
  .toBuffer()
await writeFile(path.join(SITE, 'og.png'), png)

console.log(`og.png: ${png.length.toLocaleString()} bytes`)
