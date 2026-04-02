import type { VercelRequest, VercelResponse } from '@vercel/node'
import fs from 'fs'
import path from 'path'

export default function handler(_req: VercelRequest, res: VercelResponse) {
  // Serve the static SVG with image headers
  // Most modern social platforms (LinkedIn, Twitter) now support SVG OG images
  // For maximum compatibility, convert to PNG and replace this endpoint
  const svgPath = path.join(process.cwd(), 'site', 'og.svg')
  const svg = fs.readFileSync(svgPath, 'utf8')

  res.setHeader('Content-Type', 'image/svg+xml')
  res.setHeader('Cache-Control', 'public, max-age=86400, s-maxage=86400')
  res.status(200).send(svg)
}
