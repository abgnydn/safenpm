import { ImageResponse } from '@vercel/og'

export const config = { runtime: 'edge' }

export default function handler() {
  return new ImageResponse(
    (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          width: '100%',
          height: '100%',
          background: '#0a0a0f',
          padding: '60px 80px',
          fontFamily: 'system-ui, -apple-system, sans-serif',
          justifyContent: 'center',
        }}
      >
        {/* Top bar */}
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '24px' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(34, 197, 94, 0.15)',
              marginRight: '16px',
              fontSize: '28px',
            }}
          >
            🛡️
          </div>
          <span style={{ color: '#22c55e', fontSize: '32px', fontWeight: 700 }}>safenpm</span>
          <span style={{ color: '#555570', fontSize: '24px', fontWeight: 400, marginLeft: '16px' }}>v0.5.0</span>
        </div>

        {/* Title */}
        <div
          style={{
            fontSize: '56px',
            fontWeight: 800,
            color: '#e4e4ef',
            lineHeight: 1.15,
            letterSpacing: '-1px',
            marginBottom: '24px',
          }}
        >
          Stop supply-chain attacks{' '}
          <span
            style={{
              background: 'linear-gradient(135deg, #22c55e, #06b6d4)',
              backgroundClip: 'text',
              color: 'transparent',
            }}
          >
            before they run
          </span>
        </div>

        {/* Description */}
        <div style={{ fontSize: '24px', color: '#8888a0', lineHeight: 1.5, marginBottom: '40px' }}>
          Sandboxed npm installs with static analysis, typosquat detection, and a decentralized threat intelligence network.
        </div>

        {/* Install command */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            background: '#12121a',
            border: '1px solid #1e1e2e',
            borderRadius: '12px',
            padding: '16px 24px',
            fontSize: '22px',
            fontFamily: 'monospace',
            width: '420px',
          }}
        >
          <span style={{ color: '#555570', marginRight: '12px' }}>$</span>
          <span style={{ color: '#e4e4ef' }}>npm install -g safenpm</span>
        </div>

        {/* Bottom badges */}
        <div style={{ display: 'flex', gap: '16px', marginTop: '40px' }}>
          {['Zero deps', 'TypeScript', 'macOS + Linux + Windows', 'MIT License'].map((badge) => (
            <div
              key={badge}
              style={{
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid #1e1e2e',
                borderRadius: '20px',
                padding: '8px 16px',
                fontSize: '16px',
                color: '#8888a0',
              }}
            >
              {badge}
            </div>
          ))}
        </div>
      </div>
    ),
    { width: 1200, height: 630 }
  )
}
