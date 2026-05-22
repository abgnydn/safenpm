import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts', 'functions/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts', 'functions/**/*.ts'],
      exclude: ['**/*.test.ts', 'src/cli.ts'],
    },
    reporters: process.env.CI ? ['default'] : ['default'],
    testTimeout: 10_000,
  },
})
