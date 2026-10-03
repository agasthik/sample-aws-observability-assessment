// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  define: {
    'process.env.NODE_ENV': JSON.stringify('production')
  },
  build: {
    outDir: '../observability_assessment/reporting/assets',
    emptyOutDir: true,
    assetsInlineLimit: 20_000_000,
    cssCodeSplit: false,
    lib: {
      entry: 'src/main.tsx',
      name: 'ObservabilityAssessmentReport',
      formats: ['iife'],
      fileName: () => 'report-ui.js',
      cssFileName: 'report-ui'
    }
  }
});
