/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,ts,tsx,md,mdx}'],
  darkMode: 'class', // site is dark-only; <html> carries the `dark` class.
  theme: {
    extend: {
      colors: {
        // "Agentic Red Team Ops" design tokens.
        bg: '#0a0e14',
        surface: '#10151f',
        surface2: '#141b28',
        border: '#1e2836',
        text: '#cdd7e5',
        muted: '#7688a0',
        // Offensive accent (red ops): difficulties, badges, CTAs.
        ops: {
          DEFAULT: '#ff3b3b',
          dim: '#c72e2e',
        },
        // Agentic accent (cyan AI): states, telemetry, links.
        ai: {
          DEFAULT: '#22d3ee',
          dim: '#0e9fb8',
        },
      },
      fontFamily: {
        mono: [
          'JetBrains Mono Variable',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'monospace',
        ],
        sans: ['Inter Variable', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
      maxWidth: {
        content: '72rem',
        prose: '46rem',
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        'fade-in': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        blink: 'blink 1s step-end infinite',
        'fade-in': 'fade-in 0.3s ease-out both',
      },
    },
  },
  plugins: [],
};
