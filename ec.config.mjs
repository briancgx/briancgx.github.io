/**
 * Expressive Code configuration — "Agentic Red Team Ops" dark theme.
 * Terminal frames + copy button come from Expressive Code defaults; we only
 * tune the palette so code blocks sit inside the site's surface tokens.
 */
export const ecConfig = {
  themes: ['github-dark'],
  styleOverrides: {
    borderRadius: '0.5rem',
    borderColor: '#1e2836',
    codeFontFamily:
      "'JetBrains Mono Variable', ui-monospace, SFMono-Regular, Menlo, monospace",
    codeFontSize: '0.85rem',
    frames: {
      editorTabBarBackground: '#10151f',
      editorActiveTabBackground: '#141b28',
      editorActiveTabIndicatorTopColor: '#22d3ee',
      editorActiveTabForeground: '#cdd7e5',
      terminalTitlebarBackground: '#10151f',
      terminalTitlebarForeground: '#cdd7e5',
      terminalTitlebarDotsForeground: '#7688a0',
      terminalBackground: '#0d121b',
      frameBoxShadowCssValue: 'none',
    },
    codeBackground: '#0d121b',
    scrollbarThumbColor: '#1e2836',
  },
};

export default ecConfig;
