/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { Sun, Moon, Monitor } from 'lucide-react';
import { useInvestigationStore } from '../stores/investigationStore';

const THEME_ICONS: Record<string, React.ReactNode> = {
  light: <Sun className="w-4 h-4" />,
  dark: <Moon className="w-4 h-4" />,
  system: <Monitor className="w-4 h-4" />,
};

export default function ThemeToggle() {
  const theme = useInvestigationStore(s => s.theme);
  const setTheme = useInvestigationStore(s => s.setTheme);

  const cycleTheme = () => {
    if (theme === 'light') setTheme('dark');
    else if (theme === 'dark') setTheme('system');
    else setTheme('light');
  };

  return (
    <button
      onClick={cycleTheme}
      title={`Theme: ${theme}`}
      aria-label={`Switch theme. Current: ${theme}`}
      className="p-2 rounded-lg cursor-pointer border transition-all duration-150"
      style={{
        background: 'var(--bg-panel)',
        borderColor: 'var(--border-default)',
        color: 'var(--text-secondary)',
      }}
    >
      {THEME_ICONS[theme]}
    </button>
  );
}
