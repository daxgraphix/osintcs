/**
 * Runtime anti-tampering and browser inspection deterrents.
 */

export function initSecurityMonitor() {
  if (typeof window === 'undefined') return;

  const DEVTOOLS_CODE = /xterm|console\.table|debugger|inspect|devtools/i;
  const RESIZE_THRESHOLD = 160;
  let devtoolsOpen = false;
  let lastWidth = window.outerWidth;
  let lastHeight = window.outerHeight;
  let intervalId: number | null = null;

  function checkDevTools() {
    const widthThreshold = window.outerWidth - window.innerWidth > RESIZE_THRESHOLD;
    const heightThreshold = window.outerHeight - window.innerHeight > RESIZE_THRESHOLD;

    if (widthThreshold || heightThreshold) {
      if (!devtoolsOpen) {
        devtoolsOpen = true;
        document.body.style.setProperty('filter', 'blur(6px)');
        document.body.style.setProperty('pointer-events', 'none');
        document.body.style.setProperty('user-select', 'none');
      }
    } else {
      if (devtoolsOpen) {
        devtoolsOpen = false;
        document.body.style.removeProperty('filter');
        document.body.style.removeProperty('pointer-events');
        document.body.style.removeProperty('user-select');
      }
    }
  }

  function detectConsoleOpen() {
    const prev = { error: console.error, warn: console.warn, log: console.log };
    console.error = (...args: any[]) => {
      if (args.some((arg) => typeof arg === 'string' && DEVTOOLS_CODE.test(arg))) {
        document.body.style.setProperty('filter', 'blur(4px)');
        setTimeout(() => document.body.style.removeProperty('filter'), 800);
      }
      prev.error.apply(console, args);
    };
    console.warn = (...args: any[]) => {
      if (args.some((arg) => typeof arg === 'string' && DEVTOOLS_CODE.test(arg))) {
        document.body.style.setProperty('filter', 'blur(4px)');
        setTimeout(() => document.body.style.removeProperty('filter'), 800);
      }
      prev.warn.apply(console, args);
    };
    console.log = (...args: any[]) => {
      if (args.some((arg) => typeof arg === 'string' && DEVTOOLS_CODE.test(arg))) {
        document.body.style.setProperty('filter', 'blur(4px)');
        setTimeout(() => document.body.style.removeProperty('filter'), 800);
      }
      prev.log.apply(console, args);
    };
  }

  function start() {
    detectConsoleOpen();
    intervalId = window.setInterval(() => {
      lastWidth = window.outerWidth;
      lastHeight = window.outerHeight;
      checkDevTools();
    }, 500);
  }

  function stop() {
    if (intervalId !== null) {
      clearInterval(intervalId);
      intervalId = null;
    }
    document.body.style.removeProperty('filter');
    document.body.style.removeProperty('pointer-events');
    document.body.style.removeProperty('user-select');
  }

  start();

  return stop;
}
