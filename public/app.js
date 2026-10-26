// auto.hacker — register the service worker for offline shell; progressive, optional.
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
