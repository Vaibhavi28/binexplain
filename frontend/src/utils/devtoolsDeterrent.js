/**
 * DevTools Deterrent utility.
 * Runs a debugger statement in a loop. If DevTools is open, the debugger stops execution,
 * causing a noticeable lag and alerting the user.
 */
export function initDevtoolsDeterrent() {
    const deterrent = () => {
        const start = new Date().getTime();
        // Trigger debugger breakpoint if DevTools is open
        (function() {
            return function(content) {
                Function("debugger")();
            };
        })()();
        const end = new Date().getTime();
        if (end - start > 100) {
            console.clear();
            console.log(
                '%cWARNING: DevTools detection active. Please do not inspect the app in production.',
                'color: #ff3333; font-size: 16px; font-weight: bold; background: #111; padding: 10px; border-radius: 5px;'
            );
        }
    };

    if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
        setInterval(deterrent, 1000);
    }
}
