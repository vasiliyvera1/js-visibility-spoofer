(() => {
    const targets = [window, document];

    const events = [
        'blur',
        'focus',
        'visibilitychange',
        'webkitvisibilitychange',
        'pagehide'
    ];

    for (const target of targets) {
        const listeners = getEventListeners(target);
        
        for (const type of events) {
            if (!listeners[type]) continue;

            for (const entry of listeners[type]) {
                target.removeEventListener(
                    type,
                    entry.listener,
                    entry.useCapture
                );

                console.log('removed', type, entry.listener);
            }
        }
    }

    window.onblur = null;
    window.onfocus = null;
    document.onvisibilitychange = null;

    // spoof focus state
    document.hasFocus = () => true;

    Object.defineProperty(document, 'hidden', {
        configurable: true,
        get: () => false
    });

    Object.defineProperty(document, 'visibilityState', {
        configurable: true,
        get: () => 'visible'
    });

    console.log('focus listeners nuked');

})();
