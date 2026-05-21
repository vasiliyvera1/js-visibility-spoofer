# JS Visibility Spoofer

A lightweight JavaScript utility for testing focus/visibility detection systems in web applications.

This script can:

* Remove existing `blur`, `focus`, and `visibilitychange` event listeners
* Block new focus-tracking listeners from being registered
* Spoof `document.hasFocus()`
* Override Page Visibility API values
* Neutralize inline focus handlers (`window.onblur`, `window.onfocus`)
* Help debug anti-tab-switching systems and focus-based captchas

Designed for:

* Browser security research
* Frontend testing
* CAPTCHA development
* Focus detection debugging
* DevTools experiments

## Features

* Works directly from DevTools console
* Does not require browser extensions
* Attempts to preserve normal site functionality
* Supports runtime listener cleanup
* Logs removed and blocked listeners

## Example Use Cases

* Testing anti-cheat systems
* Debugging tab visibility logic
* Researching focus detection methods
* Analyzing event listener behavior

## Disclaimer

This project is intended for educational, debugging, and research purposes only.
Use responsibly and only on systems you own or are authorized to test.
