# v5.15.1
Passbolt 5.15.1 fixes the recent crashes that occurred when using the 5.15 browser extension on video websites.

## Firefox crash on video website

We recently improved our autofill detection to better handle edge cases on modern applications. While this resulted in better overall detection, it unfortunately triggered an unexpected bug in the Firefox ESR version, leading to the recent crashes.

To resolve this, we have reduced the scope of our detection by excluding certain elements, such as video fields, which were causing the issue. If you are using the stable edition of Firefox, you were not impacted by this bug.

## Conclusion
Many thanks for your patience, we are trying to improve Passbolt everyday.

## Changelogs

### Fixed
- PB-54190 - Firefox crash issues [post v5.15.0 release]
