# Security Audit Findings

## Findings, prioritized by exploitability × impact

| Priority | Name of untrusted source       | Dangerous sink                               | Source-to-sink trace                                                                               | Payload from `attacks.md`                       |
| -------- | ------------------------------ | -------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| 1        | Fetched settings JSON          | Recursive merge into `Object.prototype`    | Settings text → `JSON.parse` → `deepMerge` → `__proto__` resolves to `Object.prototype` | `{"theme":"dark","__proto__":{"isAdmin":true}}` |
| 2        | URL `?q=` search term        | `innerHTML` in search renderer             | `location.search` → `renderSearch` → concatenated markup → `innerHTML`                    | `<img src=x onerror=alert(1)>`                  |
| 3        | Stored variable -`bio`       | `insertAdjacentHTML` in member renderer    | Stored bio → `renderMembers` → `renderMember` → HTML insertion                              | `<img src=x onerror=alert(2)>`                  |
| 4        | Stored variable - `website` | Profile link `href`                        | Stored website → `renderMember` → anchor `href` without scheme validation                    | `javascript:alert(3)`                           |
| 5        | Stored variable -`name`      | Button inline `onclick`                    | Stored name → `renderMember` → concatenation into JavaScript handler                           | `x') ; alert(4) ; ('`                           |
| 6        | Fetched config text            | Uncaught `JSON.parse` and unchecked fields | Config text → `parseConfig` → `JSON.parse` → unvalidated `title` and `maxItems`         | `{"title":"oops`                                |

## Non-finding

The member `name` heading is rendered with `textContent`, not parsed as HTML.
