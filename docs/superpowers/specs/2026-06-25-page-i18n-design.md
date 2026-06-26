# Page I18n Design

## Goal

Add English and Simplified Chinese support for MobSF Web pages, with a visible dropdown language switcher. API responses, logs, scan engine messages, and generated reports are out of scope for this phase.

## Approach

Use Django's built-in internationalization stack:

- `LocaleMiddleware` activates the language from session/cookie/request.
- `django.views.i18n.set_language` handles language switching and redirects back to the current page.
- Templates use `{% trans %}` and `{% blocktrans %}` for page-visible strings.
- Translation resources live under `mobsf/locale/zh_Hans/LC_MESSAGES/`.

This keeps the implementation aligned with Django conventions and allows later page coverage to be added by marking more template strings.

## Scope

The first implementation covers the primary Web workflow:

- Base layout title language metadata, footer, and version label.
- Top navigation, search placeholder, user dropdown, and language switcher.
- Login page.
- Home upload page and upload-related visible JavaScript messages.
- Recent scans page headings, table labels, pagination labels, and common actions.

The implementation does not translate:

- REST API JSON.
- Backend logs.
- Static/dynamic analyzer internal findings.
- PDF report content.
- Deep analysis result templates beyond the main navigation/layout shell.

## Data Flow

The language dropdown posts to `/i18n/setlang/` with:

- `language`: `en` or `zh-hans`
- `next`: current page path
- CSRF token

Django stores the selected language in the session/cookie. `LocaleMiddleware` activates that language for subsequent requests, and the template translation tags render the matching strings.

## Error Handling

Unsupported language values are rejected by Django's `set_language` view and fall back to the current/default language. If a string is not translated yet, Django renders the original English string.

## Testing

Add a lightweight Django test suite that verifies:

- Login page defaults to English.
- Posting to `set_language` switches to Simplified Chinese.
- Chinese navigation/login strings render after the switch.
- Posting back to English restores English text.
