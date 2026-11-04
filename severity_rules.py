"""Manual severity rules for APISCAN (--severity-file).

A rule file is a JSON list. Each rule needs a severity and a reason; the
reason is shown in the report so the adjustment can be justified.

    [
      {"title_contains": "password hash", "endpoint": "GET /api/Users",
       "severity": "Info", "reason": "Value is masked"}
    ]

Matching fields (all optional, all must match): title_contains,
category_contains, endpoint ("METHOD /path", "/path" or "*"; * is a wildcard,
{id} style parameter names are interchangeable).
"""
import fnmatch
import json
import re
from urllib.parse import urlsplit

LEVELS = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Info'}
_ALLOWED = {'title_contains', 'category_contains', 'endpoint', 'severity', 'reason'}
_MAX_RULES = 200

RULES = []
_NOTE = re.compile(r'\[Severity set manually from (.*?) to (\w+): (.*?)\]')


def _restore(item):
    """Recover audit trail for items read back from the database (only the note survives there)."""
    m = _NOTE.search(str(item.get('description') or ''))
    if m:
        item['reported_severity'] = '' if m.group(1) == 'n/a' else m.group(1)
        item['severity_override_reason'] = m.group(3)


def _shape(path):
    path = urlsplit(str(path or '')).path or '/'
    path = '/' + path.lstrip('/')
    return re.sub(r'\{[^}]*\}', '{}', path).rstrip('/').lower() or '/'


def _parse_endpoint(value):
    value = str(value or '*').strip()
    if value == '*':
        return None, '*'
    parts = value.split(None, 1)
    if len(parts) == 2 and parts[0].isalpha():
        return parts[0].upper(), _shape(parts[1]) if '*' not in parts[1] else parts[1].lower()
    return None, _shape(value) if '*' not in value else value.lower()


def load(path):
    """Load and validate a rule file. Raises ValueError on bad input."""
    global RULES
    with open(path, encoding='utf-8') as fh:
        data = json.load(fh)
    if not isinstance(data, list) or not data:
        raise ValueError('severity file must be a non-empty JSON list')
    if len(data) > _MAX_RULES:
        raise ValueError('severity file has more than %d rules' % _MAX_RULES)
    rules = []
    for i, rule in enumerate(data, 1):
        if not isinstance(rule, dict):
            raise ValueError('severity rule %d is not an object' % i)
        unknown = set(rule) - _ALLOWED
        if unknown:
            raise ValueError('severity rule %d has unknown keys: %s' % (i, ', '.join(sorted(unknown))))
        sev = LEVELS.get(str(rule.get('severity', '')).strip().lower())
        if not sev:
            raise ValueError('severity rule %d needs severity Critical/High/Medium/Low/Info' % i)
        reason = str(rule.get('reason') or '').strip()
        if not reason:
            raise ValueError('severity rule %d needs a reason' % i)
        if not (rule.get('title_contains') or rule.get('category_contains') or rule.get('endpoint')):
            raise ValueError('severity rule %d needs title_contains, category_contains or endpoint' % i)
        method, pattern = _parse_endpoint(rule.get('endpoint'))
        rules.append({
            'title': str(rule.get('title_contains') or '').lower(),
            'category': str(rule.get('category_contains') or '').lower(),
            'method': method, 'pattern': pattern, 'severity': sev, 'reason': reason,
        })
    RULES = rules
    return len(rules)


def clear():
    global RULES
    RULES = []


def _item_target(item):
    method = str(item.get('method') or item.get('http_method') or '').upper()
    endpoint = str(item.get('endpoint') or item.get('url') or item.get('path') or '')
    parts = endpoint.split(None, 1)
    if len(parts) == 2 and parts[0].isalpha() and parts[0].isupper():
        method, endpoint = parts[0], parts[1]
    return method, _shape(endpoint)


def _matches(rule, item, method, shape):
    if rule['method'] and rule['method'] != method:
        return False
    if rule['pattern'] != '*' and not fnmatch.fnmatchcase(shape, rule['pattern']):
        return False
    text = ' '.join(str(item.get(k) or '') for k in ('title', 'issue', 'description', 'test_name')).lower()
    if rule['title'] and rule['title'] not in text:
        return False
    cat = ' '.join(str(item.get(k) or '') for k in ('category', 'risk_key', 'audit')).lower()
    if rule['category'] and rule['category'] not in cat:
        return False
    return True


def apply(item):
    """Apply the first matching rule to item in place. No-op without rules."""
    if not RULES or not isinstance(item, dict):
        return item
    method, shape = _item_target(item)
    for rule in RULES:
        if not _matches(rule, item, method, shape):
            continue
        current = str(item.get('severity') or '')
        if current.lower() == rule['severity'].lower():
            _restore(item)
            return item
        new = rule['severity'].lower() if current.islower() else rule['severity']
        if 'reported_severity' not in item:
            item['reported_severity'] = current
        item['severity'] = new
        item['severity_override_reason'] = rule['reason']
        note = '[Severity set manually from %s to %s: %s]' % (
            item['reported_severity'] or 'n/a', rule['severity'], rule['reason'])
        desc = str(item.get('description') or '')
        if note not in desc:
            item['description'] = (desc + ' ' + note).strip()
        return item
    return item


def apply_all(items):
    if not RULES:
        return items
    return [apply(dict(i)) if isinstance(i, dict) else i for i in items]
