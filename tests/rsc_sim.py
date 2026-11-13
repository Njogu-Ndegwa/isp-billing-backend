"""A tiny RouterOS-script runner for setup-script (.rsc) unit tests.

It runs the handful of constructs the provisioning steps under test use, over
an in-memory config, so a test can say "this router already has bitwave-api
with another password -- what does it have after the script ran?" instead of
only grepping the generated text:

* ``:do { ... } on-error={ ... }``
* ``:if ([:len [/menu find where ...]] = 0|> 0) do={ ... } else={ ... }``
* ``:log <level> "..."``
* ``/menu add k=v ...``, ``/menu set [find where ...] k=v ...``,
  ``/menu set k=v ...`` (singleton menus such as ``/system identity``),
  ``/menu remove [find where ...]``
* ``find where`` with ``k=v`` / ``k!=v`` terms joined by ``and``

Errors behave like RouterOS: an ``add`` that duplicates a unique key fails
("already have ..."), and the failure is swallowed by the nearest
``on-error``. Anything else raises ``NotImplementedError`` so a test never
passes by accident on syntax the runner does not understand.

Menus are keyed by their CLI path with spaces (``"/user"``,
``"/ip address"``, ``"/interface bridge"``).
"""

from __future__ import annotations

import copy
import re

# Unique keys per menu: an add that repeats one fails, as on a real router.
UNIQUE = {
    "/user": ("name",),
    "/interface bridge": ("name",),
    "/ip address": ("address", "interface"),
}
SINGLETONS = {"/system identity"}


class RouterOSError(Exception):
    pass


class RscSim:
    def __init__(self, menus=None):
        self.menus = copy.deepcopy(menus or {})
        self.logs: list[tuple[str, str]] = []
        self._n = 0

    # -- public ---------------------------------------------------------
    def run(self, script: str) -> "RscSim":
        self._block(self._strip_comments(script))
        return self

    def rows(self, menu: str) -> list[dict]:
        return self.menus.get(menu, [])

    # -- parsing helpers ------------------------------------------------
    @staticmethod
    def _strip_comments(script: str) -> str:
        return "\n".join("" if l.strip().startswith("#") else l for l in script.splitlines())

    @staticmethod
    def _matching(text: str, i: int, open_ch: str, close_ch: str) -> int:
        """Index of the bracket closing the one at text[i] (quotes respected)."""
        depth, quoted = 0, False
        for j in range(i, len(text)):
            ch = text[j]
            if ch == '"' and text[j - 1] != "\\":
                quoted = not quoted
            elif not quoted and ch == open_ch:
                depth += 1
            elif not quoted and ch == close_ch:
                depth -= 1
                if depth == 0:
                    return j
        raise NotImplementedError(f"unbalanced {open_ch} at {text[i:i + 40]!r}")

    def _brace_body(self, text: str, i: int) -> tuple[str, int]:
        i = self._skip_ws(text, i)
        if text[i] != "{":
            raise NotImplementedError(f"expected '{{' at {text[i:i + 40]!r}")
        end = self._matching(text, i, "{", "}")
        return text[i + 1:end], end + 1

    @staticmethod
    def _skip_ws(text: str, i: int) -> int:
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        return i

    def _line_end(self, text: str, i: int) -> int:
        """End of a one-line command (brackets/quotes may not span lines here)."""
        j = text.find("\n", i)
        return len(text) if j < 0 else j

    # -- execution ------------------------------------------------------
    def _block(self, text: str) -> None:
        i = self._skip_ws(text, 0)
        while i < len(text):
            if text.startswith(":do", i):
                body, i = self._brace_body(text, i + 3)
                i = self._skip_ws(text, i)
                handler = None
                if text.startswith("on-error=", i):
                    handler, i = self._brace_body(text, i + len("on-error="))
                try:
                    self._block(body)
                except RouterOSError:
                    if handler is not None:
                        self._block(handler)
            elif text.startswith(":if", i):
                i = self._skip_ws(text, i + 3)
                if text[i] != "(":
                    raise NotImplementedError(text[i:i + 40])
                end = self._matching(text, i, "(", ")")
                cond = self._cond(text[i + 1:end])
                i = self._skip_ws(text, end + 1)
                if not text.startswith("do=", i):
                    raise NotImplementedError(text[i:i + 40])
                then, i = self._brace_body(text, i + 3)
                i = self._skip_ws(text, i)
                other = None
                if text.startswith("else=", i):
                    other, i = self._brace_body(text, i + 5)
                if cond:
                    self._block(then)
                elif other is not None:
                    self._block(other)
            elif text.startswith(":log", i):
                end = self._line_end(text, i)
                m = re.match(r':log\s+(\w+)\s+"(.*)"\s*$', text[i:end])
                if not m:
                    raise NotImplementedError(text[i:end])
                self.logs.append((m.group(1), m.group(2)))
                i = end
            elif text[i] == "/":
                end = self._line_end(text, i)
                self._command(text[i:end].strip())
                i = end
            else:
                raise NotImplementedError(f"unsupported statement {text[i:i + 60]!r}")
            i = self._skip_ws(text, i)

    def _cond(self, cond: str) -> bool:
        m = re.fullmatch(r"\s*\[:len \[(/[a-z ]+?) find where (.+)\]\]\s*(=|>)\s*0\s*", cond)
        if not m:
            raise NotImplementedError(f"unsupported condition {cond!r}")
        n = len(self._find(m.group(1), m.group(2)))
        return n == 0 if m.group(3) == "=" else n > 0

    @staticmethod
    def _pairs(text: str) -> dict:
        out = {}
        for m in re.finditer(r'([a-z-]+)=("(?:[^"\\]|\\.)*"|\S+)', text):
            v = m.group(2)
            out[m.group(1)] = v[1:-1] if v.startswith('"') else v
        return out

    def _find(self, menu: str, where: str) -> list[dict]:
        terms = []
        for term in where.split(" and "):
            m = re.fullmatch(r'\s*([a-z-]+)(!=|=)("(?:[^"\\]|\\.)*"|\S+)\s*', term)
            if not m:
                raise NotImplementedError(f"unsupported find term {term!r}")
            v = m.group(3)
            terms.append((m.group(1), m.group(2), v[1:-1] if v.startswith('"') else v))
        rows = self.menus.setdefault(menu, [])
        return [r for r in rows
                if all((str(r.get(k, "")) == v) == (op == "=") for k, op, v in terms)]

    def _command(self, line: str) -> None:
        m = re.match(r"(/[a-z ]+?) (add|set|remove)\b(.*)$", line)
        if not m:
            raise NotImplementedError(f"unsupported command {line!r}")
        menu, verb, rest = m.group(1).strip(), m.group(2), m.group(3).strip()
        rows = self.menus.setdefault(menu, [])
        target = None
        f = re.match(r"\[find where (.+?)\]\s*(.*)$", rest)
        if f:
            target = self._find(menu, f.group(1))
            rest = f.group(2)
        if verb == "add":
            row = {"disabled": "no", **self._pairs(rest)}
            keys = UNIQUE.get(menu, ())
            if keys and any(all(r.get(k) == row.get(k) for k in keys) for r in rows):
                raise RouterOSError(f"failure: already have such entry in {menu}")
            self._n += 1
            rows.append({".id": f"*{self._n:X}", **row})
        elif verb == "set":
            values = self._pairs(rest)
            if target is None:
                if menu not in SINGLETONS:
                    raise NotImplementedError(f"set without [find] on {menu}")
                if not rows:
                    rows.append({})
                target = rows[:1]
            if not target and menu not in SINGLETONS:
                return  # set on an empty find: a no-op on RouterOS
            for r in target:
                r.update(values)
        else:  # remove
            if target is None:
                raise NotImplementedError(f"remove without [find] on {menu}")
            ids = {id(r) for r in target}
            self.menus[menu] = [r for r in rows if id(r) not in ids]
