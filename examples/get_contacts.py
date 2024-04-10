#!/usr/bin/env python3

from __future__ import annotations

from typing import Any

from pylookyloo import Lookyloo

lookyloo = Lookyloo()

details: dict[str, Any]
details = lookyloo.get_takedown_information('uuid')
details = lookyloo.get_takedown_information('uuid', False)
emails: list[str] = lookyloo.get_takedown_information('uuid', True)
