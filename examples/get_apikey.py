#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pylookyloo import Lookyloo

# lookyloo_url = "https://lookyloo.circl.lu/"
lookyloo_url = "http://0.0.0.0:5100"

lookyloo = Lookyloo(lookyloo_url)

token = lookyloo.get_apikey('admin', 'admin')
print(token)
