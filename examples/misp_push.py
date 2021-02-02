#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pylookyloo import Lookyloo
import json


# lookyloo_url = "https://lookyloo.circl.lu/"
lookyloo_url = "http://0.0.0.0:5100"

lookyloo = Lookyloo(lookyloo_url)
lookyloo.init_apikey(username='admin', password='admin')
event = lookyloo.misp_push('6ae2afdc-4d90-41ce-9cae-510daf1e6577')

print(json.dumps(event, indent=2))
