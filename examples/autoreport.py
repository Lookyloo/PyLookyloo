#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pylookyloo import Lookyloo


# lookyloo_url = "https://lookyloo.circl.lu/"
# lookyloo_url = "https://lookyloo-demo.yoyodyne-it.eu/"
lookyloo_url = "http://0.0.0.0:5100"

lookyloo = Lookyloo(lookyloo_url)
capture_url = lookyloo.submit(url="https://circl.lu",
                              # auto_report=True)
                              auto_report={"email": "my_address@.contact.lu",
                                           "comment": "This is a phishing URL targeting my bank."})

print(capture_url)
