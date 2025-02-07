#!/usr/bin/env python3

from pylacus import PyLacus
from pylookyloo import Lookyloo

source_lacus = "http://127.0.0.1:7100"
uuid_to_pull = "93b3cc0e-78c4-4e8f-9331-f1b483a23597"
destination_lookyloo = "http://127.0.0.1:5100"

lacus = PyLacus(source_lacus)
lookyloo = Lookyloo(destination_lookyloo)

# Get the capture from the source Lacus
capture = lacus.get_capture(uuid_to_pull, decode=False)
if 'status' in capture and capture['status'] != 1:
    print('Capture not found/ready: ', capture)
    exit(1)

# Send the capture to the destination Lookyloo
response = lookyloo.push_from_lacus(capture)  # type: ignore[arg-type]
print(response)
