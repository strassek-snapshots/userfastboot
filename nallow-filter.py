#!/usr/bin/env python

#
# TO add a neverallow to the filter add it to the ignored list ensuring whitespace is exactly
# what is found in the file. If this becomes a burden, in the future a full lexer/parser
# will be needed for this.
#

import re
import sys

#
# The EXACT match (including whitespace that is not leading or trailing) of the neverallow to strip
# up to the terminating semi-colon POST m-4 expansion
#
ignored = [
'''neverallow { domain -init -recovery -system_server } frp_block_device:blk_file { { getattr open read ioctl lock } { open append write } };''',
'''neverallow { domain -kernel -init -recovery -vold -uncrypt -install_recovery } block_device:blk_file { open read write };''',
'''neverallow { domain -kernel -init -recovery -ueventd -watchdogd -healthd -vold -uncrypt } self:capability mknod;''',
]

pattern = re.compile(r'^\s*neverallow[^;]*;', re.MULTILINE)

# Recursively searches the buf for items matching regex and then filters the results
# based on filter list. If its in the filter list, it gets removed from the buf, all
# output is written (buffered) to stdout by default.
def filter(buf, pattern, filter_list, out=sys.stdout):

	m = pattern.search(buf)
	if not m:
		# stop condition
		out.write(buf)
		return

	s = m.group().strip()

	# on the true case ie filter it, we keep the contents of buf up to match.start()
	# else we keep buf up to match.end()
	if s in ignored:
		out.write(buf[:m.start()])
	else:
		out.write(buf[:m.end()])

	# skip past what we check and call again ensuring args from initial call
	# are propagated
	filter(buf[m.end():], pattern, filter_list, out)

def main():

	buf = sys.stdin.read()

	filter(buf, pattern, ignored)

if __name__ == "__main__":
	main()

