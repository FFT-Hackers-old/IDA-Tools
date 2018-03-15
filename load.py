from __future__ import print_function

import json
import time

import common

# Running the script multiple times within IDA doesn't reload imported modules.
reload(common)


# We'll sometimes be passing names to IDA, which expects str, not unicode.
def convert_name_str(obj):
    for k, v in obj.items():
        if isinstance(v, unicode):
            obj[k] = v.encode('utf-8')

    return obj


def main():
    fn = common.get_dump_file()
    print('Loading from %s...' % fn)

    with open(fn) as f:
        j = json.load(f, object_hook=common.convert_name_str)

    for item in common.items:
        item.load(j.get(item.KEY, []))

    print('Finished load at %s.' % time.ctime())


main()
