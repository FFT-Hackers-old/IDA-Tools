from __future__ import print_function

import json
import time

import common

# running the script multiple times within IDA doesn't reload imported modules
reload(common)


def main():
    fn = common.get_dump_file()
    print('Dumping to %s...' % fn)

    j = {item.KEY: item.dump() for item in common.items}

    with open(fn,  'w') as out:
        json.dump(j, out, indent=2, sort_keys=True, separators=(',', ': '))

    print('Finished dump at %s.' % time.ctime())


main()
