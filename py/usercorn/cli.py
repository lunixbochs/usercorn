from cls import UserCorn
import sys

def run():
    if len(sys.argv) < 2:
        print 'Usage: %s <exe> [args...]' % sys.argv[0]
        sys.exit(1)
    sys.exit(UserCorn(sys.argv[1]).run(sys.argv[1], *sys.argv[2:]))
