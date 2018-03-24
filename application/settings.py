from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('-u', '--user', default='no default', type=str, help='who runs the app')
args = parser.parse_args()
user = args.user   

IFAN = True
TRIA = False

if user == 'ifan':
    IFAN = True
    TRIA = False
elif user == 'tria':
    IFAN = False
    TRIA = True

