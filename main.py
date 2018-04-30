from application import app

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    # parser.add_argument('-u', '--user', default='no default', type=str, help='who runs the app')
    args = parser.parse_args()
    # user = args.user   
    port = args.port

    # if user == 'ifan':
    #     IFAN = True
    #     TRIA = False
    # elif user == 'tria': 
    #     IFAN = False
    #     TRIA = True

    app.run(host='0.0.0.0', port=port)