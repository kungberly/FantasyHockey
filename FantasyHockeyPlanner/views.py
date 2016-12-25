from django.shortcuts import render
from django.views import generic
import requests, random, urllib.request, urllib.parse
import hmac, hashlib, base64, oauth2
import time

def make_yahoo_request(request, url, meth, method, verifier=False, handle=False, token_secret=None, params=None):
    import time
    if not params:
        params = {}

    method = method.upper()
    meth = meth.upper()

    # Check for a valid signature method
    if meth not in ['PLAINTEXT','HMAC-SHA1']:
        print('Invalid Signature...for real')
        return False

    nonce = oauth2.generate_nonce(32)  # binascii.hexlify(os.urandom(16)).decode("utf-8")
    callback = '&oauth_callback=' + request.session.get('redirect_url') + '/callback'

    #populate parameters dict
    params['oauth_consumer_key'] = request.session.get('cons_key')
    params['oauth_nonce'] = nonce
    params['oauth_signature_method'] = meth
    params['oauth_timestamp'] = str(int(time.time()))
    params['oauth_version'] = '1.0'
    params['realm'] = 'yahooapis.com'

    if verifier:
        params['oauth_verifier'] = request.session.get('verifier')
    if handle:
        params['oauth_session_handle'] = request.session.get('handle')
    if not token_secret:
        token_secret = ''

    print('\n', 'TOKEN SECRET 3:', token_secret, '\n')

    try:
        assert request.session.get('access_token')
        params['oauth_token'] = request.session.get('access_token')
    except:
        try:
            assert request.session.get('request_token')
            params['oauth_token'] = request.session.get('request_token')
        except:
            pass
        pass

    params_list = []
    for key, val in sorted(params.items()):
        params_list.append(urllib.parse.quote_plus(key)+'='+urllib.parse.quote_plus(val))
    param_string = '&'.join(params_list)

    base_string = urllib.parse.quote_plus(method)+'&'+urllib.parse.quote_plus(url)+'&'+urllib.parse.quote_plus(param_string)

    secret = urllib.parse.quote_plus(request.session.get('cons_secret')) + '&' + urllib.parse.quote_plus(token_secret)

    print('\n','CONCAT. SECRET:',secret,'\n')

    if meth == 'PLAINTEXT':
        sig = secret
    else:
        sig = base64.b64encode(hmac.new(secret.encode(),base_string.encode(),hashlib.sha1).digest()).decode()
    print('\n','SIGNATURE:',sig,'\n')

    param_string += '&oauth_signature=' + urllib.parse.quote_plus(sig)

    final_url = url + '?' + param_string + callback
    print('\n','FINAL URL:',final_url,'\n')

    response = requests.get(final_url)
    print('RESPONSE:' +str(response.content.decode()))

    return response.content.decode()

def index(request):
    return render(request,'FantasyHockeyPlanner/index.html')

def login(request):
    '''
    Called when user clicks "login"

    Begins login process by getting oauth request token and asking for user authorization
    '''

    # Client ID info - store as session variables -- *******RESET ALL VALUES EVERYTIME YOU RESTART NGROK********
    cons_key = 'dj0yJmk9eE1hQ0xTdFUzeXhhJmQ9WVdrOWVHVlpkMnQ2Tm5NbWNHbzlNQS0tJnM9Y29uc3VtZXJzZWNyZXQmeD02Yw--'
    cons_secret = '4cf3c67535d8e202d430bc5f799591b11e2779b1'
    redirect = 'https://ec419086.ngrok.io/FantasyHockeyPlanner'

    request.session['cons_key'] = cons_key
    request.session['cons_secret'] = cons_secret
    request.session['redirect_url'] = redirect

    # Clear session variables to avoid signature rejection from old signature
    request.session['request_token'] = None
    request.session['request_token_secret'] = None
    request.session['verifier'] = None
    request.session['access_token'] = None
    request.session['token_secret'] = None
    request.session['session_handle'] = None

    try:
        get_request_token(request)
    except:
        request.session['request_token'] = None
        request.session['request_token_secret'] = None
        return render(request, 'FantasyHockeyPlanner/yahooerror.html')

    # build request authorization url
    callback = '&oauth_callback=' + redirect + '/callback'
    request_auth_base = 'https://api.login.yahoo.com/oauth/v2/request_auth?oauth_token='
    request_auth_url = request_auth_base + request.session.get('request_token') + callback

    # render login page (blank) to call yahoo to request authorization from user
    return render(request,'FantasyHockeyPlanner/login.html', {"request_auth_url": request_auth_url})

def get_request_token(request):
    request_token_base = 'https://api.login.yahoo.com/oauth/v2/get_request_token'
    r = make_yahoo_request(request, request_token_base, 'PLAINTEXT', 'GET')

    # extract token and token secret from url. Store as session variables
    request.session['request_token'] = r.split('&')[0].split('=')[1]
    request.session['request_token_secret'] = r.split('&')[1].split('=')[1]

    return

def get_token(request):
    '''
    Called when yahoo sends back oauth verifier
    Generates access token request and retrieves token for later use
    '''
    import urllib.parse

    # Extract oauth_verifier from yahoo return URL (request_token hasn't changed)
    h = request.META['QUERY_STRING'].split('&')
    #request.session['request_token'] = h[0].split('=')[1]
    request.session['verifier'] = h[1].split('=')[1]

    access_token_base = 'https://api.login.yahoo.com/oauth/v2/get_token'
    token_secret = request.session.get('request_token_secret')

    r = make_yahoo_request(request, access_token_base, 'PLAINTEXT', 'GET', verifier=True, token_secret=token_secret)

    # Extract access token from URL and store as a session variable
    access_list = r.split('&')
    access_token = access_list[0].split('=')[1]
    request.session['access_token'] = urllib.parse.unquote(access_token)

    token_secret = access_list[1].split('=')[1]
    request.session['token_secret'] = urllib.parse.unquote(token_secret)
    print('\n', 'TOKEN SECRET 1:', request.session.get('token_secret'), '\n')

    request.session['session_handle'] = access_list[3].split('=')[1]

def loggedin(request):
    if not request.session.get('access_token'):
        get_token(request)

    # get projected points for next week
    points_dict = get_player_points(request)

    get_user_data(request)

    # get roster
    start_dict, bench_dict = get_roster(request)

    '''
    print('\nSTARTERS')
    for position in start_dict:
        for starter in start_dict[position]:
            print(starter)
    print('\nBENCH')
    for bench in bench_dict:
        print(bench)
    '''

    # get current starter points
    curr_starter_points = get_starter_points(request, start_dict, points_dict)

    # update the starting lineup
    # update_starters(request,roster_list,points_dict)
    new_start_dict, new_bench_dict = check_roster(request, start_dict, bench_dict, points_dict)
    '''
    print('\nSTARTERS')
    for position in new_start_dict:
        for starter in new_start_dict[position]:
            print(starter)

    print('\nBENCH')
    for bench in new_bench_dict:
        print(bench)
    '''
    new_starter_points = get_starter_points(request, new_start_dict, points_dict)

    #print(curr_starter_points)
    #print(new_starter_points)
    #print(new_start_dict)
    #print(new_bench_dict)

    context = {'start_dict': start_dict, 'bench_dict':bench_dict,
               'new_start_dict': new_start_dict, 'new_bench_dict':new_bench_dict,
               'old_points':curr_starter_points,
               'new_points':new_starter_points
               }

    # render users homepage so that they can begin altering roster
    return render(request, 'FantasyHockeyPlanner/loggedin.html',context)

def refresh_token(request):
    import urllib.parse

    access_token_base = 'https://api.login.yahoo.com/oauth/v2/get_token'
    token_secret = request.session.get('token_secret')

    r = make_yahoo_request(request, access_token_base, 'PLAINTEXT', 'GET', verifier=True, handle=True, token_secret=token_secret)

    # Extract access token from URL and store as a session variable
    access_list = r.split('&')
    access_token = access_list[0].split('=')[1]
    request.session['access_token'] = urllib.parse.unquote(access_token)

    token_secret = access_list[1].split('=')[1]
    request.session['token_secret'] = urllib.parse.unquote(token_secret)

    request.session['session_handle'] = access_list[3].split('=')[1]

def get_user_data(request):
    base_url = 'http://fantasysports.yahooapis.com/fantasy/v2/users;use_login=1/games;game_keys=nhl/teams'
    token_secret = request.session.get('token_secret')
    print('\n', 'TOKEN SECRET 2:', token_secret, '\n')

    data = make_yahoo_request(request, base_url, 'HMAC-SHA1', 'POST', token_secret=token_secret)
    return

def get_team_data(request):
    '''
    Get current roster data and display it on the "loggedin" page
    '''
    import urllib.request
    import requests, oauth2, time, hmac, hashlib, base64

    request.session['league_key'] = '363.l.100040'
    request.session['team_key'] = '.t.1'
    base_url = 'http://fantasysports.yahooapis.com/fantasy/v2/'
    league_key = 'league/' + request.session.get('league_key') + request.session.get('team_key')#+ '.metadata'

    url = base_url+league_key
    token_secret = request.session.get('token_secret')
    print('\n','TOKEN SECRET 2:',token_secret,'\n')

    data = make_yahoo_request(request, url, 'HMAC-SHA1','POST', token_secret=token_secret)
    #print(data)

    return

def setlineup(request):
    request.session['points_dict'] = get_player_points(request)
    context = {'points_dict': request.session['points_dict']}
    # context = request.session['points_dict']

    return render(request,'FantasyHockeyPlanner/setlineup.html', context)


def get_roster(request):
    start_dict = {
        'C': {
            'Ryan Johansen': {'position': 'C'},
            'Nicklas Backstrom': {'position': 'C'}
        },
        'LW': {
            'Max Pacioretty': {'position': 'LW'},
            'Gabriel Landeskog': {'position': 'LW'}
        },
        'RW': {
            'James Neal': {'position': 'RW'},
            'Matt Duchene': {'position': 'RW'}
        },
        'D': {
            'Shayne Gostisbehere': {'position': 'D'},
            'Tyson Barrie': {'position': 'D'},
            'Brent Seabrook': {'position': 'D'},
            'Alec Martinez': {'position': 'D'}
        },
        'G': {
            'Ben Bishop': {'position': 'G'},
            'Jonathan Quick': {'position': 'G'}
        }
    }
    bench_dict = {
        "Sidney Crosby": {'position': 'C'},
        "Kyle Okposo": {'position': 'RW'},
        "James van Riemsdyk": {'position': 'LW'},
        "Robin Lehner": {'position': 'G'}
    }
    return start_dict, bench_dict


def get_player_points(request):
    import requests
    from bs4 import BeautifulSoup

    base_url = "https://www.fantasysp.com/projections/hockey/weekly/"

    try:
        response = requests.get(base_url)
        soup = BeautifulSoup(response.content, 'lxml')
        table = soup.find('table', class_='table sortable table-clean table-add-margin')
        rows = soup.find_all('tr')
        player_dict = {}
        for i in range(len(rows)):
            row = rows[i]
            name = row.find('a').get_text()
            last = name.split(' ')[1]
            position = row.find_all('span', class_='draft-teamb')[1].get_text()
            points = row.find_all('td', style='text-align: center;')[-1].get_text()

            player_dict[name] = {'position': position, 'points': points}

    except:
        print('no dice')

    return player_dict


def get_starter_points(request, start_dict, points_dict):
    points = 0
    #    print(start_dict)
    for position in start_dict:
        for player in start_dict[position]:
            try:
                points += int(points_dict[player]['points'])
            except:
                pass
    return points


def check_roster(request, start_dict, bench_dict, points_dict):
    from operator import itemgetter
    # combine rosters
    combined = combine_rosters(start_dict, bench_dict)

    # Assign points to each player and add to value in dict at index 1
    for player in combined:
        try:
            combined[player].append(int(points_dict[player]['points']))
        except:
            combined[player].append(0)

    # sort combined roster dict into a list sorted by points
    sorted_roster = sorted(combined.items(), key=lambda i: i[1][1], reverse=True)
    #    print(sorted_roster)

    # build new dicts for new lineups
    new_start = {'G': {}, 'LW': {}, 'RW': {}, 'C': {}, 'D': {}}
    new_bench = {}

    # populate new dict rosters
    for i in range(len(sorted_roster)):
        if sorted_roster[i][1][0] in ['C', 'LW', 'RW', 'G']:
            if len(new_start[sorted_roster[i][1][0]]) < 2:
                new_start[sorted_roster[i][1][0]][sorted_roster[i][0]] = {'position': sorted_roster[i][1][0]}
            else:
                new_bench[sorted_roster[i][0]] = {'position': sorted_roster[i][1][0]}
        else:
            if len(new_start[sorted_roster[i][1][0]]) < 4:
                new_start[sorted_roster[i][1][0]][sorted_roster[i][0]] = {'position': sorted_roster[i][1][0]}

    return new_start, new_bench

def combine_rosters(start, bench):
    '''
    Combine bench and starting rosters in preparation for sorting by points
    '''
    combined = {}
    for pos in start:
        for starter in start[pos]:
            combined[starter] = [start[pos][starter]['position']]
    for player in bench:
        combined[player] = [bench[player]['position']]
    return combined

def about(request):
    return render(request,'FantasyHockeyPlanner/about.html')
