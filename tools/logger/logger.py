# For starting it, use run.sh script
from pprint import pprint
from functools import wraps

from flask import Flask, request, jsonify

NODE_KEY = '00000000-0000-0000-0000-000000000000'

app = Flask(__name__)

def route(*urls):
    # like app.route, but supports several urls
    # and implies more methods
    def adder(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            """ Jsonify replies, adding node_invalid=false if needed """
            resp = f(*args, **kwargs)
            if resp is None:
                resp = {}
            if isinstance(resp, dict):
                resp.setdefault('node_invalid', False)
                return jsonify(**resp)
            return resp

        for url in urls:
            # register this wrapper for each url
            app.route(url, methods=['GET', 'POST', 'PUT'])(wrapper)
        return wrapper
    return adder

@app.before_request
def request_logging():
    print()
    print('-> {method} {path}'.format(
        method=request.method,
        path=request.path,
    ))
    try:
        json = request.get_json(force=True)
        if json is None:
            print('No data in request')
        else:
            pprint(json)
    except Exception:
        print('Invalid JSON in request:')
        pprint(request.data)


@route('/')
def index():
    return '', 204

@route('/log', '/distributed/write',
       '/v1/log', '/v1/distributed/write')
def simple_endpoint():
    pass

@route('/enroll', '/v1/enroll')
def enroll():
    return dict(
        node_key=NODE_KEY,
    )

@route('/config', '/v1/config')
def config():
    return dict(
        options=dict(
            host_identifier='uuid',
            schedule_splay_percent=10,
        ),
        file_paths={},
        schedule={},
        packs={},
    )

@route('/distributed/read', '/v1/distributed/read')
def distributed_read():
    return dict(
        queries=[],  # TODO
    )
