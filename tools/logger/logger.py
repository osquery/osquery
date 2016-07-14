# For starting it, use run.sh script
from pprint import pprint

from flask import Flask, request, jsonify

NODE_KEY = '00000000-0000-0000-0000-000000000000'

app = Flask(__name__)

def route(*urls):
    # like app.route, but supports several urls
    # and implies more methods
    def wrapper(f):
        for url in urls:
            app.route(url, methods=['GET', 'POST', 'PUT'])(f)
        return f
    return wrapper

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
    return jsonify(
        node_invalid=False,
    )

@route('/enroll', '/v1/enroll')
def enroll():
    return jsonify(
        node_key=NODE_KEY,
        node_invalid=False,
    )

@route('/config', '/v1/config')
def config():
    return jsonify(
        config='WIP',
        node_invalid=False,
    )

@route('/distributed/read', '/v1/distributed/read)
def distributed_read():
    return jsonify(
        queries=[],  # TODO
        node_invalid=False,
    )
