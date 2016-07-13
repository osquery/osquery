#!/usr/bin/env python

from flask import Flask, request, jsonify

NODE_KEY = '00000000-0000-0000-0000-000000000000'

app = Flask(__name__)

def route(*urls):
    # like app.route, but supports several urls
    # and implies more methods
    def wrapper(f):
        for url in urls:
            app.route(url, methods=['GET', 'POST', 'PUT'])
        return f
    return wrapper

@app.before_request
def request_logging():
    print(request)

@route('/')
def index():
    return '', 204

@route('/log', '/distributed/write')
def simple_endpoint():
    return jsonify(
        node_invalid=False,
    )

@route('/enroll')
def enroll():
    return jsonify(
        node_key=NODE_KEY,
        node_invalid=False,
    )

@route('/config')
def config():
    return jsonify(
        config='WIP',
        node_invalid=False,
    )

@route('/distributed/read')
def distributed_read():
    return jsonify(
        queries=[],  # TODO
        node_invalid=False,
    )


if __name__ == '__main__':
    app.run(port=8015)
