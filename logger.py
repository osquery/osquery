#!/usr/bin/env python

from flask import Flask, request, jsonify

NODE_KEY = '00000000-0000-0000-0000-000000000000'

app = Flask(__name__)

@app.before_request
def request_logging():
    print(request)

@app.route('/log')
@app.route('/distributed/write')
def simple_endpoint():
    return jsonify(
        node_invalid=False,
    )

@app.route('/enroll')
def enroll():
    return jsonify(
        node_key=NODE_KEY,
        node_invalid=False,
    )

@app.route('/config')
def config():
    return jsonify(
        config='WIP',
        node_invalid=False,
    )

@app.route('/distributed/read')
def distributed_read():
    return jsonify(
        queries=[],  # TODO
        node_invalid=False,
    )


if __name__ == '__main__':
    app.run(port=8015)
