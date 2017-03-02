
"""API for uploading files and data streams to TSD."""

import os
import logging
import json
import yaml
import tornado.queues
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
from tornado.concurrent import Future
from tornado.escape import utf8, json_decode
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from tornado.ioloop import IOLoop
from tornado.options import parse_command_line, define, options
from tornado.web import Application, RequestHandler, stream_request_body

from auth import store_email_and_password, generate_token, verify_json_web_token, \
    check_client_credentials_in_order


def read_config(file):
    with open(file) as f:
        conf = yaml.load(f)
    return conf


define('port', default=8888)
define('debug', default=True)
define('server_delay', default=0)
define('num_chunks', default=50)
define('max_body_size', 1024*1024*1024*5)

# get all this from config
# consider making a class
# investigate define functionality for storage
UPLOADS_FOLDER = '/Users/leondutoit/uploaded-files'
JWT_SECRET = 'testsecret'
DBURL = 'sqlite:////Users/leondutoit/tsd-file-api/api-users.db'

def db_init(engine_type):
    # Ref: http://docs.sqlalchemy.org/en/rel_1_1/core/pooling.html
    if engine_type == 'sqlite':
        engine = create_engine(DBURL, poolclass=QueuePool)
        try:
            conn = engine.connect()
            conn.execute('create table if not exists users(email TEXT, pw TEXT, verified INT);')
            conn.close()
        except Exception:
            raise Exception("Could not initialise sqlite - user table not created.")
        return engine
    elif engine_type == 'postgresql':
        raise Exception("postgresql engine not implemented yet")
    else:
        raise Exception("Did you perhaps make a typo in your engine spec? \
             Legal values are: 'sqlite' and 'postgresql'.")


ENGINE = db_init('sqlite')

class UserRegistrationHandler(RequestHandler):

    def prepare(self):
        data = json_decode(self.request.body)
        email = str(data['email'])
        pw = str(data['pw'])
        conn = ENGINE.connect()
        store_email_and_password(conn, email, pw)

    def post(self):
        self.write({ 'message': 'user registered' })


class JWTIssuerHandler(RequestHandler):

    def prepare(self):
        data = json_decode(self.request.body)
        self.email = str(data['email'])
        self.pw = str(data['pw'])
        conn = ENGINE.connect()
        self.answer = check_client_credentials_in_order(conn, self.email, self.pw)
        if not self.answer['credentials_in_order']:
            self.auth_status =403

    def post(self):
        if self.auth_status == 403:
            self.set_status(403)
            self.write({ 'message': self.answer['message'] })
        else:
            token = generate_token(self.email, JWT_SECRET)
            self.write({ 'token': token })


class FormDataHandler(RequestHandler):

    def prepare(self):
        auth_header = self.request.headers['Authorization']
        resp = verify_json_web_token(auth_header, JWT_SECRET, 'app_user')
        if resp is not True:
            return resp


    def post(self):
        if len(self.request.files['file']) > 1:
            # only allow one file per request for now
            self.send_error()
        # TODO: check filename
        filename = self.request.files['file'][0]['filename']
        target = os.path.normpath(UPLOADS_FOLDER + '/' + filename)
        filebody = self.request.files['file'][0]['body']
        with open(target, 'ab+') as f:
            f.write(filebody)
        self.write({'message': 'file uploaded'})

    def on_finish(self):
        # called after response is returned to client
        # could notify an external worker here
        pass


@stream_request_body
class UploadHandler(RequestHandler):

    def prepare(self):
        logging.info('UploadHandler.prepare')

    @gen.coroutine
    def data_received(self, chunk):
        #logging.info('UploadHandler.data_received(%d bytes: %r)', len(chunk), chunk[:9])
        with open('out', 'ab+') as f:
            f.write(chunk)
        # could use this to slow the client down if needed
        # yield gen.Task(IOLoop.current().call_later, options.server_delay)

    def post(self):
        logging.info('UploadHandler.post')
        self.write('ok')


@stream_request_body
class ProxyHandler(RequestHandler):

    def prepare(self):
        logging.info('ProxyHandler.prepare')
        self.chunks = tornado.queues.Queue(1)
        self.fetch_future = AsyncHTTPClient().fetch(
            'http://localhost:%d/upload_stream' % options.port,
            method='POST',
            body_producer=self.body_producer,
            request_timeout=12000.0)

    @gen.coroutine
    def body_producer(self, write):
        while True:
            chunk = yield self.chunks.get()
            if chunk is None:
                return
            yield write(chunk)

    @gen.coroutine
    def data_received(self, chunk):
        #logging.info('ProxyHandler.data_received(%d bytes: %r)', len(chunk), chunk[:9])
        yield self.chunks.put(chunk)

    @gen.coroutine
    def post(self):
        logging.info('ProxyHandler.post')
        # Write None to the chunk queue to signal body_producer to exit,
        # then wait for the request to finish.
        yield self.chunks.put(None)
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)


def main():
    parse_command_line()
    app = Application([
        ('/upload_signup', UserRegistrationHandler),
        ('/upload_token', JWTIssuerHandler),
        ('/upload_stream', UploadHandler),
        ('/stream', ProxyHandler),
        ('/upload', FormDataHandler),
    ], debug=options.debug)
    app.listen(options.port, max_body_size=options.max_body_size)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
