import threading
import json
import time
from urllib.parse import urlparse
import socket

USER_AGENT = "NightMiner"
VERSION = [0, 1]

# Verbosity and log level
QUIET = False
DEBUG = False
DEBUG_PROTOCOL = False

LEVEL_PROTOCOL = 'protocol'
LEVEL_INFO = 'info'
LEVEL_DEBUG = 'debug'
LEVEL_ERROR = 'error'


def log(message, level):
    """Conditionally write a message to stdout based on command line options and level."""

    global DEBUG
    global DEBUG_PROTOCOL
    global QUIET

    if QUIET and level != LEVEL_ERROR: return
    if not DEBUG_PROTOCOL and level == LEVEL_PROTOCOL: return
    if not DEBUG and level == LEVEL_DEBUG: return

    if level != LEVEL_PROTOCOL: message = '[%s] %s' % (level.upper(), message)

    print("[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message))


class SimpleJsonRpcClient(object):
    """Simple JSON-RPC client.

    To use this class:
      1) Create a sub-class
      2) Override handle_reply(self, request, reply)
      3) Call connect(socket)

    Use self.send(method, params) to send JSON-RPC commands to the server.

    A new thread is created for listening to the connection; so calls to handle_reply
    are synchronized. It is safe to call send from withing handle_reply.
  """

    class ClientException(Exception):
        pass

    class RequestReplyException(Exception):
        def __init__(self, message, reply, request=None):
            Exception.__init__(self, message)
            self._reply = reply
            self._request = request

        request = property(lambda s: s._request)
        reply = property(lambda s: s._reply)

    class RequestReplyWarning(RequestReplyException):
        """Sub-classes can raise this to inform the user of JSON-RPC server issues."""
        pass

    def __init__(self):
        self._socket = None
        self._lock = threading.RLock()
        self._rpc_thread = None
        self._message_id = 1
        self._requests = dict()

    def _handle_incoming_rpc(self):
        data = ""
        while True:
            # Get the next line if we have one, otherwise, read and block
            if "\n" in data:
                (line, data) = data.split('\n', 1)
            else:
                chunk = self._socket.recv(1024)
                data += chunk.decode("utf-8")
                # print(data)
                continue

            log('JSON-RPC Server > ' + line, LEVEL_PROTOCOL)

            # Parse the JSON
            try:
                reply = json.loads(line)
            except Exception:
                log("JSON-RPC Error: Failed to parse JSON %r (skipping)" % line, LEVEL_ERROR)
                continue

            try:
                request = None
                with self._lock:
                    if 'id' in reply and reply['id'] in self._requests:
                        request = self._requests[reply['id']]
                    self.handle_reply(request=request, reply=reply)
            except self.RequestReplyWarning as ex:
                # output = ""
                # if ex.request:
                #     output += '\n  ' + ex.request
                # output += '\n  ' + ex.reply
                log(ex, LEVEL_ERROR)

    def handle_reply(self, request, reply):
        # Override this method in sub-classes to handle a message from the server
        raise self.RequestReplyWarning('Override this method')

    def send(self, method, params):
        """Sends a message to the JSON-RPC server"""

        if not self._socket:
            raise self.ClientException('Not connected')

        request = dict(id=self._message_id, method=method, params=params)
        message = json.dumps(request)
        with self._lock:
            self._requests[self._message_id] = request
            self._message_id += 1
            self._socket.send(message.encode(encoding='UTF-8') + "\n".encode(encoding='UTF-8'))

        log('JSON-RPC Server < ' + message, LEVEL_PROTOCOL)

        return request

    def connect(self, socket):
        """Connects to a remove JSON-RPC server"""

        if self._rpc_thread:
            raise self.ClientException('Already connected')

        self._socket = socket

        self._rpc_thread = threading.Thread(target=self._handle_incoming_rpc)
        self._rpc_thread.daemon = True
        self._rpc_thread.start()


# Miner client
class Miner(SimpleJsonRpcClient):
    """Simple mining client"""

    class MinerWarning(SimpleJsonRpcClient.RequestReplyWarning):
        def __init__(self, message, reply, request=None):
            SimpleJsonRpcClient.RequestReplyWarning.__init__(self, 'Mining State Error: ' + message, reply, request)

    class MinerAuthenticationException(SimpleJsonRpcClient.RequestReplyException):
        pass

    def __init__(self, url, username, password, subscription, algorithm):
        SimpleJsonRpcClient.__init__(self)

        self._url = url
        self._username = username
        self._password = password

        self._subscription = subscription

        self._job = None

        self._accepted_shares = 0

    # Accessors
    url = property(lambda s: s._url)
    username = property(lambda s: s._username)
    password = property(lambda s: s._password)

    # Overridden from SimpleJsonRpcClient
    def handle_reply(self, request, reply):

        # New work, stop what we were doing before, and start on this.
        if reply.get('method') == 'mining.notify':
            if 'params' not in reply or len(reply['params']) != 9:
                raise self.MinerWarning('Malformed mining.notify message', reply)

            (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']

            # commenting this out disables actual mining
            self._spawn_job_thread(job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime)
            log('New job: job_id=%s' % job_id, LEVEL_DEBUG)

        # The server wants us to change our difficulty (on all *future* work)
        elif reply.get('method') == 'mining.set_difficulty':
            if 'params' not in reply or len(reply['params']) != 1:
                raise self.MinerWarning('Malformed mining.set_difficulty message', reply)

            (difficulty,) = reply['params']
            self._subscription.set_difficulty(difficulty)

            log('Change difficulty: difficulty=%s' % difficulty, LEVEL_DEBUG)

        # This is a reply to...
        elif request:

            # ...subscribe; set-up the work and request authorization
            if request.get('method') == 'mining.subscribe':
                if "result" not in reply or len(reply['result']) != 3 or len(reply['result'][0][0]) != 2:
                    raise self.MinerWarning('Reply to mining.subscribe is malformed', reply, request)

                ([(mining_notify, subscription_id)], extranonce1, extranonce2_size) = reply['result']
                print(extranonce2_size)

                self._subscription.set_subscription(subscription_id, extranonce1, extranonce2_size)

                log('Subscribed: subscription_id=%s' % subscription_id, LEVEL_DEBUG)

                # Request authentication
                self.send(method='mining.authorize', params=[self.username, self.password])

            # ...authorize; if we failed to authorize, quit
            elif request.get('method') == 'mining.authorize':
                if 'result' not in reply or not reply['result']:
                    raise self.MinerAuthenticationException('Failed to authenticate worker', reply, request)

                worker_name = request['params'][0]
                self._subscription.set_worker_name(worker_name)

                log('Authorized: worker_name=%s' % worker_name, LEVEL_DEBUG)

            # ...submit; complain if the server didn't accept our submission
            elif request.get('method') == 'mining.submit':
                if 'result' not in reply or not reply['result']:
                    log('Share - Invalid', LEVEL_INFO)
                    raise self.MinerWarning('Failed to accept submit', reply, request)

                self._accepted_shares += 1
                log('Accepted shares: %d' % self._accepted_shares, LEVEL_INFO)

            # ??? *shrug*
            else:
                raise self.MinerWarning('Unhandled message', reply, request)

        # ??? *double shrug*
        else:
            raise self.MinerWarning('Bad message state', reply)

    def _spawn_job_thread(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):
        """Stops any previous job and begins a new job."""

        # Stop the old job (if any)
        if self._job:
            self._job.stop()

        # Create the new job
        self._job = self._subscription.create_job(
            job_id=job_id,
            prevhash=prevhash,
            coinb1=coinb1,
            coinb2=coinb2,
            merkle_branches=merkle_branches,
            version=version,
            nbits=nbits,
            ntime=ntime
        )

        def run(job):
            # try:
            for result in job.mine():
                params = [self._subscription.worker_name] + [result[k] for k in
                                                             ('job_id', 'extranonce2', 'ntime', 'nonce')]
                self.send(method='mining.submit', params=params)
                log("Found share: " + str(params), LEVEL_INFO)
            log("Hashrate: %s" % human_readable_hashrate(job.hashrate), LEVEL_INFO)
            # except Exception as ex:
            # log("ERROR: %s" % ex, LEVEL_ERROR)

        thread = threading.Thread(target=run, args=(self._job,))
        thread.daemon = True
        thread.start()

    def serve_forever(self):
        """Begins the miner. This method does not return."""

        # Figure out the hostname and port
        url = urlparse(self.url)
        hostname = url.hostname or ''
        port = url.port or 9333

        log('Starting server on %s:%d' % (hostname, port), LEVEL_INFO)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        self.connect(sock)

        self.send(method='mining.subscribe', params=["%s/%s" % (USER_AGENT, '.'.join(str(p) for p in VERSION))])

        # Forever...
        while True:
            time.sleep(10)

