# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


# What is this?
#
# NightMiner is meant to be a simple, one-file implementation of a stratum CPU
# miner for CryptoCurrency written in Python favouring understandability
# over performance.
#
# It was originally designed for scrypt-based coins, and has been extended to
# include support for sha256d.
#
# Try running nightminer with the -P and -d to see protocol and debug details
#
# Required reading:
#   Block Hashing Algorithm - https://litecoin.info/Block_hashing_algorithm
#   Stratum Mining Protocol - http://mining.bitcoin.cz/stratum-mining/
#   Scrypt Algorithm        - http://www.tarsnap.com/scrypt/scrypt.pdf
#   Scrypt Implementation   - https://code.google.com/p/scrypt/source/browse/trunk/lib/crypto/crypto_scrypt-ref.c

import struct, sys, threading, time

from job import *
from SimpleJsonRpcClient import *

# DayMiner (ah-ah-ah), fighter of the...


# You're a master of Karate and friendship for everyone.


# Which algorithm for proof-of-work to use
ALGORITHM_SHA256D = 'sha256d'

ALGORITHMS = [ALGORITHM_SHA256D]



def human_readable_hashrate(hashrate):
    """Returns a human readable representation of hashrate."""

    if hashrate < 1000:
        return '%2f hashes/s' % hashrate
    if hashrate < 10000000:
        return '%2f khashes/s' % (hashrate / 1000)
    if hashrate < 10000000000:
        return '%2f Mhashes/s' % (hashrate / 1000000)
    return '%2f Ghashes/s' % (hashrate / 1000000000)


# Subscription state
class Subscription(object):
    """Encapsulates the Subscription state from the JSON-RPC server"""

    # Subclasses should override this
    def ProofOfWork(header):
        raise Exception('Do not use the Subscription class directly, subclass it')

    class StateException(Exception):
        pass

    def __init__(self):
        self._id = None
        self._difficulty = None
        self._extranonce1 = None
        self._extranonce2_size = None
        self._target = None
        self._worker_name = None

        self._mining_thread = None

    # Accessors
    id = property(lambda s: s._id)
    worker_name = property(lambda s: s._worker_name)

    difficulty = property(lambda s: s._difficulty)
    target = property(lambda s: s._target)

    extranonce1 = property(lambda s: s._extranonce1)
    extranonce2_size = property(lambda s: s._extranonce2_size)

    def set_worker_name(self, worker_name):
        if self._worker_name:
            raise self.StateException('Already authenticated as %r (requesting %r)' % (self._username, username))

        self._worker_name = worker_name

    def _set_target(self, target):
        self._target = '%064x' % target

    def set_difficulty(self, difficulty):
        if difficulty < 0: raise self.StateException('Difficulty must be non-negative')

        # Compute target
        if difficulty == 0:
            target = 2 ** 256 - 1
        else:
            target = min(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5), 2 ** 256 - 1)

        self._difficulty = difficulty
        self._set_target(target)

    def set_subscription(self, subscription_id, extranonce1, extranonce2_size):
        if self._id is not None:
            raise self.StateException('Already subscribed')

        self._id = subscription_id
        self._extranonce1 = extranonce1
        self._extranonce2_size = extranonce2_size

    def create_job(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):
        """Creates a new Job object populated with all the goodness it needs to mine."""

        if self._id is None:
            raise self.StateException('Not subscribed')

        return Job(
            job_id=job_id,
            prevhash=prevhash,
            coinb1=coinb1,
            coinb2=coinb2,
            merkle_branches=merkle_branches,
            version=version,
            nbits=nbits,
            ntime=ntime,
            target=self.target,
            extranonce1=self._extranonce1,
            extranonce2_size=self.extranonce2_size,
            proof_of_work=self.ProofOfWork
        )

    def __str__(self):
        return '<Subscription id=%s, extranonce1=%s, extranonce2_size=%d, difficulty=%d worker_name=%s>' % (
            self.id, self.extranonce1, self.extranonce2_size, self.difficulty, self.worker_name)


class SubscriptionSHA256D(Subscription):
    """Subscription for Double-SHA256-based coins, like Bitcoin."""

    ProofOfWork = sha256d


def test_subscription():
    """Test harness for mining, using a known valid share."""

    # log('TEST: Scrypt algorithm = %r' % SCRYPT_LIBRARY, LEVEL_DEBUG)
    log('TEST: Testing Subscription', LEVEL_DEBUG)

    subscription = SubscriptionSHA256D()

    # Set up the subscription
    reply = json.loads(
        '{"error": null, "id": 1, "result": [["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"], "f800880e", 4]}')
    log('TEST: %r' % reply, LEVEL_DEBUG)
    ((mining_notify, subscription_id), extranonce1, extranonce2_size) = reply['result']
    subscription.set_subscription(subscription_id, extranonce1, extranonce2_size)

    # Set the difficulty
    reply = json.loads('{"params": [32], "id": null, "method": "mining.set_difficulty"}')
    log('TEST: %r' % reply, LEVEL_DEBUG)
    (difficulty,) = reply['params']
    subscription.set_difficulty(difficulty)

    # Create a job
    reply = json.loads(
        '{"params": ["1db7", "0b29bfff96c5dc08ee65e63d7b7bab431745b089ff0cf95b49a1631e1d2f9f31", "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2503777d07062f503253482f0405b8c75208", "0b2f436f696e48756e74722f0000000001603f352a010000001976a914c633315d376c20a973a758f7422d67f7bfed9c5888ac00000000", ["f0dbca1ee1a9f6388d07d97c1ab0de0e41acdf2edac4b95780ba0a1ec14103b3", "8e43fd2988ac40c5d97702b7e5ccdf5b06d58f0e0d323f74dd5082232c1aedf7", "1177601320ac928b8c145d771dae78a3901a089fa4aca8def01cbff747355818", "9f64f3b0d9edddb14be6f71c3ac2e80455916e207ffc003316c6a515452aa7b4", "2d0b54af60fad4ae59ec02031f661d026f2bb95e2eeb1e6657a35036c017c595"], "00000002", "1b148272", "52c7b81a", true], "id": null, "method": "mining.notify"}')
    log('TEST: %r' % reply, LEVEL_DEBUG)
    (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']
    job = subscription.create_job(
        job_id=job_id,
        prevhash=prevhash,
        coinb1=coinb1,
        coinb2=coinb2,
        merkle_branches=merkle_branches,
        version=version,
        nbits=nbits,
        ntime=ntime
    )

    # Scan that job (if I broke something, this will run for a long time))
    for result in job.mine(nonce_start=1210450368 - 3):
        log('TEST: found share - %r' % repr(result), LEVEL_DEBUG)
        break

    valid = {'ntime': '52c7b81a', 'nonce': '482601c0', 'extranonce2': '00000000', 'job_id': u'1db7'}
    log('TEST: Correct answer %r' % valid, LEVEL_DEBUG)


# CLI for cpu mining
if __name__ == '__main__':
    import argparse

    # Parse the command line
    parser = argparse.ArgumentParser(description="CPU-Miner for Cryptocurrency using the stratum protocol")

    parser.add_argument('-o', '--url', help='stratum mining server url (eg: stratum+tcp://foobar.com:3333)')
    parser.add_argument('-u', '--user', dest='username', default='', help='username for mining server',
                        metavar="USERNAME")
    parser.add_argument('-p', '--pass', dest='password', default='', help='password for mining server',
                        metavar="PASSWORD")

    parser.add_argument('-O', '--userpass', help='username:password pair for mining server',
                        metavar="USERNAME:PASSWORD")

    parser.add_argument('-a', '--algo', default=ALGORITHM_SHA256D, choices=ALGORITHMS,
                        help='hashing algorithm to use for proof of work')

    parser.add_argument('-B', '--background', action='store_true', help='run in the background as a daemon')

    parser.add_argument('-q', '--quiet', action='store_true', help='suppress non-errors')
    parser.add_argument('-P', '--dump-protocol', dest='protocol', action='store_true', help='show all JSON-RPC chatter')
    parser.add_argument('-d', '--debug', action='store_true', help='show extra debug information')

    parser.add_argument('-v', '--version', action='version',
                        version='%s/%s' % (USER_AGENT, '.'.join(str(v) for v in VERSION)))

    options = parser.parse_args(sys.argv[1:])

    message = None

    # Get the username/password
    username = options.username
    password = options.password

    if options.userpass:
        if username or password:
            message = 'May not use -O/-userpass in conjunction with -u/--user or -p/--pass'
        else:
            try:
                (username, password) = options.userpass.split(':')
            except Exception as ex:
                message = 'Could not parse username:password for -O/--userpass'

    # Was there an issue? Show the help screen and exit.
    if message:
        parser.print_help()
        print()
        print(message)
        sys.exit(1)

    # Set the logging level
    if options.debug:
        DEBUG = True
    if options.protocol:
        DEBUG_PROTOCOL = True
    if options.quiet:
        QUIET = True

    # The want a daemon, give them a daemon
    if options.background:
        import os

        if os.fork() or os.fork(): sys.exit()

    # Heigh-ho, heigh-ho, it's off to work we go...
    if options.url:
        subscription = SubscriptionSHA256D()
        miner = Miner(options.url, username, password, subscription, ALGORITHM_SHA256D)
        miner.serve_forever()
