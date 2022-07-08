import time
import struct
import binascii
import hashlib

# Convert from/to binary and hexidecimal strings (could be replaced with .encode('hex') and .decode('hex'))
hexlify = binascii.hexlify
unhexlify = binascii.unhexlify


# nice hex array print
def pretty_hex(data):
    print("[", end='')
    for x in data[:-1]:
        print("%02X " % x, end='')
    print("%02X]" % data[-1])


def sha256d(message):
    """Double SHA256 Hashing function."""

    return hashlib.sha256(hashlib.sha256(message).digest()).digest()


def swap_endian_word(hex_word):
    """Swaps the endianness of a hexidecimal string of a word and converts to a binary string."""

    message = unhexlify(hex_word)
    # print(message)
    if len(message) != 4: raise ValueError('Must be 4-byte word')
    return message[::-1]


def swap_endian_words(hex_words):
    """Swaps the endianness of a hexidecimal string of words and converts to binary string."""
    combined = b''
    message = unhexlify(hex_words)
    if len(message) % 4 != 0:
        raise ValueError('Must be 4-byte word aligned')
    for i in range(0, len(message) // 4):
        combined = combined + message[4 * i: 4 * i + 4][::-1]

    # return ''.join([message[4 * i: 4 * i + 4][::-1] for i in range(0, len(message) // 4)])
    return combined


class Job(object):
    """Encapsulates a Job from the network and necessary helper methods to mine.

     "If you have a procedure with 10 parameters, you probably missed some."
           ~Alan Perlis
  """

    def __init__(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, target, extranonce1,
                 extranonce2_size, proof_of_work):

        # Job parts from the mining.notify command
        self._job_id = job_id
        self._prevhash = prevhash
        self._coinb1 = coinb1
        self._coinb2 = coinb2
        self._merkle_branches = [b for b in merkle_branches]
        self._version = version
        self._nbits = nbits
        self._ntime = ntime

        # Job information needed to mine from mining.subscribe
        self._target = target
        self._extranonce1 = extranonce1
        self._extranonce2_size = extranonce2_size

        # Proof of work algorithm
        self._proof_of_work = proof_of_work

        # Flag to stop this job's mine coroutine
        self._done = False

        # Hash metrics (start time, delta time, total hashes)
        self._dt = 0.0
        self._hash_count = 0

    # Accessors
    id = property(lambda s: s._job_id)
    prevhash = property(lambda s: s._prevhash)
    coinb1 = property(lambda s: s._coinb1)
    coinb2 = property(lambda s: s._coinb2)
    merkle_branches = property(lambda s: [b for b in s._merkle_branches])
    version = property(lambda s: s._version)
    nbits = property(lambda s: s._nbits)
    ntime = property(lambda s: s._ntime)

    target = property(lambda s: s._target)
    extranonce1 = property(lambda s: s._extranonce1)
    extranonce2_size = property(lambda s: s._extranonce2_size)

    proof_of_work = property(lambda s: s._proof_of_work)

    @property
    def hashrate(self):
        """The current hashrate, or if stopped hashrate for the job's lifetime."""

        if self._dt == 0:
            return 0.0
        return self._hash_count / self._dt

    def merkle_root_bin(self, extranonce2_bin):
        """Builds a merkle root from the merkle tree"""

        coinbase_bin = unhexlify(self._coinb1) + unhexlify(self._extranonce1) + extranonce2_bin + unhexlify(
            self._coinb2)
        coinbase_hash_bin = sha256d(coinbase_bin)

        merkle_root = coinbase_hash_bin
        for branch in self._merkle_branches:
            merkle_root = sha256d(merkle_root + unhexlify(branch))
        return merkle_root

    def stop(self):
        """Requests the mine coroutine stop after its current iteration."""

        self._done = True

    def mine(self, nonce_start=0, nonce_stride=1):
        """Returns an iterator that iterates over valid proof-of-work shares.

       This is a co-routine; that takes a LONG time; the calling thread should look like:

         for result in job.mine(self):
           submit_work(result)

       nonce_start and nonce_stride are useful for multi-processing if you would like
       to assign each process a different starting nonce (0, 1, 2, ...) and a stride
       equal to the number of processes.
    """

        t0 = time.time()

        # @TODO: test for extranonce != 0... Do I reverse it or not?
        for extranonce2 in range(0, 0x7fffffff):

            # Must be unique for any given job id, according to http://mining.bitcoin.cz/stratum-mining/ but never seems enforced?
            extranonce2_bin = struct.pack('<I', extranonce2)

            merkle_root_bin = self.merkle_root_bin(extranonce2_bin)
            header_prefix_bin = swap_endian_word(self._version) + swap_endian_words( self._prevhash) + merkle_root_bin + swap_endian_word(self._ntime) + swap_endian_word(self._nbits)

            print("version: ", end='')
            pretty_hex(swap_endian_word(self._version))
            print("prevhash: ", end='')
            pretty_hex(swap_endian_words( self._prevhash))
            print("merkle root: ", end='')
            pretty_hex(merkle_root_bin)
            print("ntime: ", end='')
            pretty_hex(swap_endian_word(self._ntime))
            print("nbits: ", end='')
            pretty_hex(swap_endian_word(self._nbits))

            pretty_hex(header_prefix_bin)

            time.sleep(10)
            # for nonce in range(nonce_start, 0x7fffffff, nonce_stride):
            #     # This job has been asked to stop
            #     if self._done:
            #         self._dt += (time.time() - t0)
            #         # raise StopIteration()
            #
            #     # Proof-of-work attempt
            #     nonce_bin = struct.pack('<I', nonce)
            #     inner = header_prefix_bin + nonce_bin
            #     pretty_hex(header_prefix_bin)
            #     pretty_hex(nonce_bin)
                # print("inner: ", end='')
                # print(inner.hex())
                # pow = self.proof_of_work(inner)[::-1].encode('hex')

                # Did we reach or exceed our target?
                # if pow <= self.target:
                #     result = dict(
                #         job_id=self.id,
                #         extranonce2=hexlify(extranonce2_bin),
                #         ntime=str(self._ntime),  # Convert to str from json unicode
                #         nonce=hexlify(nonce_bin[::-1])
                #     )
                #     self._dt += (time.time() - t0)
                #
                #     yield result
                #
                #     t0 = time.time()
                # time.sleep(10)

                # self._hash_count += 1

    def __str__(self):
        return '<Job id=%s prevhash=%s coinb1=%s coinb2=%s merkle_branches=%s version=%s nbits=%s ntime=%s target=%s extranonce1=%s extranonce2_size=%d>' % (
            self.id, self.prevhash, self.coinb1, self.coinb2, self.merkle_branches, self.version, self.nbits,
            self.ntime,
            self.target, self.extranonce1, self.extranonce2_size)

