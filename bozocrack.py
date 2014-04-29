#!/usr/bin/env python
import hashlib, re, sys, urllib2
from urllib import FancyURLopener
from optparse import OptionParser

HASH_REGEX = re.compile("([a-fA-F0-9]{32})")

# Gets an HTTP response from a url
def getResponse(url):
	try:
		response = urllib2.urlopen(url).read()
	except:
		print "Unexpected HTTP Error"
		sys.exit(-1)
	return response


# h = hash as a hex string?
# wordlist = a set
def dictionary_attack(h, wordlist):
    for word in wordlist:
        if hashlib.md5(word).hexdigest() == h:
            return word
    return None

# h = hash, as a hex string
def format_it(h, plaintext):
    return "{myhash}:{myplaintext}".format(myhash = h, myplaintext = plaintext)


def crack_single_hash(h):
    response = getResponse("http://www.google.com/search?q={myhash}".format(myhash = h))

    wordlist = response.read().replace('.', ' ').replace(
        ':', ' ').replace('?', '').split(' ')
    plaintext = dictionary_attack(h, set(wordlist))
    return plaintext


class BozoCrack(object):
    def __init__(self, filename, *args, **kwargs):
        self.hashes = []

        with open(filename, 'r') as f:
            hashes = [h.lower() for line in f if HASH_REGEX.match(line)
                      for h in HASH_REGEX.findall(line.replace('\n', ''))]

        self.hashes = sorted(set(hashes))

        print "Loaded {count} unique hashes".format(count=len(self.hashes))

        self.cache = self.load_cache()

    def crack(self):
        for h in self.hashes:
            if h in self.cache:
                print format_it(h, self.cache[h])
                continue

            plaintext = crack_single_hash(h)

            if plaintext:
                print format_it(h, plaintext)
                self.cache[h] = plaintext
                self.append_to_cache(h, plaintext)

    def load_cache(self, filename='cache'):
        cache = {}
        with open(filename, 'a+') as c:
            for line in c:
                hash, plaintext = line.replace('\n', '').split(':', 1)
                cache[hash] = plaintext
        return cache

    def append_to_cache(self, h, plaintext, filename='cache'):
        with open(filename, 'a+') as c:
            c.write(format_it(hash = h, plaintext = plaintext)+"\n")

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-s', '--single', metavar='MD5HASH',
                      help = 'cracks a single hash', dest='single', default = False)
    parser.add_option('-f', '--file', metavar='HASHFILE',
                      help = 'cracks multiple hashes on a file', dest = 'target',)

    options, args = parser.parse_args()

    if not options.single and not options.target:
        parser.error("please select -s or -f")
    elif options.single:
        plaintext = crack_single_hash(options.single)

        if plaintext:
            print format_it(hash = options.single, plaintext = plaintext)
    else:
        BozoCrack(options.target).crack()
