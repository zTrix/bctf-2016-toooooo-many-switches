#!/usr/bin/env python2
#-*- coding:utf-8 -*-

import os, sys, string, random

banner = 'BCTF'
flag_len = 16

_end = ''

def make_trie(*words):
    root = dict()
    for word in words:
        current_dict = root
        for letter in word:
            current_dict = current_dict.setdefault(letter, {})
        current_dict[_end] = '__END__'
    return root

def rand_str(size, alphabet=string.printable[:62] + '_+=<>.?'):
    return ''.join([random.choice(alphabet) for x in range(size)])

flag = banner + '{%s}' % rand_str(flag_len)

table = [ flag ]

def rand_similar(seed, pos, end, probability=0.8, branches=2, alphabet=string.printable[:62] + '_+=<>.?'):
    if pos >= end:
        return []
    ret = []
    for i in range(branches):
        if random.random() < probability:
            while True:
                c = random.choice(alphabet)
                if c != seed[pos]:
                    newseed = seed[:pos] + c + rand_str(len(seed) - pos - 2) + '}'
                    ret += [newseed]
                    ret += rand_similar(newseed, pos+1, end, probability, branches, alphabet)
                    break
    return ret

for i in range(len(banner)+2, len(flag)):
    table += rand_similar(flag, i, len(flag)-1)

for i in range(2000):
    x = random.choice(table)
    p = random.randint(len(banner)+1, len(flag)-1)
    table.append(x[:p] + rand_str(len(flag)-p-1) + '}')

for i in range(200):
    table.append(banner + '{%s}' % rand_str(flag_len))

class State(str):
    def __init__(self, s):
        str.__init__(s)

    def cname(self):
        return 'state_' + ''.join([x in string.printable[:62] and x or ('_' + format(ord(x), 'x')) for x in self])

def get_state(trie):
    states = {
        # key: (a transition table or a single value)
    }

    def dfs(root, path):
        if '' in root:
            states.setdefault(''.join(path), {})
            states[''.join(path)]['__NON_ALHUM__'] = root['']
            return
        for key in root:
            curdict = states.setdefault(''.join(path), {})
            curdict[key] = State(''.join(path) + key)
            dfs(root[key], path + [key])
        
    dfs(trie, [])

    return states

def gen_c_enums(states):
    ret = set()
    for state in states:
        ret.add(State(state).cname())

    return 'enum generated_state {\n' + ',\n'.join(map(lambda x: '    ' + x, list(ret))) + '\n};'
    
def gen_c_code(states, indent=8):
    ret = []
    ret +=                  ['switch (state) {']

    for state in states:
        ret +=              ['case %s:' % State(state).cname()]
        val = states[state]
        ret +=              ['    switch (c) {']
        if '__NON_ALHUM__' in val:
            ret +=          ["    case 0: "]

            saltsize = random.randint(10, 20)
            salt = rand_str(saltsize)
            factor1 = random.randint(3, 5)
            factor2 = random.randint(3, 25)
            factor3 = max(25 - factor1 - factor2, 5)
            ret +=          ['        return check(str, size, "%s", %d, %d, %d, %d);' % (salt, saltsize, factor3, factor1, factor2)]
            if state == flag:
                print '// scrypt("%s", %d, "%s", %d, %d, %d, %d, digest, 16);' % (flag, len(flag), salt, len(salt), factor3, factor1, factor2)
            ret +=          ["    default:"]
            ret +=          ["        return -1;"]
            ret +=          ["    }"]
            ret +=          ["    break;"]
            continue
        seendefault = False
        for c in val:
            ret +=          ["    case %r:" % c]
            # if c in string.lowercase:
            #    ret +=      ["    case %r:" % c.upper()]
            if isinstance(val[c], State):
                ret +=      ["        state = %s;" % val[c].cname()]
            else:
                seendefault = True
                ret +=      ["    default:"]
                ret +=      ["        return -1;"]
            ret +=          ["        break;"]
        if not seendefault:
            ret +=          ['    default:']
            ret +=          ['        return -1;']
        ret +=              ['    }']
        ret +=              ['    break;']
    ret +=                  ['}']
    return '\n'.join(map(lambda x: (' ' * indent)+x, ret))

if __name__ == '__main__':
    trie = make_trie(*table)
    states = get_state(trie)

    print '// flag = %s' % flag

    print '''
#include <stdio.h>
#include <string.h>
#include "scrypt-jane.h"

int check(const char *str, size_t size, const char * salt, size_t saltsize, int nfactor, int pfactor, int rfactor) {
    unsigned char digest[16];
    memset(digest, 0, sizeof(digest));
    scrypt(str, size, salt, saltsize, nfactor, pfactor, rfactor, digest, 16);
    unsigned char ans[16] = {0};
    return memcmp(digest, ans, 16);
}

'''
    print ''
    print gen_c_enums(states)
    print '''
off_t in_limited_set(const char *str, size_t size, off_t pos) {
    int state = state_;

    const char * p = str + pos;
    const char * end = str + size;

    while (p <= end) {
        unsigned char c = p < end ? *p : 0;
        p++;
        // printf("c = %c, state = %d\\n", c, state);
'''
    print gen_c_code(states)
    print '''
    }

    return -1;
}
'''
