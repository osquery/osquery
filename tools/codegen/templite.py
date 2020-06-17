#!/usr/bin/env python
#
#  Templite+
#  A light-weight, fully functional, general purpose templating engine
#
#  Copyright (c) 2009 joonis new media
#  Author: Thimo Kraemer <thimo.kraemer@joonis.de>
#
#  Based on Templite by Tomer Filiba
#  http://code.activestate.com/recipes/496702/
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.


import sys, os
import re

class Templite(object):

    autowrite = re.compile('(^[\'\"])|(^[a-zA-Z0-9_\[\]\'\"]+$)')
    delimiters = ('${', '}$')
    cache = {}

    def __init__(self, text=None, filename=None,
                    encoding='utf-8', delimiters=None, caching=False):
        """Loads a template from string or file."""
        if filename:
            filename = os.path.abspath(filename)
            mtime = os.path.getmtime(filename)
            self.file = key = filename
        elif text is not None:
            self.file = mtime = None
            key = hash(text)
        else:
            raise ValueError('either text or filename required')
        # set attributes
        self.encoding = encoding
        self.caching = caching
        if delimiters:
            start, end = delimiters
            if len(start) != 2 or len(end) != 2:
                raise ValueError('each delimiter must be two characters long')
            self.delimiters = delimiters
        # check cache
        cache = self.cache
        if caching and key in cache and cache[key][0] == mtime:
            self._code = cache[key][1]
            return
        # read file
        if filename:
            with open(filename) as fh:
                text = fh.read()
        self._code = self._compile(text)
        if caching:
            cache[key] = (mtime, self._code)

    def _compile(self, source):
        offset = 0
        tokens = ['# -*- coding: %s -*-' % self.encoding]
        start, end = self.delimiters
        escaped = (re.escape(start), re.escape(end))
        regex = re.compile('%s(.*?)%s' % escaped, re.DOTALL)
        for i, part in enumerate(regex.split(source)):
            part = part.replace('\\'.join(start), start)
            part = part.replace('\\'.join(end), end)
            if i % 2 == 0:
                if not part: continue
                part = part.replace('\\', '\\\\').replace('"', '\\"')
                part = '\t' * offset + 'write("""%s""")' % part
            else:
                part = part.rstrip()
                if not part: continue
                part_stripped = part.lstrip()
                if part_stripped.startswith(':'):
                    if not offset:
                        raise SyntaxError('no block statement to terminate: ${%s}$' % part)
                    offset -= 1
                    part = part_stripped[1:]
                    if not part.endswith(':'): continue
                elif self.autowrite.match(part_stripped):
                    part = 'write(%s)' % part_stripped
                lines = part.splitlines()
                margin = min(len(l) - len(l.lstrip()) for l in lines if l.strip())
                part = '\n'.join('\t' * offset + l[margin:] for l in lines)
                if part.endswith(':'):
                    offset += 1
            tokens.append(part)
        if offset:
            raise SyntaxError('%i block statement(s) not terminated' % offset)
        return compile('\n'.join(tokens), self.file or '<string>', 'exec')

    def render(self, **namespace):
        """Renders the template according to the given namespace."""
        stack = []
        namespace['__file__'] = self.file
        # add write method
        def write(*args):
            for value in args:
                #if isinstance(value, str):
                #    value = value.encode(self.encoding)
                stack.append(str(value))
        namespace['write'] = write
        # add include method
        def include(file):
            if not os.path.isabs(file):
                if self.file:
                    base = os.path.dirname(self.file)
                else:
                    base = os.path.dirname(sys.argv[0])
                file = os.path.join(base, file)
            t = Templite(None, file, self.encoding,
                            self.delimiters, self.caching)
            stack.append(t.render(**namespace))
        namespace['include'] = include
        # execute template code
        exec(self._code, namespace)
        return ''.join(stack)
