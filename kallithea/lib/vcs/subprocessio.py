"""
Module provides a class allowing to wrap communication over subprocess.Popen
input, output, error streams into a meaningful, non-blocking, concurrent
stream processor exposing the output data as an iterator fitting to be a
return value passed by a WSGI application to a WSGI server per PEP 3333.

Copyright (c) 2011  Daniel Dotsenko <dotsa[at]hotmail.com>

This file is part of git_http_backend.py Project.

git_http_backend.py Project is free software: you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation, either version 2.1 of the License,
or (at your option) any later version.

git_http_backend.py Project is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with git_http_backend.py Project.
If not, see <http://www.gnu.org/licenses/>.
"""
import collections
import os
import subprocess
import threading


class StreamFeeder(threading.Thread):
    """
    Normal writing into pipe-like is blocking once the buffer is filled.
    This thread allows a thread to seep data from a file-like into a pipe
    without blocking the main thread.
    We close inpipe once the end of the source stream is reached.
    """

    def __init__(self, source):
        super(StreamFeeder, self).__init__()
        self.daemon = True
        filelike = False
        self.bytes = bytes()
        if type(source) in (type(''), bytes, bytearray):  # string-like
            self.bytes = bytes(source)
        else:  # can be either file pointer or file-like
            if isinstance(source, int):  # file pointer it is
                # converting file descriptor (int) stdin into file-like
                source = os.fdopen(source, 'rb', 16384)
            # let's see if source is file-like by now
            filelike = hasattr(source, 'read')
        if not filelike and not self.bytes:
            raise TypeError("StreamFeeder's source object must be a readable "
                            "file-like, a file descriptor, or a string-like.")
        self.source = source
        self.readiface, self.writeiface = os.pipe()

    def run(self):
        t = self.writeiface
        if self.bytes:
            os.write(t, self.bytes)
        else:
            s = self.source
            b = s.read(4096)
            while b:
                os.write(t, b)
                b = s.read(4096)
        os.close(t)

    @property
    def output(self):
        return self.readiface


class InputStreamChunker(threading.Thread):
    def __init__(self, source, target, buffer_size, chunk_size):

        super(InputStreamChunker, self).__init__()

        self.daemon = True  # die die die.

        self.source = source
        self.target = target
        self.chunk_count_max = int(buffer_size / chunk_size) + 1
        self.chunk_size = chunk_size

        self.data_added = threading.Event()
        self.data_added.clear()

        self.keep_reading = threading.Event()
        self.keep_reading.set()

        self.EOF = threading.Event()
        self.EOF.clear()

        self.go = threading.Event()
        self.go.set()

    def stop(self):
        self.go.clear()
        self.EOF.set()
        try:
            # this is not proper, but is done to force the reader thread let
            # go of the input because, if successful, .close() will send EOF
            # down the pipe.
            self.source.close()
        except:
            pass

    def run(self):
        s = self.source
        t = self.target
        cs = self.chunk_size
        ccm = self.chunk_count_max
        kr = self.keep_reading
        da = self.data_added
        go = self.go

        try:
            b = s.read(cs)
        except ValueError:
            b = ''

        while b and go.is_set():
            if len(t) > ccm:
                kr.clear()
                kr.wait(2)
                if not kr.wait(10):
                    raise IOError(
                        "Timed out while waiting for input from subprocess.")
            t.append(b)
            da.set()
            try:
                b = s.read(cs)
            except ValueError: # probably "I/O operation on closed file"
                b = ''

        self.EOF.set()
        da.set()  # for cases when done but there was no input.


class BufferedGenerator(object):
    """
    Class behaves as a non-blocking, buffered pipe reader.
    Reads chunks of data (through a thread)
    from a blocking pipe, and attaches these to an array (Deque) of chunks.
    Reading is halted in the thread when max chunks is internally buffered.
    The .next() may operate in blocking or non-blocking fashion by yielding
    '' if no data is ready
    to be sent or by not returning until there is some data to send
    When we get EOF from underlying source pipe we raise the marker to raise
    StopIteration after the last chunk of data is yielded.
    """

    def __init__(self, source, buffer_size=65536, chunk_size=4096,
                 starting_values=None, bottomless=False):
        starting_values = starting_values or []
        if bottomless:
            maxlen = int(buffer_size / chunk_size)
        else:
            maxlen = None

        self.data = collections.deque(starting_values, maxlen)
        self.worker = InputStreamChunker(source, self.data, buffer_size,
                                         chunk_size)
        if starting_values:
            self.worker.data_added.set()
        self.worker.start()

    ####################
    # Generator's methods
    ####################

    def __iter__(self):
        return self

    def __next__(self):
        while not len(self.data) and not self.worker.EOF.is_set():
            self.worker.data_added.clear()
            self.worker.data_added.wait(0.2)
        if len(self.data):
            self.worker.keep_reading.set()
            return bytes(self.data.popleft())
        elif self.worker.EOF.is_set():
            raise StopIteration

    def throw(self, type, value=None, traceback=None):
        if not self.worker.EOF.is_set():
            raise type(value)

    def start(self):
        self.worker.start()

    def stop(self):
        self.worker.stop()

    def close(self):
        try:
            self.worker.stop()
            self.throw(GeneratorExit)
        except (GeneratorExit, StopIteration):
            pass

    ####################
    # Threaded reader's infrastructure.
    ####################
    @property
    def input(self):
        return self.worker.w

    @property
    def data_added_event(self):
        return self.worker.data_added

    @property
    def data_added(self):
        return self.worker.data_added.is_set()

    @property
    def reading_paused(self):
        return not self.worker.keep_reading.is_set()

    @property
    def done_reading(self):
        """
        Done_reading does not mean that the iterator's buffer is empty.
        Iterator might have done reading from underlying source, but the read
        chunks might still be available for serving through .next() method.

        :returns: An Bool value.
        """
        return self.worker.EOF.is_set()

    @property
    def length(self):
        """
        returns int.

        This is the length of the queue of chunks, not the length of
        the combined contents in those chunks.

        __len__() cannot be meaningfully implemented because this
        reader is just flying through a bottomless pit content and
        can only know the length of what it already saw.

        If __len__() on WSGI server per PEP 3333 returns a value,
        the response's length will be set to that. In order not to
        confuse WSGI PEP3333 servers, we will not implement __len__
        at all.
        """
        return len(self.data)

    def prepend(self, x):
        self.data.appendleft(x)

    def append(self, x):
        self.data.append(x)

    def extend(self, o):
        self.data.extend(o)

    def __getitem__(self, i):
        return self.data[i]


class SubprocessIOChunker(object):
    """
    Processor class wrapping handling of subprocess IO.

    In a way, this is a "communicate()" replacement with a twist.

    - We are multithreaded. Writing in and reading out, err are all sep threads.
    - We support concurrent (in and out) stream processing.
    - The output is not a stream. It's a queue of read string (bytes, not str)
      chunks. The object behaves as an iterable. You can "for chunk in obj:" us.
    - We are non-blocking in more respects than communicate()
      (reading from subprocess out pauses when internal buffer is full, but
       does not block the parent calling code. On the flip side, reading from
       slow-yielding subprocess may block the iteration until data shows up. This
       does not block the parallel inpipe reading occurring parallel thread.)

    The purpose of the object is to allow us to wrap subprocess interactions into
    an iterable that can be passed to a WSGI server as the application's return
    value. Because of stream-processing-ability, WSGI does not have to read ALL
    of the subprocess's output and buffer it, before handing it to WSGI server for
    HTTP response. Instead, the class initializer reads just a bit of the stream
    to figure out if error occurred or likely to occur and if not, just hands the
    further iteration over subprocess output to the server for completion of HTTP
    response.

    The real or perceived subprocess error is trapped and raised as one of
    EnvironmentError family of exceptions

    Example usage:
    #    try:
    #        answer = SubprocessIOChunker(
    #            cmd,
    #            input,
    #            buffer_size = 65536,
    #            chunk_size = 4096
    #            )
    #    except (EnvironmentError) as e:
    #        print str(e)
    #        raise e
    #
    #    return answer


    """

    def __init__(self, cmd, inputstream=None, buffer_size=65536,
                 chunk_size=4096, starting_values=None, **kwargs):
        """
        Initializes SubprocessIOChunker

        :param cmd: A Subprocess.Popen style "cmd". Can be string or array of strings
        :param inputstream: (Default: None) A file-like, string, or file pointer.
        :param buffer_size: (Default: 65536) A size of total buffer per stream in bytes.
        :param chunk_size: (Default: 4096) A max size of a chunk. Actual chunk may be smaller.
        :param starting_values: (Default: []) An array of strings to put in front of output que.
        """
        starting_values = starting_values or []
        if inputstream:
            input_streamer = StreamFeeder(inputstream)
            input_streamer.start()
            inputstream = input_streamer.output

        # Note: fragile cmd mangling has been removed for use in Kallithea
        assert isinstance(cmd, list), cmd

        _p = subprocess.Popen(cmd, bufsize=-1,
                              stdin=inputstream,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              **kwargs)

        bg_out = BufferedGenerator(_p.stdout, buffer_size, chunk_size,
                                   starting_values)
        bg_err = BufferedGenerator(_p.stderr, 16000, 1, bottomless=True)

        while not bg_out.done_reading and not bg_out.reading_paused:
            # doing this until we reach either end of file, or end of buffer.
            bg_out.data_added_event.wait(1)
            bg_out.data_added_event.clear()

        # at this point it's still ambiguous if we are done reading or just full buffer.
        # Either way, if error (returned by ended process, or implied based on
        # presence of stuff in stderr output) we error out.
        # Else, we are happy.
        returncode = _p.poll()
        if (returncode is not None # process has terminated
            and returncode != 0
        ): # and it failed
            bg_out.stop()
            out = b''.join(bg_out)
            bg_err.stop()
            err = b''.join(bg_err)
            if (err.strip() == b'fatal: The remote end hung up unexpectedly' and
                out.startswith(b'0034shallow ')
            ):
                # hack inspired by https://github.com/schacon/grack/pull/7
                bg_out = iter([out])
                _p = None
            elif err:
                raise EnvironmentError("Subprocess exited due to an error: %s" % err)
            else:
                raise EnvironmentError(
                    "Subprocess exited with non 0 ret code: %s" % returncode)
        self.process = _p
        self.output = bg_out
        self.error = bg_err
        self.inputstream = inputstream

    def __iter__(self):
        return self

    def __next__(self):
        if self.process:
            returncode = self.process.poll()
            if (returncode is not None # process has terminated
                and returncode != 0
            ): # and it failed
                getattr(self.output, 'stop', lambda: None)()
                self.error.stop()
                err = ''.join(self.error)
                raise EnvironmentError("Subprocess exited due to an error:\n" + err)
        return next(self.output)

    def throw(self, type, value=None, traceback=None):
        if getattr(self.output, 'length') or not getattr(self.output, 'done_reading'):
            raise type(value)

    def close(self):
        try:
            getattr(self.process, 'terminate', lambda: None)()
        except:
            pass
        try:
            getattr(self.output, 'close', lambda: None)()
        except:
            pass
        try:
            self.error.close()
        except:
            pass
        try:
            os.close(self.inputstream)
        except:
            pass
