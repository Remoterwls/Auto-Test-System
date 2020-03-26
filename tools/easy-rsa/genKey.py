import os, sys
import pexpect
import logging
import time
import threading
from pathlib import Path

if os.name == 'nt':
    EASY_RSA_PATH = Path('..') / 'tools' / 'easy-rsa' / 'Windows'
    KEYS_PATH = EASY_RSA_PATH / 'keys'
    LINE_BEGIN = ''
    LINE_END = os.linesep * 2
elif os.name == 'posix':
    EASY_RSA_PATH = Path('..') / 'tools' / 'easy-rsa' / 'Linux'
    KEYS_PATH = EASY_RSA_PATH / 'keys'
    LINE_BEGIN = './'
    LINE_END = os.linesep
else:
    print('Unsupported platform')
    sys.exit(1)

def is_file_valid(file):
    return os.path.exists(file) and os.path.getsize(file) > 0

def get_pexpect_child():
    if os.name == 'nt':
        from pexpect import popen_spawn

        shell = 'cmd.exe'
        child = popen_spawn.PopenSpawn(shell)
        child.expect('>')
        child.sendline('chcp 65001')
        child.expect(LINE_END)
    elif os.name == 'posix':
        shell = '/bin/bash'
        child = pexpect.spawn(shell)
    #child.logfile = sys.stdout.buffer

    return child

class build_keys(threading.Thread):
    def __init__(self, app=None):
        super().__init__()
        if app:
            self.logger = app.logger
        else:
            logging.basicConfig(level=logging.DEBUG,format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',  \
                    datefmt='%a, %d %b %Y %H:%M:%S')
            self.logger = logging

    def run(self):
        if not os.path.exists(KEYS_PATH / 'index.txt') or not is_file_valid(KEYS_PATH / 'serial'):
            self.logger.info('Clean up keys')
            start = time.time()
            child = get_pexpect_child()
            child.sendline('cd {}'.format(EASY_RSA_PATH))
            child.expect(LINE_END)

            if os.name == 'nt':
                child.sendline('vars')
            elif os.name == 'posix':
                child.sendline('source vars')
            child.expect(LINE_END)

            if os.name == 'nt':
                child.sendline('clean-all')
            elif os.name == 'posix':
                child.sendline(LINE_BEGIN + 'clean-all')
            child.expect(LINE_END)

            time.sleep(1)
            child.kill(9)

            if os.path.exists(KEYS_PATH / 'index.txt') and is_file_valid(KEYS_PATH / 'serial'):
                self.logger.info('Succeeded to clean up keys, time consumed: {}'.format(time.time() - start))
            else:
                self.logger.error('Failed to clean up keys')

        if not is_file_valid(KEYS_PATH / 'ca.key') or not is_file_valid(KEYS_PATH / 'ca.crt'):
            self.logger.info('Start to build CA key')
            start = time.time()
            child = get_pexpect_child()
            child.sendline('cd {}'.format(EASY_RSA_PATH))
            child.expect(LINE_END)

            if os.name == 'nt':
                child.sendline('vars')
            elif os.name == 'posix':
                child.sendline('source vars')
            child.expect(LINE_END)

            child.sendline(LINE_BEGIN + 'build-ca')
            child.expect(']:', timeout=30)  # Country Name
            child.send('\n')

            child.expect(']:')  # State or Province Name
            child.sendline()

            child.expect(']:')  # Locality Name
            child.sendline()

            child.expect(']:')  # Organization Name
            child.sendline()

            child.expect(']:')  # Organizational Unit Name
            child.sendline()

            child.expect(']:')  # Common Name
            child.sendline('OpenVPN-CA')

            child.expect(']:')  # Name
            child.sendline()

            child.expect(']:')  # Email Address
            child.sendline()
            child.expect(os.linesep, timeout=30)  # only one line feed works on Windows

            time.sleep(1)
            child.kill(9)

            if is_file_valid(KEYS_PATH / 'ca.key') and is_file_valid(KEYS_PATH / 'ca.crt'):
                self.logger.info('Succeeded to build CA key, time consumed: {}'.format(time.time() - start))
            else:
                self.logger.error('Failed to build CA key')
                return

        if not is_file_valid(KEYS_PATH / 'ta.key') and os.name == 'nt':
            self.logger.info('Start to build TA key')
            start = time.time()
            child = get_pexpect_child()
            child.sendline('cd {}'.format(EASY_RSA_PATH))
            child.expect(LINE_END)

            if os.name == 'nt':
                child.sendline('vars')
            elif os.name == 'posix':
                child.sendline('source vars')
            child.expect(LINE_END)

            child.sendline(LINE_BEGIN + 'build-ta')
            child.expect(LINE_END, timeout=30)

            time.sleep(1)
            child.kill(9)

            if is_file_valid(KEYS_PATH / 'ta.key'):
                self.logger.info('Succeeded to build TA key, time consumed: {}'.format(time.time() - start))
            else:
                self.logger.error('Failed to build TA key')

        if not is_file_valid(KEYS_PATH / 'server.key') or not is_file_valid(KEYS_PATH / 'server.crt'):
            self.logger.info('Start to build server key')
            start = time.time()
            child = get_pexpect_child()
            child.sendline('cd {}'.format(EASY_RSA_PATH))
            child.expect(LINE_END)

            if os.name == 'nt':
                child.sendline('vars')
            elif os.name == 'posix':
                child.sendline('source vars')
            child.expect(LINE_END)

            child.sendline(LINE_BEGIN + 'build-key-server server')
            child.expect(']:', timeout=30)  # Country Name
            #child.send('\n')
            child.sendline()

            child.expect(']:')  # State or Province Name
            child.sendline()

            child.expect(']:')  # Locality Name
            child.sendline()

            child.expect(']:')  # Organization Name
            child.sendline()

            child.expect(']:')  # Organizational Unit Name
            child.sendline()

            child.expect(']:')  # Common Name
            child.sendline('server')

            child.expect(']:')  # Name
            child.sendline()

            child.expect(']:')  # Email Address
            child.sendline()

            child.expect(']:')  # A challenge password
            #child.send('\n')    # don't know why only '\n' works
            child.sendline()

            child.expect(']:')  # An optional company name
            child.sendline()

            try:
                child.expect(r'\[y/n\]:', timeout=2)
            except pexpect.exceptions.TIMEOUT:
                self.logger.error(child.before.decode())
                child.kill(9)
                return
            child.sendline('y')

            try:
                child.expect('\[y/n\]', timeout=2)
            except pexpect.exceptions.TIMEOUT:
                self.logger.error(child.before.decode())
                self.logger.error('Signing certificate failed possibly due to repeated CSR requests')
            child.sendline('y')

            child.expect(LINE_END, timeout=30)

            time.sleep(1)
            child.kill(9)

            if is_file_valid(KEYS_PATH / 'server.key') and is_file_valid(KEYS_PATH / 'server.crt'):
                self.logger.info('Succeeded to build server key, time consumed: {}'.format(time.time() - start))
            else:
                self.logger.error('Failed to build server key')

        if not is_file_valid(KEYS_PATH / 'dh2048.pem'):
            self.logger.info('Start to build DH key')
            start = time.time()
            child = get_pexpect_child()
            child.sendline('cd {}'.format(EASY_RSA_PATH))
            child.expect(LINE_END)

            if os.name == 'nt':
                child.sendline('vars')
            elif os.name == 'posix':
                child.sendline('source vars')
            child.expect(LINE_END)

            child.sendline(LINE_BEGIN + 'build-dh')
            child.expect(r'[\.\+\*]{3}' + LINE_END, timeout=2000)

            time.sleep(1)
            child.kill(9)

            if is_file_valid(KEYS_PATH / 'dh2048.pem'):
                self.logger.info('Succeeded to build DH key, time consumed: {}'.format(time.time() - start))
            else:
                self.logger.error('Failed to build DH key')

def build_easyrsa_keys():
    thread = build_keys()
    thread.daemon = True
    thread.start()

if __name__ == '__main__':
    thread = build_keys()
    thread.start()
    thread.join()