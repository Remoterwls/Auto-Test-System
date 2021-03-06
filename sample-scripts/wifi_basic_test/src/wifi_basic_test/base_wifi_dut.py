import os.path
import re

from robotest_utilities.dut import serial_dut
from robotest_utilities.download_fw import download_fw_intf

class base_wifi_dut(serial_dut, download_fw_intf):
    SCAN_TIMEOUT = 5        # seconds
    CONNECT_TIMEOUT = 25    # seconds

    REGEXP_IP = r'(\d{1,3}(\.\d{1,3}){3})'

    def __init__(self, daemon_config, task_id):
        super().__init__(daemon_config, task_id)
        self.ip_AP = None
        self.ip_DUT = None
        self.SSID = None
        self.INFRA_MODE = None
        self.configAP = {}

        for ap in self.config['AP']:
            self.configAP[ap['name']] = ap

    def open_wifi(self, deviceName):
        dut = self.configDut[deviceName]
        dut['serialport'].write(b'wifi_open\r')
        result = self._serial_read(deviceName, self.TIMEOUT)[0]
        print(result)

    def close_wifi(self, deviceName):
        dut = self.configDut[deviceName]
        dut['serialport'].write(b'wifi_close\r')
        result = self._serial_read(deviceName, self.TIMEOUT)[0]
        print(result)

    def scan_networks(self, deviceName):
        self._flush_serial_output(deviceName)

        dut = self.configDut[deviceName]
        dut['serialport'].write(b'wifi_scan\r')
        (result, elapsedTime, _) = self._serial_read(deviceName, self.SCAN_TIMEOUT, 'scan finished')
        print(result)

        if elapsedTime == self.TIMEOUT_ERR:
            raise AssertionError('Scan timeout')
        print('Scan used time {0}s'.format(elapsedTime))

    def connect_to_network(self, deviceName, ssid, password):
        self._flush_serial_output(deviceName)

        dut = self.configDut[deviceName]
        dut['serialport'].write('wifi_connect {0} {1}\r'.format(ssid, password).encode())
        (result, elapsedTime, _) = self._serial_read(deviceName, self.CONNECT_TIMEOUT, 'ip configured')
        print(result)

        if elapsedTime == self.TIMEOUT_ERR:
            raise AssertionError('Connecting to {} timeout'.format(ssid))
        print('Connecting used time {0}s'.format(elapsedTime))

        ret = re.compile('IP: {0}'.format(self.REGEXP_IP)).search(result)
        if ret and ret.groups():
            self.ip_DUT = ret.groups()[0]
            ip = self.ip_DUT.split('.')
            ip.pop()
            ip.append('1')
            self.IP_AP = '.'.join(ip)
            self.SSID = ssid
            self.INFRA_MODE = 'Station'
        else:
            raise AssertionError("Can't get device's IP")
        return self.ip_DUT

    def disconnect_network(self, deviceName):
        self._flush_serial_output(deviceName)

        dut = self.configDut[deviceName]
        dut['serialport'].write(b'wifi_disconnect\r')
        (result, elapsedTime, _) = self._serial_read(deviceName, self.CONNECT_TIMEOUT, 'Stop DHCP')
        print(result)

        if elapsedTime == self.TIMEOUT_ERR:
            raise AssertionError('Disconnecting timeout')
        print('Disconnecting used time {0}s'.format(elapsedTime))

    def create_softap(self, deviceName, ssid, passwd, channel, hidden):
        self._flush_serial_output(deviceName)

        dut = self.configDut[deviceName]
        dut['serialport'].write('wifi_ap_adv {} {} {} {}\r'.format(ssid, passwd, channel, hidden).encode())
        (result, elapsedTime, _) = self._serial_read(deviceName, self.CONNECT_TIMEOUT, 'softap {} started!'.format(re.escape(ssid)))
        print(result)

        if elapsedTime == self.TIMEOUT_ERR:
            raise AssertionError('Setup softap timeout')
        print('Setup softap used time {0}s'.format(elapsedTime))
        # we need return softap ip address
        self.ip_DUT = dut['softap_ip']
        self.SSID = ssid
        self.INFRA_MODE = 'Soft AP'
        return self.ip_DUT