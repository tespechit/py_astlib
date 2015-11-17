
import socket
# https://docs.python.org/2/library/socket.html

__author__ = 'Aleksei Gusev'


class BasePacket(dict):
    EOL = '\r\n'
    EOL2 = '\r\n\r\n'
    last_response_packet = {}
    __is_last = None

    def __init__(self, **kwargs):
        super(BasePacket, self).__init__(**kwargs)
        self.set_action_id()

    @property
    def is_response(self):
        if self.get('Event') and self.get('Privilege'):
            return False
        elif self.get('Response'):
            return True
        else:
            return False

    @property
    def is_last(self):
        if self.__is_last is None and self.last_response_packet and isinstance(self.last_response_packet, dict):
            key = self.last_response_packet.keys()[0]
            value = self.last_response_packet.values()[0]
            self.__is_last = self.get(key) == value

        return self.__is_last

    def set_action_id(self, action_id=None):
        self['ActionID'] = action_id or 'pal_id_%s' % hex(id(self))
        return self['ActionID']

    def decode(self, packet_row):
        new_packet = BasePacket()
        new_packet.last_response_packet = self.last_response_packet.copy()
        new_packet.set_action_id(self.get('ActionID'))

        try:
            for row in packet_row.split(new_packet.EOL):
                k, v = row.split(':', 1)
                new_packet[k.strip()] = v.strip()

        except Exception as e:
            print(e, packet_row)
        finally:
            return new_packet

    def encode(self, full=True, encoding='utf8'):
        """
        Serialise packet in dict to single string

        Args:
            full (bool): If true add end packet sequence.
            encoding (str): Encoding tag.

        """

        _order = ['Event', 'EventList']

        custom_fields = list(set(self.keys()).difference(set(_order)))
        packet_fields = _order
        packet_fields.extend(custom_fields)
        packet_l = list('%s: %s' % (field_name, (self[field_name]).encode(encoding))
                        for field_name in packet_fields if self.get(field_name))

        return '%s%s' % (self.EOL.join(packet_l), self.EOL2 if full is True else self.EOL)


class LoginPacket(BasePacket):
    def __init__(self, username, password, events='off'):
        super(LoginPacket, self).__init__()

        if not events:
            events = 'off'

        self['Action'] = 'Login'
        self['Events'] = events
        self.username = self['Username'] = username
        self.password = self['Secret'] = password


class LogoffPacket(BasePacket):
    def __init__(self):
        super(LogoffPacket, self).__init__()
        self['Action'] = 'Logoff'


class OriginatePacket(BasePacket):
    def __init__(self, channel, caller_id=None, account=None,
                 app=None, app_data=None, context=None, exten=None, priority=None,
                 timeout=30.0, async=1, get_orig_response=True, **variables):
        self.channel = channel
        self.account = str(account if account else 'pal_originate_call')[:20]
        self.originate_timeout = timeout
        self.async = bool(async)
        self.caller_id = caller_id if caller_id else '-'

        if get_orig_response is True:
            self.async = True
            self.last_response_packet = {'Event': 'OriginateResponse'}

        super(OriginatePacket, self).__init__(
            Action='Originate',
            Channel=self.channel,
            Timeout='%d' % (self.originate_timeout * 1000),
            Async='%d' % self.async,
            CallerID=self.caller_id,
            Account=self.account,
        )

        if app:
            app_data = app_data or ''
            self['Application'] = '%s' % app
            self['Data'] = '%s' % app_data

        elif context and exten and priority:
            self['Exten'] = '%s' % exten
            self['Context'] = '%s' % context
            self['Priority'] = '%d' % priority

        else:
            raise TypeError('__init__() required app, [app_data] or context, exten, priority arguments')

        if variables:
            if isinstance(variables, dict):
                if len(variables.keys()) > 32:
                    raise OverflowError('Originate variable field limited to 32 vars')

                self['Variable'] = ','.join(['%s=%s' % (k, v) for k, v in variables.items()])
            else:
                self['Variable'] = '%s' % variables


class Response(object):
    def __init__(self, response_packets, parse=True, *args, **kwargs):
        self.data = []
        self.last = {}
        self.response = {}
        self._parsed = False
        self._response = response_packets

        if parse is True:
            self._parse()

    def __str__(self):
        return 'Response: %s, %s data item(s)' % (self.response.get('Response', 'None'), len(self.data))

    # def __repr__(self):
    #     return str('%s %s %s' % (self.response, self.data, self.last))

    def _parse(self):
        for p in self._response:
            if hasattr(p, 'is_response') and hasattr(p, 'is_last'):
                if p.is_response:
                    self.response = p
                elif p.is_last:
                    self.last = p
                    if not self.data:
                        self.data.append(self.last)
                else:
                    self.data.append(p)

        if self.response or self.data:
            self._parsed = True

        return self.data if self.data else self.response


class AsteriskManager(object):
    __action_id = ''
    __timeout = None
    __event_mask = {'off'}
    __known_event_mask = {'on', 'off', 'all', 'agent', 'agi', 'call', 'cdr',
                          'command', 'config', 'dialplan', 'dtmf', 'log',
                          'originate', 'reporting', 'system', 'user', 'verbose'}
    _default_timeout = 30.0
    _socket = None
    _connected = None
    _recv_buf = ''
    EOL = '\r\n'
    EOL2 = '\r\n\r\n'

    def __init__(self, host, username, password, port=5038, encoding='utf8'):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self._encoding = encoding

        self.__validate()

    @property
    def _timeout(self):
        return self.__timeout

    @_timeout.setter
    def _timeout(self, timeout):
        if timeout is None:
            pass
        else:
            self.__timeout = float(timeout)

        self.__timeout = timeout
        self._socket.settimeout(self.__timeout)

    @property
    def _event_mask(self):
        return self.__event_mask

    @_event_mask.setter
    def _event_mask(self, event_mask):
        if isinstance(event_mask, (list, tuple, set)):
            if 'off' in event_mask:
                self.__event_mask = {'off'}
            elif 'on' in event_mask:
                self.__event_mask = {'on'}
            elif 'all' in event_mask:
                self.__event_mask = {'all'}
            else:
                self.__event_mask = set(event_mask)
        else:
            raise ValueError('Sequence required')

    def __validate(self):
        for attr_name in ['host', 'username', 'password']:
            attr = getattr(self, attr_name, '')
            if not isinstance(attr, str):
                setattr(self, attr_name, attr.encode(self._encoding))

        self.port = int(self.port)

    def _connect(self, timeout=None):
        self.__timeout = self._default_timeout if not timeout else float(timeout)

        if not self._connected or not self._socket:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self._socket.connect((self.host, self.port))
            self._socket.setblocking(0)

            self._socket.settimeout(self.__timeout)

            welcome_buf = self._socket.recv(1024)
            if 'Asterisk Call Manager' not in welcome_buf:
                raise Exception('Wrong socket welcome string "%s"' % welcome_buf.strip())

            self._connected = True

    def _close(self):
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.disconnect()
        except:
            pass
        finally:
            self._socket = None
            self._connected = False

    def _send(self, send_buf):
        if not self._socket or not self._connected:
            raise Exception('Socket not connected')

        return self._socket.sendall(send_buf)

    def _read_packet(self, buf_size=1024, timeout=None):
        if not self._socket or not self._connected:
            raise Exception('Socket not connected')

        if timeout:
            self._timeout = timeout

        while 1:
            # time.sleep(.5)
            recv_buf = ''
            if self.EOL2 not in self._recv_buf:
                recv_buf = self._socket.recv(buf_size)

                if not recv_buf:
                    continue

            self._recv_buf = '%s%s' % (self._recv_buf, recv_buf)

            if self.EOL2 in self._recv_buf:
                packet, self._recv_buf = self._recv_buf.split(self.EOL2, 1)
                return packet

    def _authenticate(self):
        login_packet = LoginPacket(username=self.username, password=self.password, events='off')

        for packet in self.send(login_packet):
            if packet.is_response:
                break

    def connect(self, timeout=None):
        self._connect(timeout)
        self._authenticate()

    def disconnect(self):
        try:
            self._send(LogoffPacket().encode())
        except:
            pass
        self._close()

    def send(self, request_packet):
        self._send(request_packet.encode())
        resp_events = []
        keep_reading = 1

        try:
            while keep_reading:
                new_packet_row = self._read_packet()

                if new_packet_row and request_packet['ActionID'] in new_packet_row:
                    new_packet = request_packet.decode(new_packet_row)

                    resp_events.append(new_packet)
                    if new_packet.is_last is True:
                        keep_reading = 0

                    else:
                        if new_packet.is_response:
                            if new_packet['Response'] != 'Success':
                                keep_reading = 0

                            elif not new_packet.last_response_packet:
                                keep_reading = 0

                # else:
                #     print('\n   --> default in AMI.send next(iter_packet)', new_packet_row[:40])

        except socket.timeout:
            raise

        return resp_events

    def events(self, event_mask='on'):
        """
        Set event mask to specified

        Args:
            event_mask: List or comma separated string of event masks' names
                on - If all events should be sent.
                off - If no events should be sent.
                all - Equal to on.
                system,call,log,... - To select which flags events should have to be sent.

                all, agent, agi, call, cdr, command, config, dialplan,
                dtmf, log, originate, reporting, system, user, verbose

        """

        if isinstance(event_mask, (str, unicode)):
            event_mask = [str(i) for i in event_mask.replace(' ', '').split(',')]
        elif isinstance(event_mask, (list, tuple, set)):
            event_mask = set(event_mask)

        action_packet = BasePacket(Action='Events', EventMask='%s' % ','.join(event_mask))
        resp_events = self.send(action_packet)
        for packet in resp_events:
            if packet.is_response:
                self.__event_mask = event_mask
                break

        return resp_events

    def listen(self, event_mask='on'):
        self.events(event_mask=event_mask)
        self._timeout = self._default_timeout

        while 1:
            yield BasePacket().decode(self._read_packet())


class AMI(AsteriskManager):

    def ping(self):
        return Response(self.send(BasePacket(Action='Ping')))

    def core_show_channels(self):
        packet = BasePacket(Action='CoreShowChannels')
        packet.last_response_packet = {'Event': 'CoreShowChannelsComplete'}
        return Response(self.send(packet))

    def sip_peer_status(self):
        packet = BasePacket(Action='SipPeerStatus')
        packet.last_response_packet = {'Event': 'SIPpeerstatusComplete'}
        return Response(self.send(packet))

    def sip_show_peer(self, peer):
        return Response(self.send(BasePacket(Action='SIPshowpeer', Peer=str(peer))))

    def originate(self, tech=None, data=None, channel=None, caller_id=None, account=None,
                  app=None, app_data=None, context=None, exten=None, priority=None,
                  timeout=30.0, async=1, get_orig_response=True, **variables):

        if tech and data:
            channel = '%s/%s' % (tech, data)

        ev_mask = self._event_mask
        if get_orig_response is True:
            new_ev_mask = self._event_mask.union({'call'})
            self.events(event_mask=new_ev_mask)

        packet = OriginatePacket(channel, caller_id=caller_id, account=account,
                                 app=app, app_data=app_data, context=context, exten=exten, priority=priority,
                                 timeout=timeout, async=async, get_orig_response=get_orig_response, **variables)

        timeout = self._timeout
        # change socket timeout to originate timeout + 1 sec
        if not async:
            self._timeout = packet.originate_timeout + 1

        result = self.send(packet)

        self._timeout = timeout

        if get_orig_response is True:
            self.events(event_mask=ev_mask)

        return Response(result)


