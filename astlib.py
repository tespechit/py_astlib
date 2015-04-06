#!/usr/bin/env python

import socket

# https://docs.python.org/2/library/socket.html


class AstBase(object):
    mask = 'off'

    def __init__(self, host, user, password, port=5038):
        # TODO # add port validation
        self.connect_info = {'host': host, 'port': int(port), 'user': user, 'password': password}

    def _connect(self, socket_timeout=None):
        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # if socket_timeout is None or socket_timeout > 0:
        #     pass
        #     # print('send to blocking socket, timeout "%s"' % socket_timeout)
        # elif socket_timeout == 0.0:
        #     print('send to non blocking socket, timeout "%s"' % socket_timeout)
        # else:
        #     raise Exception('send to ELSE socket, timeout "%s"' % socket_timeout)

        _socket.settimeout(socket_timeout)
        _socket.connect((self.connect_info['host'], self.connect_info['port']))

        return _socket

    def _raw_send_s(self, send_buf, recv_buf_size=1024*1024, socket_timeout=None, stop_buf=None):
        response = ()

        if stop_buf:
            _socket = self._connect()
        else:
            _socket = self._connect(socket_timeout=socket_timeout)

        try:
            send_buf = str(send_buf)
            # print(type(send_buf), send_buf)
            # print('--[%s]--' % send_buf)
            _socket.sendall(send_buf)
            while 1:
                recv_buf = _socket.recv(recv_buf_size)
                # print('--[%s]--' % recv_buf)

                if recv_buf:
                    response += (recv_buf,)
                    if stop_buf:
                        # TODO # do something for case insensitive compare
                        if stop_buf in recv_buf:
                            # print('----- stop buf break')
                            break
                else:
                    # print('----- break')
                    break

        except socket.timeout as ste:
            if stop_buf:
                raise ste

        # print('socket shutdown', _socket.shutdown(0))
        # print('socket close', _socket.close())

        # print('--%s--' % ''.join(response))
        return ''.join(response)

    def set_events_mask(self, mask):
        pass
        # FIX ME
        # validate mask here
        # self.mask = mask
        # response = self.raw_send('Action: Events\r\nActionID: ALP_%s_EventsMask\r\nEventMask: %s\r\n\r\n'
        #                          % (self.mask, self.connect_data['user']))
        # response = self.parse_packets(response)

    def set_events_off(self):
        return self.set_events_mask('off')


class AstMI(AstBase):
    socket_timeout = None

    def command_s(self, send_buf, action_id=None, stop_buf=None, socket_timeout=1.0):
        if socket_timeout:
            self.socket_timeout = socket_timeout

        if isinstance(send_buf, (str, type(u''))):
            pass
        elif isinstance(send_buf, dict):
            send_buf = encode_packet(**send_buf)
        else:
            raise ValueError('send buffer - wrong data type(%s)' % type(send_buf))

        if send_buf.lower().find('actionid: ') >= 0:
            action_id = None
        else:
            if action_id:
                send_buf = send_buf.replace('\r\n\r\n', '\r\nActionID: %s\r\n\r\n' % action_id)
            else:
                send_buf = send_buf.replace('\r\n\r\n', '\r\nActionID: ALP_%s_Command\r\n\r\n'
                                                        % self.connect_info['user'])
                action_id = None

        send_buf_s = ('Action: Login\r\nUsername: %(user)s\r\n'
                      'Secret: %(password)s\r\nEvents: off\r\n\r\n' % self.connect_info)
        send_logoff = 'Action: Logoff\r\n\r\n'
        if action_id:
            send_logoff = send_buf.replace('\r\n\r\n', '\r\nActionID: %s\r\n\r\n' % action_id)

        send_buf_s = '%s%s%s' % (send_buf_s, send_buf, send_logoff)

        # ts = [time.time()]
        response = self._raw_send_s(send_buf=send_buf_s, recv_buf_size=1024*1024,
                                    socket_timeout=self.socket_timeout, stop_buf=stop_buf)
        # ts.append(time.time())
        # print(ts[1]-ts[0])
        return parse_packets(response, action_id)

    # ami methods
    def show_channels_s(self, key=None):
        send_d = {'Action': 'CoreShowChannels',
                  'ActionID': 'ALP_%s_CoreShowChannels' % self.connect_info['user']}
        stop_buf = 'Event: CoreShowChannelsComplete\r\nEventList: Complete\r\n'

        response = self.command_s(send_d, stop_buf=stop_buf)

        if not response:
            return {}

        # handle response, check final packet
        fin = response[-1]
        if fin.get('event') == 'CoreShowChannelsComplete':
            if fin.get('eventlist') != 'Complete':
                raise Exception('Core Show Channels Complete: "%s"' % fin.get('eventlist'))
        else:
            raise Exception('Core Show Channels: no FIN packet')

        if key:
            key = str(key).lower()
            if key not in ('channel', 'uniqueid', 'bridgedchannel', 'bridgeduniqueid', 'calleridname', 'calleridnum'):
                key = 'channel'

            return dict((pd[key], pd) for pd in response if pd.get('event') == 'CoreShowChannel')
        else:
            return tuple(pd for pd in response if pd.get('event') == 'CoreShowChannel')

    def sip_show_peer(self, peer):
        """
        peer name must be specified
        """
        send_d = {'Action': 'SIPShowPeer',
                  'ActionID': 'ALP_%s_SIPShowPeer' % self.connect_info['user'],
                  'Peer': peer}
        stop_buf = '\r\nResponse: Goodbye\r\n'

        response = tuple(d for d in self.command_s(send_d, stop_buf=stop_buf) if d.get('objectname') == peer)

        if not response:
            return ()

        return response

    def sip_peer_status(self, peer=None):
        send_d = {'Action': 'SIPpeerStatus',
                  'ActionID': 'ALP_%s_SIPPeerStatus' % self.connect_info['user'],
                  'Peer': peer}
        stop_buf = '\r\nEvent: SIPpeerstatusComplete\r\n'

        response = tuple(d for d in self.command_s(send_d, stop_buf=stop_buf) if d.get('event') == 'PeerStatus')

        if not response:
            return ()

        return response

    def sip_peers_s(self, key=None):
        send_d = {'Action': 'SIPPeers', 'ActionID': 'ALP_%s_SipShowPeers' % self.connect_info['user']}
        stop_buf = 'Event: PeerlistComplete\r\nEventList: Complete\r\n'

        response = self.command_s(send_d, stop_buf=stop_buf)

        if not response:
            return {}

        # handle response, check final packet
        fin = response[-1]
        if fin.get('event') == 'PeerlistComplete':
            if fin.get('eventlist') != 'Complete':
                raise Exception('Sip Show Peers Complete: "%s"' % fin.get('eventlist'))
        else:
            raise Exception('Sip Show Peers: no FIN packet')

        if key:
            key = str(key).lower()
            if key not in ('objectname',):
                key = 'objectname'

            return dict((pd[key], pd) for pd in response if pd.get('event') == 'PeerEntry')
        else:
            return tuple(pd for pd in response if pd.get('event') == 'PeerEntry')

    def iax_peer_list_s(self, key=None):
        send_d = {'Action': 'IAXpeerlist', 'ActionID': 'ALP_%s_IaxShowPeers' % self.connect_info['user']}
        stop_buf = 'Event: PeerlistComplete\r\nEventList: Complete\r\n'

        raise Exception('Method not ready')

    # # queues ami
    def queue_status_s(self, queue=None, member=None):
        """


        # Status numbers
        # 1 - Not in Use
        # 2 - In Use
        # 3 - Busy
        # 4 -
        # 5 - Unavailable
        # 6 - Ringing
        """
        send_d = {'Action': 'QueueStatus', 'ActionID': 'ALP_%s_QueueStatus' % self.connect_info['user']}
        stop_buf = 'Event: QueueStatusComplete\r\n'

        if queue:
            send_d['Queue'] = '%s' % queue

        if member:
            send_d['Member'] = '%s' % member

        response = self.command_s(send_d, stop_buf=stop_buf)

        if not response:
            return {}

        # handle response, check final packet
        fin = response[-1]
        if fin.get('event') != 'QueueStatusComplete':
            raise Exception('Queue Status: no FIN packet')

        result = {'queue_params': {}, 'queue_entries': {}, 'queue_members': {}}
        for pd in response:
            if pd.get('event') == 'QueueParams':
                result['queue_params'].update({pd.get('queue'): pd})
            elif pd.get('event') == 'QueueEntry':
                result['queue_entries'].update({pd.get('channel'): pd})
            elif pd.get('event') == 'QueueMember':
                if not result['queue_members'].get(pd['name']):
                    result['queue_members'].update({pd['name']: pd})
                else:
                    result['queue_members'][pd['name']].update(pd)

                if not result['queue_members'][pd['name']].get('queues'):
                    result['queue_members'][pd['name']]['queues'] = ()
                result['queue_members'][pd['name']]['queues'] += (result['queue_members'][pd['name']].pop('queue'),)

            else:
                pass

        return result

    def queues_status_all_s(self):
        return self.queue_status_s()


# --- helpers ----------------------------------------------------------------------------------------------------------


def parse_packets(data, action_id=None):
    packets = ()
    if not isinstance(data, (str, type(u''))):
        raise ValueError('Wrong input data type, got %s, need str or unicode' % type(data))

    for packet_row in data.split('\r\n\r\n'):
        pd = decode_packet(packet_row)
        if pd:
            if pd.get('response'):
                if pd['response'] in ['Success']:
                    pass
                elif pd['response'] in ['Goodbye']:
                    continue
                # elif pd['response'] != 'Success':
                #     packets += (pd,)
                #     raise Exception(pd)
                else:
                    packets += (pd,)
                    raise Exception(pd)

            if action_id:
                if pd.get('actionid') == action_id:
                    packets += (pd,)
            else:
                pd.pop('actionid', None)
                packets += (pd,)

    return packets


def encode_packet(full=True, **kwargs):
    ENDL = u'\r\n'
    _order = [u'Event', u'EventList']

    custom_fields = list(set(kwargs.keys()).difference(set(_order)))
    packet_fields = _order
    packet_fields.extend(custom_fields)
    packet_l = list(u'%s: %s' % (field_name, kwargs[field_name])
                    for field_name in packet_fields if kwargs.get(field_name))

    return u'%s%s' % (ENDL.join(packet_l), ENDL*2 if full is True else ENDL)


def decode_packet(packet_row):
    # full uncut packet must be in packet_row as single string
    packet = {}
    rows = packet_row.split('\r\n')
    rows.reverse()
    val_pieces = []
    for row in rows:
        pair = row.split(': ', 1)
        if len(pair) == 2:
            key, val = pair
            key = key.strip().lower()
            val_pieces.insert(0, val)
            packet[key] = '\r\n'.join(val_pieces)
            val_pieces = []

        elif len(pair) == 1 and pair[0]:
            val_pieces.insert(0, pair[0])

    return packet


