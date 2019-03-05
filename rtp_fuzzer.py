#!/usr/bin/python
# -*- coding: utf-8 -*-
# from scapy.all import *
from bitstring import BitArray
from itertools import islice, product, chain
from ConfigParser import ConfigParser
import socket
import os
import time
import hashlib
import random
import string
import sys


#global varible
config = ConfigParser()
config.read('rtp.conf')
RHOST = config.get('rtpfuzz', 'RHOST')
RPORT = config.get('rtpfuzz', 'RPORT')
DELAY = config.get('rtpfuzz', 'DELAY')
junk = config.get('rtpfuzz', 'JUNK')
msfpat = config.get('rtpfuzz', 'MSFPATTERN')
STOPAFTER = config.get('rtpfuzz', 'STOPAFTER')
SERVICETYPE = config.get('rtpfuzz', 'TYPE')

# Little Bit Typecasting
RPORT = int(RPORT)
STOPAFTER = int(STOPAFTER)
DELAY = int(DELAY)
TEST_CASE_ID = 0

rtp_packet_types = {
    'version': 2,
    'padding': 0,
    'crsc_count': 0,
    'extension': 0,
    'marker': 0,
    'payload_type': 99,
    'sequence_number': 16,
    'timev': 32,
    'ssrc_id': 3000,
    'csrc_id': 32,
    'profile_extension_id': 16,
    'extension_header_length': 16,
    'payload': -1
}

def createpattern(length):
    length = int(length)
    data = ''.join(tuple(islice(chain.from_iterable(product(
        string.ascii_uppercase, string.ascii_lowercase, string.digits)), length)))
    return data

def send_to_target(data):
    data += createpattern(100)
    try:

        if SERVICETYPE == 'TCP':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((RHOST, RPORT))
            s.send(data)
            time.sleep(DELAY)

        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(data, (RHOST, RPORT))
            time.sleep(DELAY)

        print("[*] Test case ID:%d" % (TEST_CASE_ID-1) + " END------")

    except:
        print('ERROR: Build Socket failed,Check Service is TCP or UDP !!!')
        sys.exit(1)

    # time.sleep(1)
    # s.send(data)
    # s.ex

    # time.sleep(2)

# -----------RTP PayLoad Type fuzz function--------

def fuzz_payloadtype(count):
    global  TEST_CASE_ID
    for i in range(count):

        rtp_packet = BitArray()
        rtp_packet += 'uint:2=%d' % rtp_packet_types['version']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['padding']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['extension']
        rtp_packet += 'uint:4=%d' % rtp_packet_types['crsc_count']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['marker']
        # payload type range
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        print("[*] Test type : Basis Payloadtype, Payload : %d " %(i))
        rtp_packet += 'uint:7=%d' % i
        rtp_packet += 'uint:16=%d' % rtp_packet_types['sequence_number']
        rtp_packet += 'uint:32=%d' % rtp_packet_types['timev']
        rtp_packet += 'uint:32=%d' % rtp_packet_types['ssrc_id']
        send_to_target(rtp_packet.tobytes())

# -----------RTP Timestamp fuzz function--------


def fuzz_timestamp(count):
    global  TEST_CASE_ID
    timestamp_max = 2**32 - 1

    for i in range(count):

        rtp_packet = BitArray()
        rtp_packet += 'uint:2=%d' % rtp_packet_types['version']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['padding']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['extension']
        rtp_packet += 'uint:4=%d' % rtp_packet_types['crsc_count']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['marker']

        rtp_packet += 'uint:7=%d' % rtp_packet_types['payload_type']
        rtp_packet += 'uint:16=%d' % rtp_packet_types['sequence_number']
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_timestamp = random.randint(0,timestamp_max)
        print("[*] Test type : Basis Timestamp Test ,Payload : %d " %(rand_timestamp))
        rtp_packet += 'uint:32=%d' % rand_timestamp
        # rtp_packet += 'uint:32=%d' % rtp_packet_types['timev']

        rtp_packet += 'uint:32=%d' % rtp_packet_types['ssrc_id']
        send_to_target(rtp_packet.tobytes())

#-----------RTP Sequence_Number fuzz function--------

def fuzz_sequence_number(count):
    global  TEST_CASE_ID
    for i in range(count):

        rtp_packet = BitArray()
        rtp_packet += 'uint:2=%d' % rtp_packet_types['version']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['padding']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['extension']
        rtp_packet += 'uint:4=%d' % rtp_packet_types['crsc_count']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['marker']

        rtp_packet += 'uint:7=%d' % rtp_packet_types['payload_type']
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_number = random.randint(0,65535)
        # rtp_packet += 'uint:16=%d' % rtp_packet_types['sequence_number']
        rtp_packet += 'uint:16=%d' % rand_number
        print("[*] Test type : Basis Sequence Number Test , Payload : %d " %(rand_number))
        rtp_packet += 'uint:32=%d' % rtp_packet_types['timev']
        rtp_packet += 'uint:32=%d' % rtp_packet_types['ssrc_id']
        send_to_target(rtp_packet.tobytes())

# -----------RTP SSRC Identifier fuzz function--------
def fuzz_ssrc_id(count):
    global  TEST_CASE_ID
    ssrc_id_max = 2**32 - 1

    for i in range(count):

        rtp_packet = BitArray()
        rtp_packet += 'uint:2=%d' % rtp_packet_types['version']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['padding']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['extension']
        rtp_packet += 'uint:4=%d' % rtp_packet_types['crsc_count']
        rtp_packet += 'uint:1=%d' % rtp_packet_types['marker']
        rtp_packet += 'uint:7=%d' % rtp_packet_types['payload_type']
        rtp_packet += 'uint:16=%d' % rtp_packet_types['sequence_number']
        rtp_packet += 'uint:32=%d' % rtp_packet_types['timev']

        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_number = random.randint(0,ssrc_id_max)
        print("[*] Test type : Basis SSRC identifier Test , Payload : %d " %(rand_number))
        rtp_packet += 'uint:32=%d' % rand_number

        # rtp_packet += 'uint:32=%d' % rtp_packet_types['ssrc_id']

        send_to_target(rtp_packet.tobytes())

def start_fuzz():
    # rtp = b'\x80\x63\x78\xa6\x00\x00\x17\x65\xe6\x89\xe9\x31' + (b'\x61' * 1000)
    rtp_packet = BitArray()
    # rtp_packet += 'uint:2=%d' % rtp_packet_types['version']
    # rtp_packet += 'uint:1=%d' % rtp_packet_types['padding']
    # rtp_packet += 'uint:1=%d' % rtp_packet_types['extension']
    # rtp_packet += 'uint:4=%d' % rtp_packet_types['crsc_count']
    # rtp_packet += 'uint:1=%d' % rtp_packet_types['marker']
    # raw_input(rtp_packet)
    # rtp_packet += 'A'
    # raw_input(rtp_packet)
    # rtp_packet += 'uint:7=%d' % rtp_packet_types['payload_type']
    test_case_count = 0
    fuzz_payloadtype(128)
    print "[*] Test Function : fuzz_payloadtype End"
    # raw_input(TEST_CASE_ID)
    fuzz_timestamp(40000)
    print "[*] Test Function : fuzz_timestamp End"

    fuzz_sequence_number(20000)
    print "[*] Test Function : fuzz_sequence_number End"
    fuzz_ssrc_id(40000)
    print "[*] Test Function : fuzz_ssrc_id End"

    # rtp_packet += 'uint:16=%d' % rtp_packet_types['sequence_number']
    # rtp_packet += 'uint:32=%d' % rtp_packet_types['timev']
    # rtp_packet += 'uint:32=%d' % rtp_packet_types['ssrc_id']
    # rtp_packet.append('0x41'*80)
    # print(rtp_packet)
    # print(rtp_packet[4:8])
    # raw_input(len(rtp_packet[4:8]))
    # print(rtp_packet)
    # raw_input(len(rtp_packet))
    # for count in range(STOPAFTER):
    pkt = rtp_packet.tobytes()

def computeKey():
    username = 'admin'
    realm = 'RTSP'
    password = 'pass'
    nonce = '0000040dY892418598785d2a2304a74adf22f6098f2792'
    method = 'SETUP'
    url = 'rtsp://192.168.1.56:554/stream0'

    m1 = hashlib.md5(username + ":" + realm + ":" + password).hexdigest()
    m2 = hashlib.md5(method + ":" + url).hexdigest()
    response = hashlib.md5(m1 + ":" + nonce + ":" + m2).hexdigest()
    # raw_input(response)
    return response


if '__main__' == __name__:
    # pcap_reader = RawPcapReader('rtsp_rtp_example.pcap')
    # key = computeKey()
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
    print "[*]                      WELCOME                   [*]"
    print "[*]                RTPfuzzer version 1.0           [*]"
    print "[*]                rtp Protocol fuzzer             [*]"
    print "[*]                Author : Leon Zhang             [*]"
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
    print "[*]              Your Preferences                     "
    print "[*] Target Host :", RHOST, "on PORT", RPORT
    print "[*] Time Delay between two requests :", DELAY, "Sec"
    print "[*] Fuzzing with Metasploit Pattern :", msfpat
    print "[*] Fuzzing case : ",STOPAFTER
    raw_input('Are you ready to start fuzzing test?,(using ctrl+c to terminate)')


    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
    print "[*]                 Start Basis Fuzzing            [*]"
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"

    start_fuzz()
    # for index,pkt in enumerate(pcap_reader):
    #     if index > 60:

            # raw_input(index)
            # pkt[0].show()
            # raw_input(hexdump(pkt[0][71]))
            # raw_input(pkt)
