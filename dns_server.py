from sys import argv, exit
from socket import socket, AF_INET, SOCK_DGRAM
from easyzone import easyzone
from utils import *
from os import listdir
import random

#========GLOBAL==========
PORT = 53535
ZONES = None
SOCKET = None
DNS_PORT = 53
#========================


def get_response(request):
    header = Header(request)
    questions = []
    for _ in range(header.qd_count):
        questions.append(Question(info_in_bytes=request, pointer=header.position_in_message[1]))
    query_flags = format(header.flags, '016b')  # Transform flags to string.
    rd = query_flags[7]  # Recursion Desired bit.
    request_id = header.q_id
    rcode, AA, answers = get_answers(header, questions, rd)

    # QR + Opcode + AA + TC + RD + RA + Z + RCODE
    header.q_id = request_id
    header.flags = int('1' + '0000' + AA + '0' + '0' + '1' + '000' + format(rcode, '04b'), 2)
    header.an_count = len(answers)
    header.ns_count = 0
    header.ar_count = 0
    response = header.to_bytes()
    for question in questions:
        response += question.to_bytes()
    for answer in answers:
        response += answer.to_bytes()
    return response


def get_answers(header, questions, do_recursion):
    question = questions[0]  # Only one question is handled.

    rcode = NXDOMAIN

    domain = None
    for zone in ZONES:
        domain = zone.get_names().get(question.q_name)  # Zone object
        if domain is not None:
            break

    if domain is None or domain.records(RFC1035_TYPES[question.q_type]) is None:
        if do_recursion:
            header.q_id = 0
            header.ns_count = 0
            header.ar_count = 0
            questions_bytes = b''
            for question in questions:
                questions_bytes += question.to_bytes()
            rcode, answers = recursive_search(header, questions_bytes, [ROOT_SERVERS[0]], [])
            return rcode, '0', answers
        return rcode, '1', []

    records = domain.records(RFC1035_TYPES[question.q_type])
    answers = []
    for record in records.items:
        answer = Answer()
        answer.a_name = domain.name
        answer.a_type = question.q_type
        answer.a_class = 0x0001
        answer.a_ttl = domain.ttl

        answer.a_data = record
        answers.append(answer)

    rcode = NOERROR
    return rcode, '1', answers

# This solution assumes that for every NS record,
# there will be A record in Additional records.
def recursive_search(q_header, questions_bytes, servers, visited_addrs):
    for server in servers:
        addr = server.split()[-1]

        if addr in visited_addrs:
            continue
        visited_addrs.append(addr)

        request_id = random.randrange(65535)
        q_header.q_id = request_id

        SOCKET.sendto(q_header.to_bytes() + questions_bytes, (addr, DNS_PORT))
        SOCKET.settimeout(5)
        response, _ = SOCKET.recvfrom(512)  # Timeout
        SOCKET.settimeout(None)

        header = Header(response)
        pointer = header.position_in_message[1]
        questions = []
        for _ in range(header.qd_count):
            question = Question(info_in_bytes=response, pointer=pointer)
            questions.append(question)
            pointer = question.position_in_message[1]
        answers = []
        for _ in range(header.an_count):
            answer = Answer(info_in_bytes=response, pointer=pointer)
            answers.append(answer)
            pointer = answer.position_in_message[1]
        authorities = []
        for _ in range(header.ns_count):
            answer = Answer(info_in_bytes=response, pointer=pointer)
            authorities.append(answer)
            pointer = answer.position_in_message[1]
        aditionals = []
        for _ in range(header.ar_count):
            answer = Answer(info_in_bytes=response, pointer=pointer)
            aditionals.append(answer)
            pointer = answer.position_in_message[1]

        rcode = int(format(header.flags, '016b')[-4:])
        if rcode != 0:
            return NXDOMAIN, []

        if header.an_count != 0:
            return NOERROR, answers

        if header.ns_count != 0:
            servers = []
            for record in aditionals:
                typ = RFC1035_TYPES[record.a_type]
                if typ == 'A':
                    servers.append(typ + ' ' + str(record.a_data))
            res_code, res = recursive_search(q_header, questions_bytes, servers, visited_addrs)
            if res_code == NOERROR:
                return NOERROR, res
    return NXDOMAIN, []


def server():
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind(('', PORT))
    global SOCKET
    SOCKET = server_socket
    while True:
        request, client_address = server_socket.recvfrom(512)
        response = get_response(request)
        server_socket.sendto(response, client_address)


def read_zone_files(directory):
    zones = []
    zone_files = listdir(directory)
    for zone_filename in zone_files:
        zone = easyzone.zone_from_file(zone_filename.split('conf')[0], directory + zone_filename)
        zones.append(zone)
    return zones


def main():
    try:
        zone_directory = argv[1]
        print(zone_directory)
        global ZONES
        ZONES = read_zone_files(zone_directory)
    except:
        print('File Not Found or Not Valid Zone File!')
        exit(1)
    server()


if __name__ == '__main__':
    main()

