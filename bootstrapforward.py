###############################
# The code is not pretty, and is stolen from a number of other sources and modified. 
# relys on the machine running the code have multiple IP addresses to run the port forward on 443.
# the server runs as a DNS server for the main URL's needed to do bootstrapping.
# any other dns resolves to the host default IP address, you can redirect this to anywhere as required.
###############################

import socket
import threading
import sys
import time
import socketserver



DNS_HEADER_LENGTH = 12
# TODO make some DNS database with IPs connected to regexs

DNShost = '192.168.1.209'
DNSport = 53
    
default = '192.168.1.209'
updates = '192.168.1.210'
downloads ='192.168.1.211'
urlcloud = '192.168.1.212'
dnsservice = '192.168.1.213'

###### other entries you might need if you want to run everything via the socket proxy.
# serverlist.urlcloud.paloaltonetworks.com
# pandb2dc10prod.urlcloud.paloaltonetworks.com
# pandb2dlprod.urlcloud.paloaltonetworks.com
#
# assume you can add more by adding more IP addresses to the host. see the 
######

################DNS part##############

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        socket = self.request[1]
        data = self.request[0].strip()

        # If request doesn't even contain full header, don't respond.
        if len(data) < DNS_HEADER_LENGTH:
            return

        # Try to read questions - if they're invalid, don't respond.
        try:
            all_questions = self.dns_extract_questions(data)
        except IndexError:
            return

        # Filter only those questions, which have QTYPE=A and QCLASS=IN
        # TODO this is very limiting, remove QTYPE filter in future, handle different QTYPEs
        accepted_questions = []
        for question in all_questions:
            name = str(b'.'.join(question['name']), encoding='UTF-8')
#            print(name)
            if question['qtype'] == b'\x00\x01' and question['qclass'] == b'\x00\x01':
                accepted_questions.append(question)
                print('\033[32m{}\033[39m'.format(name))
            else:
                print('\033[31m{}\033[39m'.format(name))


        response = (
            self.dns_response_header(data) +
            self.dns_response_questions(accepted_questions) +
            self.dns_response_answers(accepted_questions)
        )
        socket.sendto(response, self.client_address)

    def dns_extract_questions(self, data):
        """
        Extracts question section from DNS request data.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        questions = []
        # Get number of questions from header's QDCOUNT
        n = (data[4] << 8) + data[5]
        # Where we actually read in data? Start at beginning of question sections.
        pointer = DNS_HEADER_LENGTH
        # Read each question section
        for i in range(n):
            question = {
                'name': [],
                'qtype': '',
                'qclass': '',
            }
            length = data[pointer]
            # Read each label from QNAME part
            while length != 0:
                start = pointer + 1
                end = pointer + length + 1
                question['name'].append(data[start:end])
                pointer += length + 1
                length = data[pointer]
            # Read QTYPE
            question['qtype'] = data[pointer+1:pointer+3]
            # Read QCLASS
            question['qclass'] = data[pointer+3:pointer+5]
            # Move pointer 5 octets further (zero length octet, QTYPE, QNAME)
            pointer += 5
            questions.append(question)
        return questions

    def dns_response_header(self, data):
        """
        Generates DNS response header.
        See http://tools.ietf.org/html/rfc1035 4.1.1. Header section format.
        """
        header = b''
        # ID - copy it from request
        header += data[:2]
        # QR     1    response
        # OPCODE 0000 standard query
        # AA     0    not authoritative
        # TC     0    not truncated
        # RD     0    recursion not desired
        # RA     0    recursion not available
        # Z      000  unused
        # RCODE  0000 no error condition
        header += b'\x80\x00'
        # QDCOUNT - question entries count, set to QDCOUNT from request
        header += data[4:6]
        # ANCOUNT - answer records count, set to QDCOUNT from request
        header += data[4:6]
        # NSCOUNT - authority records count, set to 0
        header += b'\x00\x00'
        # ARCOUNT - additional records count, set to 0
        header += b'\x00\x00'
        return header

    def dns_response_questions(self, questions):
        """
        Generates DNS response questions.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        sections = b''
        for question in questions:
            section = b''
            for label in question['name']:
                # Length octet
                section += bytes([len(label)])
                section += label
            # Zero length octet
            section += b'\x00'
            section += question['qtype']
            section += question['qclass']
            sections += section
        return sections

    def dns_response_answers(self, questions):
        """
        Generates DNS response answers.
        See http://tools.ietf.org/html/rfc1035 4.1.3. Resource record format.
        """
        records = b''
        for question in questions:
            name = str(b'.'.join(question['name']), encoding='UTF-8')
#            print(name)
            if name == "updates.paloaltonetworks.com":
                IP = updates
            elif name == "downloads.paloaltonetworks.com":
                IP = downloads
            elif name == "s0000.urlcloud.paloaltonetworks.com":
                IP = urlcloud
            elif name == "dns.service.paloaltonetworks.com":
                IP = dnsservice
            else:
                IP = default
#            print (IP)
 
            record = b''
            for label in question['name']:
                # Length octet
                record += bytes([len(label)])
                record += label
            # Zero length octet
            record += b'\x00'
            # TYPE - just copy QTYPE
            # TODO QTYPE values set is superset of TYPE values set, handle different QTYPEs, see RFC 1035 3.2.3.
            record += question['qtype']
            # CLASS - just copy QCLASS
            # TODO QCLASS values set is superset of CLASS values set, handle at least * QCLASS, see RFC 1035 3.2.5.
            record += question['qclass']
            # TTL - 32 bit unsigned integer. Set to 0 to inform, that response
            # should not be cached.
            record += b'\x00\x00\x00\x00'
            # RDLENGTH - 16 bit unsigned integer, length of RDATA field.
            # In case of QTYPE=A and QCLASS=IN, RDLENGTH=4.
            record += b'\x00\x04'
            # RDATA - in case of QTYPE=A and QCLASS=IN, it's IPv4 address.
            record += b''.join(map(
                lambda x: bytes([int(x)]),
                IP.split('.')
            ))
            records += record
        return records

################ DNS Part END ##############

################ Socket forwarder ##############


def handledns(buffer):
    return buffer
    

def transfer(src, dst, direction):
    src_name = src.getsockname()
    src_address = src_name[0]
    src_port = src_name[1]
    dst_name = dst.getsockname()
    dst_address = dst_name[0]
    dst_port = dst_name[1]
    while True:
        buffer = src.recv(0x400)
        if len(buffer) == 0:
            print ("[-] No data received! Breaking...")
            break
        # print "[+] %s:%d => %s:%d [%s]" % (src_address, src_port, dst_address, dst_port, repr(buffer))
        if direction:
            print ("[+] %s:%d >>> %s:%d [%d]" % (src_address, src_port, dst_address, dst_port, len(buffer)))
        else:
            print ("[+] %s:%d <<< %s:%d [%d]" % (dst_address, dst_port, src_address, src_port, len(buffer)))
        dst.send(handledns(buffer))
    print ("[+] Closing connecions! [%s:%d]" % (src_address, src_port))
    src.shutdown(socket.SHUT_RDWR)
    src.close()
    print ("[+] Closing connecions! [%s:%d]" % (dst_address, dst_port))
    dst.shutdown(socket.SHUT_RDWR)
    dst.close()


def server(local_host, local_port, remote_host, remote_port, max_connection,host):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((local_host, local_port))
    server_socket.listen(max_connection)
    print ("[+] Server started [%s:%d] for [%s]" % (local_host, local_port, host))
    print ("[+] Connect to [%s:%d] to get the content of [%s:%d]" % (local_host, local_port, remote_host, remote_port))
    while True:
        local_socket, local_address = server_socket.accept()
        print ("[+] Detect connection from [%s:%s]" % (local_address[0], local_address[1]))
        print ("[+] Trying to connect the REMOTE server [%s:%d]" % (remote_host, remote_port))
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((remote_host, remote_port))
        print ("[+] Tunnel connected! Tranfering data...")
        # threads = []
        s = threading.Thread(target=transfer, args=(
            remote_socket, local_socket, False))
        r = threading.Thread(target=transfer, args=(
            local_socket, remote_socket, True))
        # threads.append(s)
        # threads.append(r)
        s.start()
        r.start()
    print ("[+] Releasing resources...")
    remote_socket.shutdown(socket.SHUT_RDWR)
    remote_socket.close()
    local_socket.shutdown(socket.SHUT_RDWR)
    local_socket.close()
    print ("[+] Closing server...")
    server_socket.shutdown(socket.SHUT_RDWR)
    server_socket.close()
    print ("[+] Server shuted down!")
    
    
    
################ Socket forwarder END ##############
    
def main():
    MAX_CONNECTION = 0x10
    LOCAL_HOST1 = updates
    LOCAL_HOST2 = downloads
    LOCAL_HOST3 = urlcloud
    LOCAL_HOST4 = dnsservice

    HOST1 = 'updates.paloaltonetworks.com'
    HOST2 = 'downloads.paloaltonetworks.com'
    HOST3 = 's0000.urlcloud.paloaltonetworks.com'
    HOST4 = 'dns.service.paloaltonetworks.com'

    REMOTE_HOST1 = socket.gethostbyname(HOST1)
    REMOTE_HOST2 = socket.gethostbyname(HOST2)
    REMOTE_HOST3 = socket.gethostbyname(HOST3)
    REMOTE_HOST4 = socket.gethostbyname(HOST4)
    LOCAL_PORT = 443
    REMOTE_PORT = 443

    thread1 = threading.Thread(target=server, args=(LOCAL_HOST1, LOCAL_PORT, REMOTE_HOST1, REMOTE_PORT, MAX_CONNECTION, HOST1))
    thread2 = threading.Thread(target=server, args=(LOCAL_HOST2, LOCAL_PORT, REMOTE_HOST2, REMOTE_PORT, MAX_CONNECTION, HOST2))
    thread3 = threading.Thread(target=server, args=(LOCAL_HOST3, LOCAL_PORT, REMOTE_HOST3, REMOTE_PORT, MAX_CONNECTION, HOST3))
    thread4 = threading.Thread(target=server, args=(LOCAL_HOST4, LOCAL_PORT, REMOTE_HOST4, REMOTE_PORT, MAX_CONNECTION, HOST4))
    
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    
    dnsserver = socketserver.ThreadingUDPServer((DNShost, DNSport), DNSHandler)
    print('\033[36mStarted DNS server.\033[39m')
    threadx = threading.Thread(target=dnsserver.serve_forever, args=())
    threadx.start() 


if __name__ == "__main__":
    main()