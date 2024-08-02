from dnslib import DNSRecord, QTYPE, RR, DNSHeader, A, TXT, AAAA
import socket
import threading




def handle_dns_request(dns_records, data, client_address, server_socket):
    try:
        request = DNSRecord.parse(data)
        query = str(request.q.qname)

        if query in dns_records:
            ip_addressES, record_type, ttl = dns_records[query]

            response = DNSRecord(DNSHeader(request.header.id, qr=1, aa=1, ra=1), q=request.q)

            for ip_address in ip_addressES:
                if request.q.qtype == 1:  # A
                    response.add_answer(RR(request.q.qname, request.q.qtype, rdata=A(ip_address), ttl = 300))
                elif request.q.qtype == 16:
                    response.add_answer(RR(request.q.qname, request.q.qtype, rdata=TXT(ip_address), ttl = 300))
                else:
                    response.add_answer(RR(request.q.qname, 16, rdata=TXT(ip_address), ttl = 300))

            response_packet = response.pack()
            server_socket.sendto(response_packet, client_address)
            print(f"Sent DNS response for {query} to {client_address} : {ip_address}", response)            
        else:
            print(f"\n \n No DNS record found for {query} \n \n")

    except Exception as e:
        print(f"Error handling DNS request: {e}")



def DNS_Thread(socket, dns_records):
    while True:
        try:
            data, client_address = socket.recvfrom(1024)
            handle_dns_request(dns_records, data, client_address, socket)
        except Exception as e:
            print("Exception at DNS... \n")
            return

class DNSServer:
    def __init__(self, host, port):
        self.DNS_HOST = host
        self.DNS_PORT = port
        self.dns_records = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((self.DNS_HOST, self.DNS_PORT))

    def add_dns_record(self, domain, ip_address, record_type, ttl):
        if domain in self.dns_records:
            (tmp_ip_address, tmp_record_type, tmp_ttl) =  self.dns_records[domain]
            tmp_thing = tmp_ip_address + [ip_address]
            self.dns_records[domain] = (tmp_thing, tmp_record_type, tmp_ttl)
        else:
            self.dns_records[domain] = ([ip_address], record_type, ttl)
        return

    def start(self):
        print(f"DNS server listening on {self.DNS_HOST}:{self.DNS_PORT}")
        thread = threading.Thread(target=DNS_Thread, args=(self.server_socket, self.dns_records), daemon=True)
        thread.start()
        return thread

    def stop(self):
        self.server_socket.close()
        return
