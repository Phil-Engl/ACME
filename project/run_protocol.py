from acme_client import *
from my_DNS_server import DNSServer
from challenge_HTTP_server import MyHTTPServer
from  certificate_HTTPS_server import MyCERTServer
from shutdown_HTTP_server import MyTerminator
import os
import signal
import sys

def main():
    challenge_type = sys.argv[1]
    directory_url = sys.argv[3] 
    record = sys.argv[5]

    domains = []
    tmp_domains = sys.argv[6:]

    next_dom = False
    next_rev = False
    revoke = False

    for d in tmp_domains:
        if next_dom:
            domains.append(d)
            next_dom = False
        if next_rev:
            revoke = d
            next_rev = False
        if d == '--domain':
            next_dom = True
        if d == '--revoke':
            revoke = True

    print("challenge type:", challenge_type)
    print("directory url: ", directory_url)
    print("record: ", record)
    print("domains: ", domains)
    print("revoke?: ", revoke)

    client = myClient(challenge_type, directory_url, record, domains)

    initialize_client(client)

    #terminator = MyTerminator('0.0.0.0', 5003)
    #term_thread = terminator.start()
    #client.http_server = MyHTTPServer('0.0.0.0', 5002, client.thumbprint)
    #client.certificate_serverer = MyCERTServer('0.0.0.0', 5001, 'certificate.pem', 'priv_key.pem')
    #client.dns_server = DNSServer(client.record, 10053)

    terminator = MyTerminator(record, 5003)
    term_thread = terminator.start()
    client.http_server = MyHTTPServer(record, 5002, client.thumbprint)
    client.certificate_serverer = MyCERTServer(record, 5001, 'certificate.pem', 'priv_key.pem')
    client.dns_server = DNSServer(record, 10053)

    for d in domains: 
        client.dns_server.add_dns_record( d + "." , record, QTYPE.A, 60)

    register_acc(client)
    make_new_order(client)
    http_thread, dns_thread = solve_challenges(client)
    finalize_order(client)
    download_cert(client)

    with open('certificate.pem', 'wb') as cert_file, open('priv_key.pem', 'wb') as key_file:
        cert_file.write(client.final_certificate.content)
        key_file.write(client.private_cert_key_pem)

        cert_file.close()
        key_file.close()

    cert_thread = client.certificate_serverer.start()

    if revoke:
        revoke_cert(client)

    term_thread.join()
    return

if __name__ == "__main__":
    main()