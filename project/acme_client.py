
#import os
import base64
import json
import sys
import time
#import dns_server
#import dns_server2
from my_DNS_server import DNSServer
from challenge_HTTP_server import MyHTTPServer

from dnslib import QTYPE
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AttributeOID, NameOID

import requests
import threading
import hashlib

class myClient:
    def __init__(self, challenge_type, direcotry_url, record, domains):
        self.directory_url = direcotry_url
        self.record = record
        self.domains = domains
        self.s = None
        self.directory = None
        self.public_key = None
        self.private_key = None
        self.dns_server = None
        self.http_server = None
        self.curr_nonce = None
        self.account = None
        self.order = None
        self.jwk = None
        self.thumbprint = None
        self.challenge_type = challenge_type#"http-01" #"dns-01"
        self.private_cert_key = None
        self.public_cert_key = None
        self.private_cert_key_pem = None
        self.public_cert_key_pem = None
        self.certificate_link = None
        self.certificate_server = None
        self.final_certificate = None

def get_ec_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def get_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def hash_jwk(jwk):
    jwk_tmp = json.dumps(jwk, separators=(',',':'), sort_keys = True).encode('utf-8')
    sha256 = hashes.Hash(hashes.SHA256())
    sha256.update(jwk_tmp)
    jwk_hash = sha256.finalize()    
    return jwk_hash

def get_jwk(public_key):
    tmp_pub_key = public_key.public_numbers()

    e = tmp_pub_key.e
    n = tmp_pub_key.n

    e_as_BYTES = e.to_bytes(e.bit_length(), 'big')
    n_as_BYTES = (n).to_bytes(n.bit_length(), 'big')

    e_encoded = base64.urlsafe_b64encode(e_as_BYTES).decode('utf-8').rstrip("=")
    n_encoded = base64.urlsafe_b64encode(n_as_BYTES).decode('utf-8').rstrip("=")

    jwk = {
        "e": e_encoded,
        "kty": "RSA",
        "n": n_encoded
    }
    return jwk

def get_thumbprint(public_key):
    jwk = get_jwk(public_key)
    jwk_hash = hash_jwk(jwk)
    thumbprint = base64.urlsafe_b64encode(jwk_hash).decode('utf-8').rstrip("=")
    return thumbprint

def get_jwk_and_thumbprint(public_key):
    tmp_pub_key = public_key.public_numbers()

    e = tmp_pub_key.e
    n = tmp_pub_key.n

    e_as_BYTES = e.to_bytes(e.bit_length(), 'big')
    n_as_BYTES = (n).to_bytes(n.bit_length(), 'big')

    e_encoded = base64.urlsafe_b64encode(e_as_BYTES).decode('utf-8').rstrip("=")
    n_encoded = base64.urlsafe_b64encode(n_as_BYTES).decode('utf-8').rstrip("=")

    jwk = {
        "e": e_encoded,
        "kty": "RSA",
        "n": n_encoded
    }

    jwk_hash = hash_jwk(jwk)
    thumbprint = base64.urlsafe_b64encode(jwk_hash).decode('utf-8').rstrip("=")
    return jwk, thumbprint

def get_jwk_and_thumbprint_ec(public_key):
    tmp_pub_key = public_key.public_numbers()

    x = tmp_pub_key.x
    y = tmp_pub_key.y

    x_as_BYTES = x.to_bytes(32, 'big')
    y_as_BYTES = y.to_bytes(32, 'big')

    x_encoded = base64.urlsafe_b64encode(x_as_BYTES).decode('utf-8').rstrip("=")
    y_encoded = base64.urlsafe_b64encode(y_as_BYTES).decode('utf-8').rstrip("=")

    jwk = {
        "crv": "P-256",
        "kty": "EC",
        "x": x_encoded,
        "y": y_encoded
    }

    jwk_hash = hash_jwk(jwk)
    thumbprint = base64.urlsafe_b64encode(jwk_hash).decode('utf-8').rstrip("=")
    return jwk, thumbprint

def register_acc(client):
    url = client.directory["newAccount"]
    test_payload = {
        "termsOfServiceAgreed" : True,
        "contact" : ["mailto: dummy_mail@ethz.ch"]
        }

    acc_req = make_signed_post_request2(client, url, test_payload, use_jwk=True, kid = "", nonce=None)

    if(acc_req.status_code != 201):
        print("account creation failed \n")
        print("response: ", acc_req.status_code)
        #sys.exit(1)
    client.account = acc_req
    return

def get_jws(protected, payload, signature):
    jws = {
        "protected": protected, 
        "payload": payload,
        "signature": signature
    }
    return jws

def get_protected_jwk_header(jwk, nonce, url):
    protected_header = {
        "alg": "RS256",
        "jwk": jwk,
        "nonce": nonce,
        "url": url
    }

    header_as_BYTES = json.dumps(protected_header).encode('utf-8')
    header_encoded = base64.urlsafe_b64encode(header_as_BYTES).decode('utf-8').rstrip("=")
    return header_encoded

def get_protected_jwk_header_ec(jwk, nonce, url):
    protected_header = {
        "alg": "ES256",
        "jwk": jwk,
        "nonce": nonce,
        "url": url
    }

    header_as_BYTES = json.dumps(protected_header).encode('utf-8')
    header_encoded = base64.urlsafe_b64encode(header_as_BYTES).decode('utf-8').rstrip("=")
    return header_encoded

def get_protected_kid_header(kid, nonce, url):
    protected_header = {
        "alg": "RS256",
        "kid": kid,
        "nonce": nonce,
        "url": url
    }
    header_as_BYTES = json.dumps(protected_header).encode('utf-8')
    header_encoded = base64.urlsafe_b64encode(header_as_BYTES).decode('utf-8').rstrip("=")
    return header_encoded

def get_protected_kid_header_ec(kid, nonce, url):
    protected_header = {
        "alg": "ES256",
        "kid": kid,
        "nonce": nonce,
        "url": url
    }
    header_as_BYTES = json.dumps(protected_header).encode('utf-8')
    header_encoded = base64.urlsafe_b64encode(header_as_BYTES).decode('utf-8').rstrip("=")
    return header_encoded

def get_signature(private_key, message):
    signature_as_BYTES = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())    
    signature_encoded = base64.urlsafe_b64encode(signature_as_BYTES).decode('utf-8').rstrip("=")
    return signature_encoded

def get_signature_ec(private_key: ec.EllipticCurvePrivateKey, message):
    sig1 = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r,s = decode_dss_signature(sig1)
    concat = r.to_bytes(32,'big') + s.to_bytes(32, 'big')
    signature = base64.urlsafe_b64encode(concat).decode('utf-8').rstrip("=")
    return signature


def make_signed_post_request2(client, url, payload, use_jwk, kid, nonce):
    jwk = client.jwk
    
    if nonce == None:
        nonce = client.s.head(client.directory['newNonce']).headers['Replay-Nonce']
    if use_jwk:
        protected_header = get_protected_jwk_header_ec(jwk, nonce, url)
    else:
        protected_header = get_protected_kid_header_ec(kid, nonce, url)
    if payload != "":
        payload_as_BYTES = (json.dumps(payload)).encode('utf-8')
        payload_encoded = base64.urlsafe_b64encode(payload_as_BYTES).decode('utf-8').rstrip("=")
    else:
        payload_encoded = payload

    message = ("%s.%s" % (protected_header, payload_encoded)).encode('utf-8')
    signature = get_signature_ec(client.private_key, message)
    jws = get_jws(protected_header, payload_encoded, signature)

    weird_header = {
    "Content-Type": "application/jose+json"
    }

    response = client.s.post(url, json= jws, headers = weird_header)
    return response

def make_new_order(client):
    url = client.directory['newOrder']
    kid = client.account.headers['location']
    
    identifiers = []
    for d in client.domains:
        identifiers.append({"type": "dns", "value": d})
    payload = {"identifiers": identifiers}
    response = make_signed_post_request2(client, url, payload, use_jwk=False, kid=kid, nonce=None)

    if(response.status_code != 201):
        print("NewOrder failed \n")
        print("response: ", response.status_code, "\n")
    client.order = response.json()
    client.curr_nonce = response.headers['Replay-Nonce']
    return 

def solve_all_http_challenge(client, challenge_list):
    kid = client.account.headers['location']
    for challenge_url, challenge_token, challenge_identifier_value in challenge_list:
        client.http_server.add_token( challenge_token )
    http_thread = client.http_server.start()
    dns_thread = client.dns_server.start()

    i = 0
    while(i<10):
        time.sleep(i)
        for challenge_url, challenge_token, challenge_identifier_value in challenge_list:
            if i ==0:
                response = make_signed_post_request2(client, challenge_url, {}, use_jwk=False, kid=kid, nonce = client.curr_nonce)
            else:
                response = make_signed_post_request2(client, challenge_url, "", use_jwk=False, kid=kid, nonce = client.curr_nonce)
            if response.status_code == 200:
                client.curr_nonce = response.headers['Replay-Nonce']
                if response.json()['status'] == 'valid':
                    i = 100
        i = i+1
    return http_thread, dns_thread

def solve_all_dns_challenges(client, challenge_list):
    thumbprint = client.thumbprint
    kid = client.account.headers['location']
    
    for challenge_url, challenge_token, challenge_identifier_value in challenge_list:
        identifier_authenticator = challenge_token + "." + thumbprint
        sha256 = hashes.Hash(hashes.SHA256())
        sha256.update( identifier_authenticator.encode('utf-8') )
        tmp_digest = sha256.finalize()
        digest = base64.urlsafe_b64encode(tmp_digest).decode('utf-8').rstrip("=")
        client.dns_server.add_dns_record("_acme-challenge." + challenge_identifier_value +  ".", digest, QTYPE.TXT, 300)

    thread = client.dns_server.start()

    i = 0
    while(i<10):
        time.sleep(i)
        for challenge_url, challenge_token, challenge_identifier_value in challenge_list:
            if i ==0:
                response = make_signed_post_request2(client, challenge_url, {}, use_jwk=False, kid=kid, nonce = client.curr_nonce)
            else:
                response = make_signed_post_request2(client, challenge_url, "", use_jwk=False, kid=kid, nonce = client.curr_nonce)
            if response.status_code == 200:
                client.curr_nonce = response.headers['Replay-Nonce']
                if response.json()['status'] == 'valid':
                    i = 100
        i = i+1
    return None, thread

def solve_challenges(client):
    authorizations = client.order["authorizations"]
    kid = client.account.headers['location']
    http_challenges = []
    dns_challenges = []

    for url in authorizations:
        response = make_signed_post_request2(client, url, "", use_jwk=False, kid=kid, nonce = client.curr_nonce)
        if(response.status_code != 200):
            print("Fetching challenges failed \n")
            print("response: ", response.status_code, "\n")
        else:
            client.curr_nonce = response.headers['Replay-Nonce']
            response_JSON = response.json()

            challenge_status = response_JSON['status']
            challenge_identifier_value = response_JSON['identifier']['value']

            if challenge_status == "pending" and challenge_identifier_value in client.domains or ('*.'+challenge_identifier_value) in client.domains:
                for challenge in response_JSON["challenges"]:
                    if challenge["type"] == "http-01":
                        challenge_url = challenge['url']
                        challenge_token = challenge['token']
                        http_challenges.append( (challenge_url, challenge_token, challenge_identifier_value))
                    elif challenge["type"] == "dns-01":
                        challenge_url = challenge['url'] 
                        challenge_token = challenge['token']
                        dns_challenges.append( (challenge_url, challenge_token, challenge_identifier_value) )
    
    http_thread, dns_thread = None, None

    if client.challenge_type == "http-01" or client.challenge_type == "http01":
        http_thread, dns_thread = solve_all_http_challenge(client, http_challenges)
    elif client.challenge_type == "dns-01" or client.challenge_type == "dns01":
        http_thread, dns_thread = solve_all_dns_challenges(client, dns_challenges)
    else:
        print("FAIL: DONT RECOGINZE THIS CHALLENGE TYPE: ", client.challenge_type, "\n")
    return http_thread, dns_thread

def get_cert_keys():
    private_key, public_key = get_ec_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
    

    public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, private_pem, public_key, public_pem

def get_csr(client):
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'test string'),]))
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(domain) for domain in client.domains]), critical=False)
    request = builder.sign(client.private_cert_key, hashes.SHA256())
    request_der = request.public_bytes(encoding=serialization.Encoding.DER)
    encoded_request = base64.urlsafe_b64encode(request_der).decode('utf-8').rstrip("=")

    csr = {
        "csr": encoded_request
    }

    return csr


def finalize_order(client):
    finalize_url = client.order["finalize"]
    account_kid = client.account.headers['Location']
    client.private_cert_key, client.private_cert_key_pem, client.public_cert_key, client.public_cert_key_pem = get_cert_keys()
    csr = get_csr(client)

    time.sleep(5)

    new_order = make_signed_post_request2(client, finalize_url, csr, use_jwk=False, kid = account_kid, nonce=None)

    if new_order.status_code == 200:
        order_kid = new_order.headers['Location']
        if(new_order.status_code != 200):
            print("Finalize request failed \n")
            print("response: ", response.status_code, "\n")
        client.curr_nonce = new_order.headers['Replay-Nonce']

        i = 0
        while(i<10):
            time.sleep(i)
            response = make_signed_post_request2(client, order_kid, "", use_jwk=False, kid = account_kid, nonce=client.curr_nonce)
            if response.status_code != 200:
                print("Checking status of finalization failed \n")
                print("response: ", response.status_code, "\n")

            client.curr_nonce = response.headers['Replay-Nonce']

            if response.json()['status'] == 'valid':
                client.certificate_link = response.json()['certificate']
                i = 100
            i = i+1
    else:
        print("Finalization failed, will retry now... \n")
        print(new_order.json())
        finalize_order(client)

    return

def download_cert(client):
    kid = client.account.headers['Location']
    cert_url = client.certificate_link
    cert = make_signed_post_request2(client, cert_url, "", use_jwk=False, kid=kid, nonce=client.curr_nonce)

    if cert.status_code != 200:
        print("Checking status of finalization failed \n")
        print("response: ", cert.status_code, "\n")

    client.curr_nonce = cert.headers['Replay-Nonce']
    print("certificate:  \n", cert.content)
    client.final_certificate = cert
    return

def revoke_cert(client):
    cert_pem = x509.load_pem_x509_certificate(client.final_certificate.content).public_bytes(encoding=serialization.Encoding.DER)
    pem_encoded = base64.urlsafe_b64encode(cert_pem).decode('utf-8').rstrip("=")

    rev_payload = {
        "certificate": pem_encoded
    }

    kid = client.account.headers['Location']
    link = client.directory['revokeCert']
    response = make_signed_post_request2(client, link, rev_payload, use_jwk=False, kid=kid, nonce=client.curr_nonce)
    print(response.status_code)
    if response.status_code != 200:
        print("Revocation failed \n")
        print("response: ", response.status_code, "\n")
    return

def initialize_client(client):
    print("initializing client \n")
    client.private_key, client.public_key = get_ec_key()
    client.jwk, client.thumbprint = get_jwk_and_thumbprint_ec(client.public_key)

    s = requests.Session()
    s.verify = "pebble.minica.pem"
    client.s = s

    directory_response = s.get(client.directory_url)

    if(directory_response.status_code != 200):
        print("directory request failed \n")
        print("response: ", directory_response.status_code, "\n")
        return
    client.directory = directory_response.json()
    return
