#!/usr/bin/python
import csv

#client_hello_to_disect_path     = "annotated_client_hello.dump"
client_hello_to_disect_path     = "annotated_client_hello.dump"

rfc_mapping_path                = "helpers/mapping-rfc.csv"
iana_rfc_mapping_path           = "helpers/tls-p.csv"

def import_rfc_mapping(import_file_path):
    rfc_map = {}
    with open(import_file_path, newline='\n') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=';')
        for row in spamreader:
            k,v = row
            rfc_map[k]=v
    return rfc_map

def import_iana_rfc_mapping(import_file_path):
    iana_rfc_map = {}
    with open(import_file_path, newline='\n') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',')
        for row in spamreader:
            key, cipher, dtlsok, recommended, reference = row
            iana_rfc_map[key] = (cipher, dtlsok, recommended, reference)
    return iana_rfc_map

def read_client_hello(file_path):
    client_hello = ""
    f = open(file_path, "r")
    for line in f:
        client_hello += line
    client_hello_dict = client_hello.replace('\n', " ").split(" ")
    return client_hello_dict

def get_bytes(low, high, read_dict):
    result = ""
    for i in range(low, high+1):
        result += read_dict[i] + " "
    return result[:-1]

rfc_mapping             = import_rfc_mapping(rfc_mapping_path)
iana_rfc_mapping        = import_iana_rfc_mapping(iana_rfc_mapping_path)
ch_dict                 = read_client_hello(client_hello_to_disect_path)



record_header_bytes     = (0,4)
handshake_header_bytes  = (5,8)
client_version_bytes    = (9,10)
client_random_bytes     = (11,42) # why not 43?
session_id_length_bytes = 43


record_header           = get_bytes(record_header_bytes[0], record_header_bytes[1], ch_dict)
handshake_header        = get_bytes(handshake_header_bytes[0], handshake_header_bytes[1], ch_dict)
client_version          = get_bytes(client_version_bytes[0], client_version_bytes[1], ch_dict)
client_random           = get_bytes(client_random_bytes[0], client_random_bytes[1], ch_dict)
session_id_length       = int(ch_dict[session_id_length_bytes], 16)
session_id = ""
if session_id_length != "0":
    session_id = get_bytes(session_id_length_bytes + 1, session_id_length_bytes + session_id_length + 1, ch_dict)

cipher_suites_length_bytes = (session_id_length_bytes+session_id_length+1,session_id_length_bytes+session_id_length+2)
cipher_suites_length    = int(get_bytes(cipher_suites_length_bytes[0], cipher_suites_length_bytes[1], ch_dict).replace(" ",""),16)

cipher_suites_bytes     = (cipher_suites_length_bytes[1]+1, cipher_suites_length_bytes[1]+cipher_suites_length)
cipher_suites           = get_bytes(cipher_suites_bytes[0], cipher_suites_bytes[1], ch_dict)


print("Record header: "     + record_header)
print("Handshake header: "  + handshake_header)
print("Client version: "    + client_version)
print("Client random: "     + client_random)
print("Session ID length: " + str(session_id_length))
print("Session ID: "        + str(session_id))
print("Cipher suite length: " + str(cipher_suites_length))
print("Cipher suites: "     + cipher_suites)

for i in range(0, cipher_suites_length, 2):
    cipher_suites_dict = cipher_suites.split(" ")
    rfc = "0x" + cipher_suites_dict[i].upper() + ",0x" + cipher_suites_dict[i+1].upper()
    try:
        print(iana_rfc_mapping[rfc])
    except:
        print("Cipher not found in rfc mapping: " + rfc)