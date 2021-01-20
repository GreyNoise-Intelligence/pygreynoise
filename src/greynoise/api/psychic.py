from enum import Enum
from os import path
import requests
import gzip
import socket
import struct
import time

class PsychicMode(Enum):
    MEM = "mem"
    DISK = "disk"

# Local functions

def ip2int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int2ip(i):
    return socket.inet_ntoa(struct.pack("!I", i))

def ip2offsetposition(ip):

    # Convert IP to int
    i = ip2int(ip)

    # Get offset by dividing by 8
    offset = i // 8

    # Get remainder (modulo)
    remainder = i % 8

    # Return values
    return offset, remainder

def offset_and_bytemask_to_ips(offset, b):

    # Initialize some variables
    block = offset * 8
    ips = []

    # Iterate thru the bits flipped in the byte mask
    for i in range(0, 7):

        # Check if the bit is set
        if int.from_bytes(b, "big") & (1 << (i )):

            # If so, generate the IP format of (int + block)
            ip = int2ip(block+i)
            
            # Append to list of "noise IPs"
            ips.append(ip)

    # Return the list of IPs
    return ips

# Hardcoding a bunch of stuff for now
def data_file_exists():
    return path.exists("/Users/andrew/.config/greynoise/data_files/data_file.bin")

def retrieve_data_file():
    
    uri = "http://localhost:8000/data_file.bin.gz"

    print("[PSYCHIC] Grabbing compressed data file from %s..." % uri)
    r = requests.get(uri)

    # Hardcoding now to save time
    print("[PSYCHIC] Writing compressed file to %s..." % "/Users/andrew/.config/greynoise/data_files/data_file.bin.gz")
    with open("/Users/andrew/.config/greynoise/data_files/data_file.bin.gz", "wb") as f:
        f.write(r.content)

    return

def decompress_data_file():

    print("[PSYCHIC] Decompressing data file at %s..." % "/Users/andrew/.config/greynoise/data_files/data_file.bin.gz")

    # Nabbed this code from stack overflow
    # https://stackoverflow.com/questions/52332897/how-to-extract-a-gz-file-in-python
    with gzip.open("/Users/andrew/.config/greynoise/data_files/data_file.bin.gz", 'rb') as s_file, open("/Users/andrew/.config/greynoise/data_files/data_file.bin", 'wb') as d_file:
        while True:
            block = s_file.read(65536)
            if not block:
                break
            else:
                d_file.write(block)

    return


def open_handle_to_data_file():

    # Return open handle to file
    return open("/Users/andrew/.config/greynoise/data_files/data_file.bin", "rb")

class Psychic(object):

    def __init__(self, 
            psychic_mode=PsychicMode.DISK,
            psychic_file_handle=None):

        self.psychic_mode = psychic_mode
        self.psychic_file_handle = psychic_file_handle

        # Check for data file
        if data_file_exists() == False:

            # If it doesn't, get it
            retrieve_data_file()

            # Decompress it
            decompress_data_file()

            # Confirm that it exists
            if data_file_exists():
                pass

        # Check for mode
        if self.psychic_mode == PsychicMode.MEM:

            # Slurp data file into memory
            self.mem = load_data_file_into_mem()

        elif self.psychic_mode == PsychicMode.DISK:

            # Open file handle to data file
            self.psychic_file_handle = open_handle_to_data_file()

        else:

            # Sling an error: invalid psychic mode
            print("[PSYCHIC] ERROR INVALID PSYCHIC MODE: %s" % self.psychic_mode)
            print("[PSYCHIC] SETTING PSYCHIC TO FALSE AND EJECTING")
            self.use_psychic = False
            return

    def check_ip(self, ip):
        
        #print("[PSYCHIC] check_ip() called on %s" % ip)
        
        result = bool()

        if self.psychic_mode == PsychicMode.MEM:
            result = check_ip_against_in_mem_data_structure(ip)
        elif self.psychic_mode == PsychicMode.DISK:
            result = self.check_ip_against_on_disk_data_file(ip)
        else:
            print("[PSYCHIC] ERROR INVALID MODE: %s" % self.psychic_mode)
        return result
        

    def check_ips(self, ips):

        #print("[PSYCHIC] check_ips() called on %s" % str(ips))
        
        results = {}

        for ip in ips:
            results[ip] = self.check_ip(ip)

        return results

    # Lower level operations
    def check_ip_against_on_disk_data_file(self, ip):
        
        # Get offset and bit position
        offset, position = ip2offsetposition(ip)

        # Seek to the offset
        self.psychic_file_handle.seek(offset)

        # Read one byte
        b = self.psychic_file_handle.read(1)

        # Convert the byte and mask to a list of IPs that are noise
        ips = offset_and_bytemask_to_ips(offset, b)
        results = ip in ips

        # Call logger
        #self.log_activity(ip, results)

        return results

    def check_ip_against_in_memory_data_file(self, ip):
        
        # Get offset and bit position
        offset, position = ip2offsetposition(ip)

        # Read the byte
        b = self.psychic_in_mem_data_structure[offset:offset+1]

        # Convert the byte and mask to a list of IPs that are noise
        ips = offset_and_bytemask_to_ips(offset, b)
        results = ip in ips

        # Call logger
        #self.log_activity(ip, results)

        return results

    def log_activity(self, ip, status):

        # WISHLIST
        #
        #   - Absolutely necessary:
        #       - IP looked up
        #       - Y/N response
        #       - Timestamp
        #   - Nice to haves:
        #       - Integration name
        #       - Binding language
        #       - Data file timestamp
        #       - Version info
        #
        # CONSIDERATIONS
        #
        # - Store in memory or write to file
        # - Flush/write/send interval
        #
        # THOUGHTS
        # 
        # - For now I'm going to proceed with in-mem and send/flush at something
        #   like a 10k interval
        # - For dev tho I'm going to write to file
        
        log_entry = {"ip": ip, "status": status, "timestamp": int(time.time())}
        self.psychic_log_enclave.append(log_entry)

        # Once the log enclave is bigger than N (or Y seconds have passed) ship it off.
        # In this case, write to file and move on,
        # but also possible to POST to API endpoint
        if len(self.psychic_log_enclave) >= self.psychic_log_enclave_size:

            print("[!] LOG ENCLAVE FULL! Flushing to file...")

            f = open(self.psychic_log_file, "a+")
            
            for entry in self.psychic_log_enclave:
                f.write("%s\n" % entry)
            f.close()

            self.psychic_log_enclave = []

            print("[!] Log enclave should be empty now. Here's the len: {}".format(len(self.psychic_log_enclave)))

        return
