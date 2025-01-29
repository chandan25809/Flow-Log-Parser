import os
import re
import csv
import socket
from collections import defaultdict

LOG_ENTRY_REGEX = re.compile(
    r"^2\s+"                      # Version must be "2"
    r"(\d{12})\s+"                # Account ID (12-digit number)
    r"(eni-[a-z0-9]+)\s+"         # Interface ID (eni-XXXX)
    r"([\d\.]+)\s+"               # Source IP Address (IPv4 format)
    r"([\d\.]+)\s+"               # Destination IP Address (IPv4 format)
    r"(\d+|-)\s+"                 # Source Port (integer or "-")
    r"(\d+|-)\s+"                 # Destination Port (integer or "-")
    r"(\d+)\s+"                   # Protocol (integer)
    r"(\d+)\s+"                   # Packets (integer)
    r"(\d+)\s+"                   # Bytes (integer)
    r"(\d+)\s+"                   # Start Time (Unix Timestamp)
    r"(\d+)\s+"                   # End Time (Unix Timestamp)
    r"(ACCEPT|REJECT)\s+"         # Action (ACCEPT or REJECT)
    r"(OK|NODATA|SKIPDATA)$"      # Log Status
)

class FlowLogParser:
    def __init__(self,log_file,lookup_file,output_file):
        self.log_file=log_file
        self.lookup_file=lookup_file
        self.lookup_table={}
        self.port_protocol_counts=defaultdict(int)
        self.tag_counts=defaultdict(int)
        self.output_file=output_file
        self.protocol_mapping = self.gen_protocol_mappings()

    def gen_protocol_mappings(self):
        common_protocols = [
            "tcp", "udp", "icmp", "igmp", "ggp", "ipv4", "st", "egp", "pup", "hmp",
            "xns-idp", "rdp", "iso-tp4", "dccp", "xtp", "ddp", "idpr-cmtp", "ipv6",
            "ipv6-route", "ipv6-frag", "gre", "esp", "ah", "skip", "ipv6-icmp",
            "ipv6-nonxt", "ipv6-opts", "rspf", "vmtp", "ospf", "ipip", "encap",
            "pim", "comp", "sctp"
        ]

        mappings = {}
        for protocol in common_protocols:
            try:
                protocol_number = socket.getprotobyname(protocol)
                mappings[str(protocol_number)] = protocol
            except OSError:
                continue  

        return mappings
    
    def get_protocol_name(self,protocol_number):
        return self.protocol_mapping.get(str(protocol_number), "unknown")
    
    def parse_log_entry(self,log_entry):
        log_entry = log_entry.strip()
        match = LOG_ENTRY_REGEX.match(log_entry)

        if not match:
            return None
        
        chunks=log_entry.split()
        
        if len(chunks)<13:
            return None

        log_version=chunks[0].strip()

        if log_version!="2":
            return None
        
        dstport = chunks[6].strip()
        protocol_number = chunks[7].strip()

        if protocol_number not in self.protocol_mapping:
            return None
        
        protocol=self.get_protocol_name(protocol_number)

        return dstport,protocol.lower()
    
    def load_lookup_table(self):

        if not self.lookup_file or not os.path.exists(self.lookup_file):
            print("No lookup table provided. All logs will be marked as 'Untagged'.")
            return 
        
        try:
            with open(self.lookup_file,mode='r') as file:
                reader = csv.reader(file)
                next(reader)
                for row in reader:
                    if len(row)!=3:
                        continue #skip invalid row
                    dstport,protocol,tag = map(str.strip, row)
                    # Skip rows where dstport is missing or not numeric**
                    if not dstport or not protocol or not tag or (not dstport.isdigit() and dstport != "0"):
                        continue  

                    self.lookup_table[(dstport.strip(),protocol.lower().strip())] = tag.strip()
        except Exception as e:
            print(f"Error reading lookup file: {e}")
    

    
    def get_tag_from_lookup(self,dstport,protocol):
        return self.lookup_table.get((dstport, protocol), "Untagged")
    
    
    def process_logs(self):
        try:
            with open(self.log_file,mode='r') as file:
                for line in file:
                    log_data=self.parse_log_entry(line)
                    if not log_data:
                        continue # Skip invalid or unsupported entries
                    dstport, protocol = log_data
                    tag = self.get_tag_from_lookup(dstport, protocol)
                    self.tag_counts[tag]+=1
                    self.port_protocol_counts[(dstport,protocol)]+=1
        except Exception as e:
            print(f"Error processing log file: {e}")

    def write_output(self):
        try:
            with open(self.output_file,mode='w') as file:
                self.write_tag_counts(file)
                self.write_port_protocol_counts(file)
            print(f"Output successfully written to {self.output_file}")
        except Exception as e:
            print(f"Error writing output file: {e}")

    def write_tag_counts(self,file):
        file.write("Tag Counts:\nTag,Count\n")
        for tag,count in self.tag_counts.items():
            file.write(f"{tag},{count}\n")
        file.write("\n")
    
    def write_port_protocol_counts(self,file):
        file.write("Port/Protocol Combination Counts:\nPort,Protocol,Count\n")
        for (port, protocol), count in self.port_protocol_counts.items():
            file.write(f"{port},{protocol},{count}\n")

if __name__ == "__main__":

    log_file = "flow_logs.txt"
    lookup_file = "lookup_table.csv"
    output_file = "output_results.txt"

    parser = FlowLogParser(log_file, lookup_file, output_file)
    parser.load_lookup_table()
    parser.process_logs()
    parser.write_output()
    print(f"Processing complete. Results saved in {output_file}.")
