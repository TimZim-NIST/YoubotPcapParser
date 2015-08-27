#
# Author:       Timothy Zimmerman (timothy.zimmerman@nist.gov)
# Organization: National Institute of Standards and Technology
#               U.S. Department of Commerce
# License:      Public Domain
#
# Description:  Searches through the current directory for all PCAP files and
#               unifies them into a single PCAP file, as well as inserting
#               all the packets into a SQLite database.
#
# Resource(s):  http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html
#               http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
#               http://sebastianraschka.com/Articles/sqlite3_database.html
#

import datetime
import glob
import sqlite3
from struct import unpack
import pyshark
import ros_msg_dissector as rosDisector
import hashlib

# Create the DB with the current date and time
curr_date = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
conn = sqlite3.connect("unified_" + curr_date + ".db")

# Create the SQLite cursor and table
c = conn.cursor()

c.execute('''CREATE TABLE packets (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                shark_timestamp REAL, \
                shark_file_id INTEGER, \
                shark_frame_num INTEGER, \
                shark_eth_dst TEXT, \
                shark_eth_src TEXT, \
                shark_ip_dst TEXT, \
                shark_ip_src TEXT, \
                shark_tcp_port_dst INTEGER, \
                shark_tcp_port_src INTEGER, \
                shark_tcp_seq_num INTEGER, \
                shark_tcp_next_seq_num INTEGER, \
                shark_tcp_expected_ack INTEGER, \
                shark_tcp_checksum INTEGER, \
                shark_analysis_initial_rtt REAL, \
                shark_data BLOB, \
                shark_data_len INTEGER, \
                md5_hash TEXT \
                )''')

c.execute('''CREATE TABLE rosPackets (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                parent_id INTEGER, \
                shark_frame_num INTEGER, \
                shark_data BLOB, \
                shark_data_len INTEGER, \
                ros_msg_tuple TEXT, \
                md5_hash TEXT \
                )''')
                
c.execute('''CREATE TABLE pcapFiles (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, machinename TEXT)''')
c.execute('''CREATE TABLE unclassifiedROSMessages ( id INTEGER PRIMARY KEY AUTOINCREMENT, \
                                                    parent_id INTEGER, \
                                                    pyshark_id INTEGER, \
                                                    packet_data BLOB \
                                                    )''')

# Iterate through the current directory for all PCAP files
for filename in glob.glob(".\YoubotCycle1\*.pcap"):
    # Open the current PCAP file...
    f = open(filename, 'rb')
    magic_num = f.read(4);
    f.close()
    
    # Print the filename for diagnostics
    print ("\n[FOUND]: \"" + str(filename) + "\"")
    
    # Store the machine name for later reference
    machine_name = filename.split('_')[0]
    print ("Machine name: " + machine_name)
    
    # Insert it into the DB
    filetuple = (str(filename), str(machine_name))
    c.execute('''INSERT INTO pcapFiles VALUES (NULL, ?,?)''', filetuple)
    c.execute('''SELECT last_insert_rowid()''')
    pcap_filenumber = c.fetchone()[0]
    print("File number: " + str(pcap_filenumber))

    # Check the global header for proper format and the endianness
    if unpack('>I', magic_num)[0] == 0xd4c3b2a1:
        unpack_header = '<'
    elif unpack('>I', magic_num)[0] == 0xa1b2c3d4:
        unpack_header = '>'
    else:
        print ('This PCAP file doesn\'t seem right... exiting.')
        exit()

    detectedPackets = 0
    dissectedPackets = 0
	
     # Filter for packets in pyshark (exactly as would be entered into Wireshark filter GUI)
     # The filter "tcp && !nfs && !ssh &&!http && !ntp && tcp.flags == 0x0018" removes most
     # unwanted packets that have been encountered during normal robotic enclave operation
    pyshark_filter = "tcp && !nfs && !ssh && !http && !ntp && !ethercat && tcp.flags == 0x0018 && data"
	
    captureFile = pyshark.FileCapture(filename, display_filter=pyshark_filter)
    for packet in captureFile:
        
        try:
            detectedPackets += 1
            
            md5_string = (packet.eth.dst, packet.eth.src, packet.ip.dst, packet.ip.src, packet.tcp.dstport, packet.tcp.srcport, \
                          packet.tcp.seq, packet.tcp.nxtseq, packet.tcp.ack, packet.data.data.binary_value, packet.data.len)
            md5_string = bytes(str(md5_string),'utf-8')
            packet_md5 = hashlib.md5(md5_string).hexdigest()
            
            packetTuple = ( packet.sniff_timestamp, pcap_filenumber, packet.frame_info.number, packet.eth.dst, packet.eth.src, \
                    packet.ip.dst, packet.ip.src, packet.tcp.dstport, packet.tcp.srcport, packet.tcp.seq, \
                    packet.tcp.nxtseq, packet.tcp.ack, packet.tcp.checksum, packet.tcp.analysis_initial_rtt, \
                    packet.data.data.binary_value, packet.data.len, packet_md5)
            
            c.execute('''INSERT INTO packets VALUES (NULL, ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', packetTuple)
            curr_id = c.lastrowid
    
            # Run the packet data through the dissector to determine if it is a ROS
            # packet of the types we are looking for, and if so store the data
            packetData = rosDisector.dissectPacket(unpack_header, packet.data.data.binary_value)
            
            # Did the function return data? No data means it was not able to dissect
            if len(packetData) > 0:
                dissectedPackets += 1
                for msg in packetData:
                    rosTuple = ( curr_id, packet.frame_info.number, packet.data.data.binary_value, packet.data.len, str(msg), packet_md5)
                    c.execute('''INSERT INTO rosPackets VALUES (NULL, ?,?,?,?,?,?)''', rosTuple)
            else:
                packetTuple = ( curr_id, packet.frame_info.number, packet.data.data.binary_value)
                c.execute('''INSERT INTO unclassifiedROSMessages VALUES (NULL, ?,?,?)''', packetTuple)
                # Then we will insert all of this into the database
                
        except:
            pass
        
    successPercent = (dissectedPackets/detectedPackets)*100
    print(  "Successfully dissected " + str(dissectedPackets) + " out of " + str(detectedPackets) + \
            " packets ({0:.2f}".format(successPercent) + "%) in " + str(filename))
    
    # Commit the changes we have made to the DB before we open a new file
    conn.commit()
    #print("[DONE]")
    
c.execute('''SELECT last_insert_rowid()''')
pcap_filenumber = c.fetchone()[0]

# Now we have a database and a PCAP file with the same data, close everything!
conn.close()



























