#/usr/bin/env python

from scapy.all import rdpcap, sniff
import json, ast, sys, argparse

ap_list=[]
prompt="no"

def main():
    global prompt
    #argv=sys.argv
    parser=argparse.ArgumentParser(description="Fingerprinting access points without an active connection to them.")
    parser.add_argument("-f", "--file", dest="file", help="A PCAP file of interest")
    parser.add_argument("-t", "--target", help="A target SSID to look for")
    parser.add_argument("-s", "--sniff", help="Sniff live traffic with argument to specify interface")
    #parser.add_argument("-i", "--iface", help="(For sniffing) What interface to sniff on")
    parser.add_argument("-u", "--update", action='store_true', help="Update values of the dictionary")
    args = parser.parse_args()
    if args.update:
        prompt="yes"
    if args.target:
        if args.file:
            file=args.file
            pcap=rdpcap(file)
            find(pcap, args.target)
        if args.sniff:
            sniff(prn=find, iface=args.sniff)
    else:
        if args.file:
            file=args.file
            pcap=rdpcap(file)
            parse(pcap)
        if args.sniff:
                sniff(prn=parse, iface=args.sniff)


def parse(pcap):
    #Importing dictionary for comparison
    dict_file=".dictionary"
    with open(dict_file, 'r') as file:
        temp=file.read()
        try:
            list_dict=ast.literal_eval(temp)
        except:
            list_dict={}
    for packet in pcap:
        if packet.type == 0 and packet.subtype ==8: #If packet is beacon
            if packet.info not in ap_list:          #If SSID has not been parsed
                ssid=packet.info
                ap_list.append(ssid)                #Add SSID to list
                id_list=[]
                for i in range(0,20):               #Iterate through layers. Layers are dynamic but I can't figure out how to get a length of them.
                    try:
                        frame=packet.getlayer(i)
                        id_list.append(frame.ID)    #Gets tag number and adds to list
                    except:
                        continue
                try:
                    print("\nSSID:" + ssid.decode("utf-8") + "\n")
                    print("Possible Firmware Version:",list_dict[str(id_list)])  #Print firmware version if tag sequence is in dictionary
                    if prompt=="yes":
                        print("\nWould you like to change the firmware version listed? [yes/no]\n")
                        change=input()
                        if change.lower() == 'yes':
                            print("\nEnter the new firmware version\nSpecify a range of firmware versions here\n")
                            fw_version=input()
                            list_dict[str(id_list)]=fw_version
                except:                             #Tries to get firmware version from user to add to dictionary
                    if prompt=="yes":
                        print("\nUnable to match firmware for",(packet.info.decode("utf-8")))
                        print("\nDo you know the firmware for " + (packet.info.decode("utf-8")) + "? [yes/no]\n" )
                        known=input()
                        if known.lower() == 'yes':
                            version=input("Please enter firmware version\n")
                            list_dict[str(id_list)]=version
                    else:
                        print("\nUnable to match firmware for",(packet.info.decode("utf-8")))


    with open(dict_file, 'w') as file:
        file.write(str(list_dict))

def find(pcap):
    args = parser.parse_args()
    target_ssid=args.target
        #Importing dictionary for comparison
        #pcap=rdpcap(pcap_raw)
        #target_ssid=args.target
    dict_file=".dictionary"
    with open(dict_file, 'r') as file:
        temp=file.read()
        try:
            list_dict=ast.literal_eval(temp)
        except:
            list_dict={}
    for packet in pcap:
        if (packet.info.decode("utf-8")) == target_ssid: #If SSID is target SSID
            if packet.type == 0 and packet.subtype ==8: #If packet is beacon
                id_list=[]
                for i in range(0,20):               #Iterate through layers. Layers are dynamic but I can't figure out how to get a length of them.
                    try:
                        frame=packet.getlayer(i)
                        id_list.append(frame.ID)    #Gets tag number and adds to list
                    except:
                        continue
                try:
                    print("\nPossible Firmware Version:",list_dict[str(id_list)])
                except:
                    print("\nUnable to match firmware versions")
                return 0
    print("\nUnable to find target SSID")

if __name__ == '__main__':
    main()
