import argparse
import logging
import sys

from src.bacon.core import Bacon


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Fingerprinting access points without an active connection to them.")
    parser.add_argument("-f", "--file", dest="file", help="A PCAP file of interest")
    parser.add_argument("-t", "--target", help="A target SSID to look for")
    parser.add_argument("-s", "--sniff", help="Sniff live traffic with argument to specify interface")
    parser.add_argument("-i", "--interface", help="(For sniffing) What interface to sniff on")
    parser.add_argument("-u", "--update", action='store_true', help="Update values of the dictionary")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    log = logging.getLogger('BACON')
    log.setLevel(logging.INFO)
    if args.verbose:
        log.setLevel(logging.DEBUG)
    log_format = logging.Formatter("[BACON-%(levelname)s] %(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(log_format)
    log.addHandler(ch)
    print("Bacon Finger Printer")
    bacon = Bacon(args.file, args.target, args.sniff, args.interface, args.update, log)
    bacon.run()