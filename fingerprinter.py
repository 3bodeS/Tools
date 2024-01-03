from scapy.all import *
import argparse

"""
 def active_fingerprint(target: str, sport0: int, dport0: int):
	seq=100
	ip = IP(dst=target)
	tcp= TCP(sport= sport0, dport= dport0, flags="S", seq= seq)

	packet= ip/tcp
	synack_packet = sr1(packet)

	next_seq = seq + 1
	my_ack = synack_response.seq + 1

	ack_packet = TCP(sport=sport0, dport=dport0, flags="A", seq=next_seq, ack=my_ack)
	send(ip/ack_packet)

	payload_packet = TCP(sport=sport, dport=dport, flags='', seq=next_seq)
	payload="some data"
	send(ip/payload_packet/payload)
"""

def argument_parser():
    """Allow user to specify target host and port."""
    parser = argparse.ArgumentParser(description="Basic OS detection tool.")
    parser.add_argument("-H", "--host", help="Host IP address")
    parser.add_argument("-sP", "--sendport",help="sender port'")
    parser.add_argument("-dP", "--destport",help="destination port'")

    var_args = vars(parser.parse_args())  # Convert argument namespace to dictionary
    return var_args

def fingerprint(target: str, sport0: int, dport0: int):
	seq=100
	ip = IP(dst=target)
	tcp= TCP(sport= sport0, dport= dport0, flags="S", seq= seq)

	packet= ip/tcp
	synack_packet = sr1(packet ,verbose=0)
	#synack_packet.show()
	if synack_packet.ttl == 128:
		return "Windows"
	elif synack_packet.ttl == 64:
		return "Linux"

	
'''
ip= str(input("Enter the target ip: "))
sendp= int(input("Enter Sending Port: "))
destp= int(input("Enter destination Port: "))
'''

if __name__ == "__main__":
	try:
		user_args = argument_parser()
		host = str(user_args["host"])
		sport = int(user_args["sendport"])
		dport = int(user_args["destport"])
		print(f"The Host {host} OS is " + fingerprint(host, sport, dport))
	except AttributeError:
		print("Error. Please provide the command-line arguments before running.")


