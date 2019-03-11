import scapy.all as scapy
import sys
import oyaml as yaml
from collections import OrderedDict

pcap_pkts = scapy.rdpcap(sys.argv[1])
attackDict = {}
allDict = {}
attackProbList = []
mainIpMacList = []
attackMacCountList = []
benignList = []
arpTupleList = []
srcMacList = []
dstMacList = []
parameters = ["packet_index", "victim_mac_address", "attacker_mac_address", "benign_mac_address", "spoofed_ip_address"]
dictOrderedYaml = OrderedDict()
yamlMainList = []

# Add Source MAC
def sMacAdd(sMacList):
    for i in range(len(sMacList)):
        attackDict.setdefault(sMacList[i][0], [])
        if sMacList[i][1] not in attackDict[sMacList[i][0]]:
            attackDict[sMacList[i][0]].append(sMacList[i][1])

# Add Destination MAC
def dMacAdd(dMacList):
    for s in range(len(dMacList)):
        allDict.setdefault(dMacList[s][0], [])
        if dMacList[s][1] not in allDict[dMacList[s][0]]:
            allDict[dMacList[s][0]].append(dMacList[s][1])

# Create a Tuple for all packets
def allMacCountTuple(mydict1):
    for key, val in mydict1.iteritems():
        orgMacIp = (key, val)
        mainIpMacList.append(orgMacIp)

# Create a Tuple for Attacker
def attackMacCountTuple(mydict):
    for k, v in mydict.iteritems():
        macIp = (k, v, len(v))
        attackProbList.append(macIp)

# Tracker for Count. The number of times a unique IP address is seen for a MAC.
def Tracker(pkts):
    count = -1
    for packet in pkts:
        count = count + 1
        if packet.haslayer(scapy.Ether) and packet.haslayer(scapy.ARP):
            if packet[scapy.ARP].op == 2:
                actMac = packet[scapy.Ether].src
                targetMac = packet[scapy.Ether].dst
                frame = count
                smac = packet[scapy.ARP].hwsrc
                dmac = packet[scapy.ARP].hwdst
                sip = packet[scapy.ARP].psrc
                dip = packet[scapy.ARP].pdst
                if actMac == smac:
                    arpTuple = (smac, sip, dmac, dip, actMac, frame)
                    sMac = (smac, sip)
                    dMac = (dmac, dip)
                    arpTupleList.append(arpTuple)
                    srcMacList.append(sMac)
                    dstMacList.append(dMac)
        else:
            continue

# Check if Attacker by count of MAC to IP associations.
def checkAttacker(attMacListProb):
    for mac in attMacListProb:
        if mac[2] > 1:
            attackMacCountList.append(mac[0])

# Benign MAC Count
def benignMacCount(orgIpMacList):
    for omac in orgIpMacList:
        actMacIp = (omac[0], omac[1])
        benignList.append(actMacIp)

# Output YAML
def outputYaml(final_yaml_list):
    for element in final_yaml_list:
        print('---')
        print(yaml.dump(element, default_flow_style=False))


def main():
    Tracker(pcap_pkts)
    sMacAdd(srcMacList)
    dMacAdd(dstMacList)
    allMacCountTuple(allDict)
    attackMacCountTuple(attackDict)
    checkAttacker(attackProbList)
    benignMacCount(mainIpMacList)

    for attMac in attackMacCountList:
        attacker = attMac
        for i in arpTupleList:
            for j in benignList:
                actualMac = j[1]
                if attacker == i[0] and i[1] in j[1]:
                    dict_yaml = OrderedDict()
                    dict_yaml[parameters[0]] = i[5]
                    dict_yaml[parameters[1]] = str(i[2])
                    dict_yaml[parameters[2]] = str(i[0])
                    dict_yaml[parameters[3]] = str(j[0])
                    dict_yaml[parameters[4]] = str(i[1])
                    yamlMainList.append(dict_yaml)

    outputYaml(yamlMainList)


if __name__ == "__main__":
    sys.exit(main())

