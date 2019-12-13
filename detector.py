import dpkt, sys, socket
file = sys.argv[1]
file = open(file, 'rb')
pcap = dpkt.pcap.Reader(file)
syn = {}
synack = {}
for (ts,buf) in pcap:
    try:
        ethernet = dpkt.ethernet.Ethernet(buf)
        ip = ethernet.data
        tcp = ip.data
        if(tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK):
            if(ip.src in syn.keys()):
                syn[ip.src] += 1
            else:
                syn[ip.src] = 1
                synack[ip.src] = 0
        elif(tcp.flags & dpkt.tcp.TH_ACK and tcp.flags & dpkt.tcp.TH_SYN ):
            if(ip.dst in synack.keys()):
                synack[ip.dst] += 1
            else:
                synack[ip.dst] = 1
                syn[ip.dst] = 0
    except:
        pass
for key in syn:
    if(syn[key]>(synack[key]*3) or (syn[key]>0 and synack[key]==0)):
        value = ""
        try:
            value = socket.inet_ntop(socket.AF_INET, key)
        except ValueError:
            value = socket.inet_ntop(socket.AF_INET6, key)
        print(value)