
module Network.Probecraft where

import Network.Pcap
import Network.Probecraft.Sniff

printPackets iface cnt bpf = do
    pcap <- openLive iface 1500 False 100000
    setFilter pcap bpf True 0
    link <- datalink pcap
    print $ show link
    loopBS pcap cnt handler
    (statistics pcap) >>= print
    where handler = \head dat -> do
                        print "packet:"
                        print head
                        let pkt = id $! ethernet dat
                        print $ ((matchEth ./. matchIpv4) ./. (matchIcmp .|. matchTcp .|. matchUdp)) pkt
                        putStrLn $ pp pkt

