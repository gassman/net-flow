// Class encapsulates ethernet details from
// decoded PCAP packet
export class LinkLayer {
    network!: NetworkLayer;
    shost!: EthernetAddr;
    dhost!: EthernetAddr;
    ethertype: number = 0;
    vlan: string = "";
    payload!: any

    constructor( obj: LinkLayer ) {
        this.dhost = obj.dhost;
        this.shost = obj.shost;
        this.ethertype = obj.ethertype;
        this.vlan = obj.vlan;
        this.network = new NetworkLayer( obj.payload as NetworkLayer)
    }

}


// Class encapsulating ethernet MAC address
export class EthernetAddr {

    addr;

    constructor(ether: string) {
        this.addr = Array.from(ether);
    }

    // Return string representation of the address array
    toString(){
        return `${this.addr[0]}:${this.addr[1]}:${this.addr[2]}:${this.addr[3]}:${this.addr[4]}:${this.addr[5]}`;
    }
}

// Class to encapsulate network layer PCAP details
export class NetworkLayer {
    transport!: TransportLayer;
    daddr!: IPAddress;
    saddr!: IPAddress;
    diffserv: number = 0;
    flags: any;
    fragmentOffest: number = 0;
    headerChecksum: number = 0;
    headerLength: number = 0;
    identification: number = 0;
    length: number = 0;
    protocol: number = 0;
    payload: any;
    protocolName: string = "";
    ttl: number = 0;
    version: number = 0;

    // Clone from a cast JSON network layer object
    constructor( obj: NetworkLayer) {
        this.daddr = obj.daddr;
        this.saddr = obj.saddr;
        this.diffserv = obj.diffserv;
        this.flags = obj.flags;
        this.fragmentOffest = obj.fragmentOffest;
        this.headerChecksum = obj.headerChecksum;
        this.headerLength = obj.headerLength;
        this.identification = obj.identification;
        this.length = obj.length;
        this.protocol = obj.protocol;
        this.protocolName = this.getProtocol(this.protocol);
        this.ttl = obj.ttl;
        this.version = obj.version;
        this.transport = new TransportLayer(obj.payload as TransportLayer);
    }

    // Returns string value of network protocol based on numberic value
    private getProtocol( num: number ): string {
        let protName = "";

        switch( num ) {
            case 1: protName = 'ICMP';
                break;
            case 2: protName = 'IGMP';
                break;
            case 6: protName = 'TCP';
                break;
            case 17: protName = 'UDP';
                break;
            default: protName = '???';
        }
        return protName;
    }
}

export class IPAddress {
    addr;
    constructor(ip: string) {
        this.addr = Array.from(ip);    
    }

    // Returns the string representation of a IP address
    // IPv4: aaa.bbb.ccc.ddd
    // IPv6: aabb:ccdd:eeff:0011:2233:4455:6677:8899
    toString(): string {
        let response = "";
        let separator = "."
        if ( this.addr.length > 4 ){
            for( let i=0; i < this.addr.length; i++ ){
                if ( i % 2 === 0 )
                    response += this.addr[i] + separator;
                else
                    response += this.addr[i];
            }
            response = response.slice(0,-1);
        } else {
            for( let i=0; i < this.addr.length; i++ ){
                response += this.addr[i] + separator;
            }    
        }
        response = response.slice(0,-1);
        return response;
    }
}

// Class encapsulating transport layer details of
// decode PCAP packet
export class TransportLayer {
    ackno: number = 0;
    checksum: number = 0;
    data!: string;
    dataLength: number = 0;
    dport: number = 0;
    flags: any;
    headerLength: number = 0;
    options: any;
    reserved: string = "";
    seqno: number = 0;
    sport: number = 0;
    urgentPointer: number = 0;
    windowSize: number = 0;

    constructor(obj: TransportLayer){
        this.ackno = obj.ackno;
        this.checksum = obj.checksum;
        this.data = obj.data;
        this.dataLength = obj.dataLength;
        this.dport = obj.dport;
        this.flags = obj.flags;
        this.headerLength = obj.headerLength;
        this.options = obj.options;
        this.reserved = obj.reserved;
        this.seqno = obj.seqno;
        this.sport = obj.sport;
        this.urgentPointer = obj.urgentPointer;
        this.windowSize = obj.windowSize;
    }
}