import { LinkType, PacketWithHeader, PcapSession, createOfflineSession, decode } from "pcap";
import fs from "node:fs";
import { Buffer } from "node:buffer";
import {MinMax, StdDev, Mean} from "./maths";
import { LinkLayer } from "./network";

export class Settings {
    maxPacketsPerFLow = 82;
    minPacketsPerFlow = 15;
    inputPcapFilename:string = "";
    outputCsvFilename:string = "";
    labelsToAdd: Map<string, string | number | boolean > = new Map();
}

// Enumerates traffic flow direction
enum Direction {
    Forward,
    Reverse
}

export class Stats {
    total: number = 0;
    min: number = 0;
    max: number = 0;
    stdDev: number = 0.0;
    mean: number = 0.0;
    constructor() {
    }
}

// Class encapsulates packet sorce and destination
// derives map keys for packet storage
export class PacketVector {
    srcIp: string = "";
    srcPort: number = 0;
    dstIp: string = "";
    dstPort: number = 0;
    protocol: string = "TCP"

    constructor( srcIp: string, 
                 srcPort: number,
                 protocol: string,
                 dstIp: string,
                 dstPort: number ) {
        this.srcIp = srcIp;
        this.srcPort = srcPort;
        this.protocol = protocol;
        this.dstIp = dstIp;
        this.dstPort = dstPort;
    }

    key(): string {
        return `${this.srcIp}:${this.srcPort}:${this.protocol}:${this.dstIp}:${this.dstPort}`;
    }
    
    reverseKey(): string {
        return `${this.dstIp}:${this.dstPort}:${this.protocol}:${this.srcIp}:${this.srcPort}`;
    }

    toCsvString(): string {
       return `${this.key()},${this.srcIp},${this.dstIp},${this.protocol},${this.srcPort},${this.dstPort}`
    }
}

// Class to store packet statistics within a flow
export class PacketStats {
    packetVec!: PacketVector;
    flowLength: number = 0;
    flowStartTime: number = 0;
    flowPrevTime: number = 0;
    flowDuration: number = 0;
    packetSizes: Array<number> = [];
    packetSize: Stats = new Stats();
    intArrTime: Stats = new Stats();
    intArrTimes: Array<number> = [];
    fwdPacketSizes: Array<number> = [];
    fwdPacketSize: Stats = new Stats();
    fwdFlowLength: number = 0;
    fwdFlowPrevTime: number = 0;
    fwdIntArrTimes: Array<number> = [];
    fwdIntArrTime: Stats = new Stats();
    revPacketSizes: Array<number> = [];
    revPacketSize: Stats = new Stats();
    revFlowLength: number = 0;
    revFlowPrevTime: number = 0;
    revIntArrTimes: Array<number> = [];
    revIntArrTime: Stats = new Stats();
    minPacketsBool: boolean = false;

    constructor( pv: PacketVector) {
        this.packetVec = pv;
    }

    // CSV report header
    static header(labels:Map<string,string|number|boolean>): string {
        let headerStr = "";
        const headerElements = ["Key","SrcIP", "DstIP", "Protocol", "SrcPort", 
                                "DstPort", "FlowDuration", "FlowLength", 
                                "FwdFlowLength", "RevFlowLength", "PacketSizeTotal",
                                "PacketSizeMean", "PacketSizeStd", "PacketSizeMin",
                                "PacketSizeMax", "FwdPacketSizeTotal", "RevPacketSizeTotal",
                                "FwdPacketSizeMean", "RevPacketSizeMean", "FwdPacketSizeStd",
                                "RevPacketSizeStd", "FwdPacketSizeMin", "RevPacketSizeMin",
                                "FwdPacketSizeMax", "RevPacketSizeMax", "IntArrTimeMean",
                                "IntArrTimeStd", "IntArrTimeMin", "IntArrTimeMax", "FwdIntArrTimeTotal",
                                "RevIntArrTimeTotal", "FwdIntArrTimeMean", "RevIntArrTimeMean",
                                "FwdIntArrTimeStd", "RevIntArrTimeStd", "FwdIntArrTimeMin",
                                "RevIntArrTimeMin", "FwdIntArrTimeMax", "RevIntArrTimeMax",
                                "FlowLengthPerTime", "FwdFlowLengthPerTime", "RevFlowLengthPerTime",
                                "PacketSizeTotalPerTime", "FwdPacketSizeTotalPerTime", "RevPacketSizeTotalPerTime"]
        for( let i=0; i < headerElements.length; i++ ) {
            headerStr += headerElements[i] + ",";
        }
        for( const key of labels.keys() ) {
            headerStr += key + ",";
        }
        headerStr=headerStr.slice(0, -1);
        headerStr += "\n";
        return headerStr;
    }

    // CSV row element
    row(labels:Map<string,string|number|boolean>): string {
        let rowStr = "";
        const rowElements = [this.flowDuration, this.flowLength, this.fwdFlowLength, this.revFlowLength,
            this.packetSize.total, this.packetSize.mean, this.packetSize.stdDev, this.packetSize.min,
            this.packetSize.max, this.fwdPacketSize.total, this.revPacketSize.total, this.fwdPacketSize.mean,
            this.revPacketSize.mean, this.fwdPacketSize.stdDev, this.revPacketSize.stdDev, this.fwdPacketSize.min,
            this.revPacketSize.min, this.fwdPacketSize.max, this.revPacketSize.max, this.intArrTime.mean,
            this.intArrTime.stdDev, this.intArrTime.min, this.intArrTime.max, this.fwdIntArrTime.total,
            this.revIntArrTime.total, this.fwdIntArrTime.mean, this.revIntArrTime.mean, this.fwdIntArrTime.stdDev,
            this.revIntArrTime.stdDev, this.fwdIntArrTime.min, this.revIntArrTime.min, this.fwdIntArrTime.max,
            this.revIntArrTime.max, this.flowLength/this.flowDuration, (this.fwdFlowLength/this.flowDuration),
            (this.revFlowLength/this.flowDuration), (this.packetSize.total/this.flowDuration), (this.fwdPacketSize.total/this.flowDuration),
            (this.revPacketSize.total/this.flowDuration)]
        for( let i=0; i < rowElements.length; i++ ) {
            rowStr += rowElements[i] + ",";
        }
        for( const value of labels.values() ) {
            rowStr += value + ",";
        }

        rowStr = rowStr.slice(0,-1);
        return this.packetVec.toCsvString() + `,${rowStr}\n`;
    }
}



// Class encapsulates PCAP Header details for each packet.
// https://www.netresec.com/?page=Blog&month=2022-10&post=What-is-a-PCAP-file
export class PcapPacketHeader {
    private tv_sec: number;
    private tv_usec: number;
    private len: number;
    private caplen: number;

    constructor( buff: Buffer ) {
        this.tv_sec = buff.readUInt32LE(0);
        this.tv_usec = buff.readUInt32LE(4);
        this.caplen = buff.readUInt32LE(8);
        this.len = buff.readUInt32LE(12);
    }

    timeInMilliseconds(): number {
        return Math.round((this.tv_sec * 1000.0 ) + (this.tv_usec / 1000.0))
    }

    timeInMicroseconds(): number {
        return Math.round((this.tv_sec * 1000000.0 ) + this.tv_usec)
    }

    length(): number {
        return this.len
    }

    capturedLength(): number {
        return this.caplen;
    }

}


/// Class encapsulating network flows between a source and destination endpoint
export class Flow {
    private session!: PcapSession;
    private flows = new Map<string, PacketStats>();
    private pcapPktHeader!: PcapPacketHeader;
    private settings = new Settings();
    private complete = false;

    // Attempts to open the PCAP file and process the data
    // sessions emit a number of packet events, and a final complete event
    constructor( opts: Settings ){
        if ( opts.inputPcapFilename.length < 6 )
            throw new Error('input PCAP file name must be more than 6 characters');
        this.settings = opts;
    }


    async run(): Promise<boolean> {
        try {
            this.session = createOfflineSession(this.settings.inputPcapFilename);
        } catch( e ) {
            console.error(`error processing pcap file. reason: ${e}`);
        }
        return await new Promise((resolve, reject) => {
            this.session.on('error', (err)=> {
                reject(`error raised during processing, reason ${err}`);
            })
            this.session.on('packet', (pkt: PacketWithHeader) => {
                const pph = new PcapPacketHeader(pkt.header);
                const dataPkt = decode.packet(pkt);
                const pktDetails = new LinkLayer(dataPkt.payload as LinkLayer);
                let packetVec = new PacketVector( pktDetails.network.saddr.toString(), 
                                                pktDetails.network.transport.sport,
                                                pktDetails.network.protocolName,
                                                pktDetails.network.daddr.toString(),
                                                pktDetails.network.transport.dport );
                this.processPacket(packetVec, pph);
            });
            this.session.on('complete', () => {
                let outFileName = "";
                if (this.settings.outputCsvFilename == "") {
                    let name = this.settings.inputPcapFilename.split('.')[0];
                    name += "_pcap_stats.csv"
                    outFileName = name;
                } else {
                    outFileName = this.settings.outputCsvFilename;
                }
                fs.writeFileSync(outFileName, PacketStats.header(this.settings.labelsToAdd));
                this.flows.forEach(( pkt: PacketStats ) => {
                    if( pkt.minPacketsBool )
                        fs.appendFileSync(outFileName, pkt.row(this.settings.labelsToAdd));
                });
                resolve(true);
            })
        })
    }


    // Determine if the flow map already has an existing stats package for the packet
    // Determine flow direction
    // Initialise new flow packet, or update and existing statistics package
    processPacket( pktVec: PacketVector, pph: PcapPacketHeader ) {
        const fwdPkt = this.flows.has(pktVec.key())
        const revPkt = this.flows.has(pktVec.reverseKey())
        const pktExists = fwdPkt || revPkt;
        let direction!: Direction;
        let key = "";
        if ( !fwdPkt && !revPkt ) {
            direction = Direction.Forward;
            key = pktVec.key();
        } else if ( fwdPkt && !revPkt ) {
            direction = Direction.Forward;
            key = pktVec.key();
        } else if ( !fwdPkt && revPkt ) {
            direction = Direction.Reverse;
            key = pktVec.reverseKey();
        } else {
            console.error('Forward and reverse keys should not co-exist, code error')
        }

        if( !pktExists ) {
            let pktStats = new PacketStats(pktVec);
            if ( direction === Direction.Forward ) {
                pktStats.fwdPacketSizes.push(pph.length());
                pktStats.fwdPacketSize.total = pph.length();
                pktStats.fwdPacketSize.mean = pph.length() * 1.0;
                pktStats.fwdFlowLength = 1;
                pktStats.fwdFlowPrevTime = pph.timeInMicroseconds();
            } else {
                pktStats.revPacketSizes.push(pph.length());
                pktStats.revPacketSize.total = pph.length();
                pktStats.revPacketSize.mean = pph.length() * 1.0;
                pktStats.revFlowLength = 1;
                pktStats.revFlowPrevTime = pph.timeInMicroseconds();
            }
            pktStats.flowStartTime = pph.timeInMicroseconds();
            pktStats.flowPrevTime = pph.timeInMicroseconds();
            pktStats.flowLength = 1;
            this.flows.set(key, pktStats);
        } else {
            const pktStats = this.flows.get(key);
            if ( pktStats == undefined ) {
                console.error( `could not find stats with key ${key}`);
                return
            }
            // Only update if the maximum packets hasn't been reached
            if ( pktStats.flowLength < this.settings.maxPacketsPerFLow ) {
                const currInterArrivalTime = pph.timeInMicroseconds() - pktStats.flowPrevTime;
                pktStats.packetSizes.push(pph.length())
                pktStats.intArrTimes.push(currInterArrivalTime);
                if ( direction === Direction.Forward ) {
                    pktStats.fwdPacketSizes.push(pph.length());
                    pktStats.fwdFlowLength += 1;
                    if ( pktStats.fwdFlowLength === 1 ) {
                        pktStats.fwdFlowPrevTime = pph.timeInMicroseconds();
                    } else {
                        const curFwdInterArrivalTime = pph.timeInMicroseconds() - pktStats.fwdFlowPrevTime;
                        pktStats.fwdIntArrTime.total += curFwdInterArrivalTime;
                        pktStats.fwdIntArrTimes.push(curFwdInterArrivalTime);
                        pktStats.fwdIntArrTime.mean = Mean(pktStats.fwdIntArrTimes);
                        pktStats.fwdIntArrTime.stdDev = StdDev(pktStats.fwdIntArrTimes);
                        let [min,max] = MinMax(pktStats.fwdIntArrTimes);
                        pktStats.fwdIntArrTime.min = min;
                        pktStats.fwdIntArrTime.max = max;
                        pktStats.fwdPacketSize.total += pph.length();
                        pktStats.fwdPacketSize.mean = Mean(pktStats.fwdPacketSizes);
                        pktStats.fwdPacketSize.stdDev = StdDev(pktStats.fwdPacketSizes);
                        [min,max] = MinMax(pktStats.fwdPacketSizes);
                        pktStats.fwdPacketSize.min = min;
                        pktStats.fwdPacketSize.max = max;
                        pktStats.fwdFlowPrevTime = pph.timeInMicroseconds();
                    }
                }
                if ( direction === Direction.Reverse ) {
                    pktStats.revPacketSizes.push(pph.length());
                    pktStats.revFlowLength += 1;
                    if ( pktStats.revFlowLength === 1 ) {
                        pktStats.revFlowPrevTime = pph.timeInMicroseconds();
                    } else {
                        const curRevInterArrivalTime = pph.timeInMicroseconds() - pktStats.revFlowPrevTime;
                        pktStats.revIntArrTime.total += curRevInterArrivalTime;
                        pktStats.revIntArrTimes.push(curRevInterArrivalTime);
                        pktStats.revIntArrTime.mean = Mean(pktStats.revIntArrTimes);
                        pktStats.revIntArrTime.stdDev = StdDev(pktStats.revIntArrTimes);
                        let [min, max] = MinMax(pktStats.revIntArrTimes);
                        pktStats.revIntArrTime.min = min;
                        pktStats.revIntArrTime.max = max;
                        pktStats.revPacketSize.total += pph.length();
                        pktStats.revPacketSize.mean = Mean(pktStats.revPacketSizes);
                        pktStats.revPacketSize.stdDev = StdDev(pktStats.revPacketSizes);
                        [min, max] = MinMax(pktStats.revPacketSizes);
                        pktStats.revPacketSize.min = min;
                        pktStats.revPacketSize.max = max;
                        pktStats.revFlowPrevTime = pph.timeInMicroseconds();
                    }
                }
                pktStats.flowDuration = pph.timeInMicroseconds() - pktStats.flowStartTime;
                pktStats.flowLength += 1;
                const currInterArrTimes = pktStats.fwdIntArrTimes.concat(pktStats.revIntArrTimes);
                pktStats.intArrTime.total = pktStats.fwdIntArrTime.total + pktStats.revIntArrTime.total;
                if ( currInterArrTimes.length > 1 ) {
                    pktStats.intArrTime.stdDev = StdDev(currInterArrTimes);
                    const [min, max] = MinMax(currInterArrTimes)
                    pktStats.intArrTime.min = min;
                    pktStats.intArrTime.max = max;
                    pktStats.intArrTime.mean = Mean(currInterArrTimes);
                }
                pktStats.flowPrevTime = pph.timeInMicroseconds();
                pktStats.packetSize.total = pktStats.fwdPacketSize.total + pktStats.revPacketSize.total;
                pktStats.packetSize.mean = Mean(pktStats.packetSizes);
                const [min, max] = MinMax(pktStats.packetSizes)
                pktStats.packetSize.min = min;
                pktStats.packetSize.max = max;
                pktStats.packetSize.stdDev = StdDev(pktStats.packetSizes);
                if (pktStats.flowLength > this.settings.minPacketsPerFlow)
                    pktStats.minPacketsBool = true;
                this.flows.set(key, pktStats);
            }
        }
    }
}