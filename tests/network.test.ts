import { LinkLayer, NetworkLayer, TransportLayer } from "../src/network";

const testTL =    { 
    ackno: 534,
    checksum: 409867583,
    data: "akigi3ptkwpgwleltj",
    dataLength: 456,
    dport: 8080,
    flags: ["a","b","c"],
    headerLength: 95,
    options: [],
    reserved: "test",
    seqno: 526,
    sport: 24356,
    urgentPointer: 0,
    windowSize: 220
}

const testNL =    { 
    daddr: "192,168,23,143",
    saddr: "10,4,7,1",
    diffserv: 123,
    flags: ['a','c','e'],
    fragmentOffest: 9359,
    headerChecksum: 49395938,
    headerLength: 425,
    identification: 6367,
    length: 124,
    protocol: 17,
    protocolName: "",
    ttl: 42,
    version: 123,
    payload: testTL
}

const testLL =    { 
    shost: "a2:45:9e:27:1b:ec",
    dhost: "2a:54:e9:72:b1:ce",
    ethertype: 2,
    vlan: "123",
    network: null,
    payload: testNL
}


test('successfully creates transport layer', () => {
    const test = new LinkLayer(testLL as unknown as LinkLayer)
    expect(test).toBeInstanceOf(LinkLayer);
});

test('successfuly creates a network layer', () => {
    const test = new NetworkLayer(testNL as unknown as NetworkLayer)
    expect(test).toBeInstanceOf(NetworkLayer);
});

test('successfuly creates a transport layer', () => {
    const test = new TransportLayer(testTL as unknown as TransportLayer)
    expect(test).toBeInstanceOf(TransportLayer);
});