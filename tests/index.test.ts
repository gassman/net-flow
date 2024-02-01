import { Flow,Settings } from "../src";

function Response(): boolean {
    return true;
}

test('successfully parses a PCAP file', async () => {
    const opts = new Settings;
    opts.minPacketsPerFlow = 20;
    opts.maxPacketsPerFLow = 50;
    opts.inputPcapFilename = "/home/user/dev/js/net-flow/webgoat.pcap"
    opts.outputCsvFilename = "/home/user/dev/js/net-flow/webgoat_pcap_stats.csv"
    const test = new Flow(opts);
    const resp = await test.run();
    expect(resp).toBe(true);
  });