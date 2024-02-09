## net-flow

A basic TypeScript library to parse regular PCAP files and generate mathematical statistics about the packets within a flow.

After cloning the repository, install the required NPM packages:

`npm install`

Building Node compatible package: 

`npm run build`

Node .js, .d.ts and .map files are generated in the ./dist folder.

### Basic Usage

``` 
import { Flow, Settings } from "@gassman/net-flow";

const opts = new Settings();

opts.minPacketsPerFlow = 20;
opts.maxPacketsPerFLow = 50;
opts.opts.labelsToAdd = new Map([["Benign", true]]); 
opts.inputPcapFilename = "/home/user/test.pcap";
opts.outputCsvFilename = "/home/user/test_pcap_stats.csv";

const flow = new Flow(opts);
flow.run()
.then( (success: boolen) => {
    console.log("Done!");
})
.catch( (e) => {
    console.error(`Something went wrong, reason: ${e}`);
})
```

There are around 39 statistical values gathered for each flow including:
* Flow inter-arrival time
* Flow packet size
* Flow duration
* Flow length
Covering forward, reverse and total statistics and including minimum, maximum, mean and standard deviation values for some metrics. Optionally set a label to classify the output before importing the data into a machine learning tool

Outut is  in CSV format and suitable for consumptions within Pandas or other frameworks accepting CSV input.