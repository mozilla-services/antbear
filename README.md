# antbear

`antbear` is a command line tool named after the [giant
anteater](https://en.wikipedia.org/wiki/Giant_anteater) that:

1. [slurps up captures and traces](#slurping-captures-and-traces)

1. converts and sticks the data together into a long, sticky timeline

1. consumes the timeline to find bugs, validate properties, or
   generate documentation

## slurping captures and traces

1. anteater currently reads files ending with `.pcap` as [packet
captures](https://en.wikipedia.org/wiki/Pcap) and `.har` as [HTTP
archives](https://en.wikipedia.org/wiki/HAR_(file_format))




## tips

* provide as comprehensive data as possible e.g. from a functional
  test run with high coverage against a local development service






Goals:

* allow devs, ops, and dev ops to analyze the security of the
  applications and services across more of the network stack (TCP/IP
  and application layer)
* continual assessment
* document and export metrics
* run offline / against passive / sniffed traffic or traces


Non-goals:

* active testing or probing e.g. for exposed git directories
* interactive UI
* report generation e.g. PDFs


Pipelines:

assess: Read -> Combine into a rough timeline -> Analyze -> Write
convert/document: Read -> Combine into a rough timeline -> Write


# Usage

## Limitations

* cannot defragment chunked or large responses from pcap files
