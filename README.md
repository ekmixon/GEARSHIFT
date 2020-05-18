# GEARSHIFT
GEARSHIFT is a tool that attempts to create a fuzz harness for a specified address in a stripped binary. It is so named because it will likely leverage a mix of reverse and forward engineering.

## Proposal
Information from the original research proposal can be found in [proposal.md](proposal.md).

## Leveraged technologies
The initial plan intends to leverage disassemblers' existing parsing and code flow determination, as well as symbolic analysis engine(s) and, where applicable, debug symbols or source-assisted techniques.

### Disassembly
By allowing existing disassembly engines to determine executable and procedure entry points, static cross references can be used to find syntactic information about calls to the specified address. Additionally, disassemblers' ability to track arguments from API calls' arguments and return types to arguments passed to our address of interest will allow for more stringent harness creation.

### Symbolic Execution
Symbolic engines will allow for input bounding on arguments to the specified address, and may in some cases also give typing information. Input bounding (or value bounding within procedure flow) can then be used when generating input within a fuzzer.

### Open source projects used:
To be filled in as we leverage technologies and techniques

## References of interest:
To be filled in as we find interesting papers
