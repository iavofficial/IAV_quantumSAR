# IAV quantumSAR
IAV quantumSAR is planned as an AUTOSAR Cryptodriver with a collection of post-quantum cryptographic algorithms for microcontroller presented by [IAV GmbH](https://www.iav.com/). The post-quantum cryptographic algorithms are based on the [PQClean](https://github.com/PQClean/PQClean) repository, which is a clean collection of the [NIST post-quantum project](https://csrc.nist.gov/projects/post-quantum-cryptography). IAV quantumSAR implements these algorithms to use them for automotive microcontrollers in an AUTOSAR Classic environment. The goal is to have a collection of various cryptographic algorithms for future automotive cybersecurity projects preparing for the upcoming computing power of quantum computers.

## Security Note
There was no security risk analysis like TARA or similar carried out for QuantumSAR. The post-quantum cryptographic algorithms itself were evaluated by NIST.

## Content
The base of IAV quantumSAR is the PQCleanAutomotive repository. It includes the following post-quantum cryptographic algorithms:

* CRYSTALS-KYBER

The following post-quantum cryptographic algorithms are in work:

* CRYSTALS-DILITHIUM
* FALCON
* SPHINCS+

## Implementation
For the integration of IAV quantumSAR, the file Crypto.c contains an example of the use of the CRYSTALS-KYBER algorithm.

## License

Copyright [2023] [IAV GmbH]

Licensed under the Apache License, Version 2.0 (the "License");\
you may not use this file except in compliance with the License.\
You may obtain a copy of the License at\
\
&nbsp;&nbsp;&nbsp;[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)\
\
Unless required by applicable law or agreed to in writing, software\
distributed under the License is distributed on an "AS IS" BASIS,\
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\
See the License for the specific language governing permissions and\
limitations under the License.

## AUTOSAR

QuantumSAR should supporting the AUTOSAR Version [R22-11](https://www.autosar.org/fileadmin/standards/R22-11/CP/AUTOSAR_SWS_CryptoDriver.pdf). 

## Patent
The Encryption PQC algorithm CRYSTALS-KYBER is one of the candidate algorithms for public-key post-quantum standards. There are two patent portfolios listed in a patent license agreement published by NIST.  
https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/selected-algos-2022/nist-pqc-license-summary-and-excerpts.pdf
Please check the license condition before any commercial implementation. IAV isn’t owner, applicant, licensor or sub-licensor of the patent portfolios. It is any implementers sole responsibility to do the final license check for all implementations of CRYSTALS-KYBER. IAV is not responsible for possible infringements of third party rights.

## MISRA

QuantumSAR and the post-quantum cryptographic algorithms are checked with the 2012 version of [MISRA](https://misra.org.uk/app/uploads/2021/06/MISRA-C-2012-Permits-First-Edition.pdf).
