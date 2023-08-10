tpm-ssh-agent / tpm\_i2c
============================

## tpm-ssh-agent
A SSH agent implementation using TPM-stored RSA-2048 key

## tpm\_i2c
An implementation of TCTI / TPM API over I2C that used internally at tpm-ssh-agent

## References
* [OPTIGA™ TPM SLB 9673 TPM2.0 Data Sheet](https://www.infineon.com/dgdl/Infineon-OPTIGA+TPM+SLB+9673+FW26-DataSheet-v01_02-EN.pdf?fileId=8ac78c8c821f389001826301ac645a26)
* [Microchip MCP2221A Datasheet](https://ww1.microchip.com/downloads/aemDocuments/documents/APID/ProductDocuments/DataSheets/MCP2221A-Data-Sheet-20005565E.pdf)
* [TCG TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/) especially Part 2 and 3. 
* [TCG PC Client Platform TPM Profile (PTP) Specification](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
* [TCG TPM I2C Interface Specification](https://trustedcomputinggroup.org/resource/tcg-tpm-i2c-interface-specification/)
* [TCG PC Client Device Driver Design Principles for TPM 2.0](https://trustedcomputinggroup.org/resource/tcg-pc-client-device-driver-design-principles-for-tpm-2-0/)
* [NIST SP 800-108 rev. 1 Recommendation for Key Derivation Using Pseudorandom Functions](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf)
* [RFC4253: The Secure Shell (SSH) Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253)
* [RFC4432: RSA Key Exchange for the Secure Shell (SSH) Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4432)
* [RFC8332: Use of RSA Keys with SHA-256 and SHA-512 in the Secure Shell (SSH) Protocol](https://datatracker.ietf.org/doc/html/rfc8332)
* [draft-miller-ssh-agent-04: SSH Agent Protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04)
* [microsoft / TSS.MSR](https://github.com/microsoft/TSS.MSR)
* [infineon / optiga-tpm-cheatsheet](https://github.com/Infineon/optiga-tpm-cheatsheet)
* [google / go-tpm](https://github.com/google/go-tpm)
* [A driver for TPM 1.2 both of SLB9635 and SLB9645 in the Linux kernel](https://github.com/torvalds/linux/blob/master/drivers/char/tpm/tpm_i2c_infineon.c)
* Graeme Proudler, Liqun Chen, and Chris Dalton. 2014. [***Trusted Computing Platforms: TPM2.0 in Context***](https://link.springer.com/book/10.1007/978-3-319-08744-3). Springer. 
* Will Arthur, David Challener, and Kenneth Goldman. 2015. [***A Practical Guide to TPM 2.0: Using the Trusted Platform Module in the New Age of Security***](https://link.springer.com/book/10.1007/978-1-4302-6584-9). Apress Berkeley, CA. 
