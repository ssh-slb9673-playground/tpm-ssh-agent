tpm-ssh-agent / tpm\_i2c / more
=================================

## tpm-ssh-agent
A SSH agent implementation using TPM-stored ~~RSA-2048 key~~ secp256r1 ECDSA key

## tpm-attestation
An implementation of 1-RTT Remote Attestation Protocol

## tpm\_i2c
An implementation of TCTI / TPM API over I2C that used internally at above projects

## schematics
These projects are designed to run specifically on my self-developed USB-TPM dongle. It's possible to modify them to be compatible with fTPM, sTPM, vTPM, and more, but it will require creating a TCTI module for that purpose.

You can find the schematics for the dongle here: [/usb_tpm_dongle_schematic.pdf](/usb_tpm_dongle_schematic.pdf).

## References
* [OPTIGA™ TPM SLB 9673 TPM2.0 Data Sheet](https://www.infineon.com/dgdl/Infineon-OPTIGA+TPM+SLB+9673+FW26-DataSheet-v01_02-EN.pdf?fileId=8ac78c8c821f389001826301ac645a26)
* [Microchip MCP2221A Datasheet](https://ww1.microchip.com/downloads/aemDocuments/documents/APID/ProductDocuments/DataSheets/MCP2221A-Data-Sheet-20005565E.pdf)
* [TCG TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
* [TCG PC Client Platform TPM Profile (PTP) Specification](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
* [TCG TPM I2C Interface Specification](https://trustedcomputinggroup.org/resource/tcg-tpm-i2c-interface-specification/)
* [TCG PC Client Device Driver Design Principles for TPM 2.0](https://trustedcomputinggroup.org/resource/tcg-pc-client-device-driver-design-principles-for-tpm-2-0/)
* [TCG Registry of Reserved TPM 2.0 Handles and Localities](https://trustedcomputinggroup.org/resource/registry/)
* [TCG EK Credential Profile for TPM Family 2.0](https://trustedcomputinggroup.org/resource/http-trustedcomputinggroup-org-wp-content-uploads-tcg-ek-credential-profile-v-2-5-r2_published-pdf/)
* [NIST SP 800-108 rev. 1 Recommendation for Key Derivation Using Pseudorandom Functions](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf)
* [RFC4251: The Secure Shell (SSH) Protocol Architecture](https://datatracker.ietf.org/doc/html/rfc4251)
* [RFC4253: The Secure Shell (SSH) Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253)
* [RFC4432: RSA Key Exchange for the Secure Shell (SSH) Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4432)
* [RFC5656: Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer](https://www.rfc-editor.org/rfc/rfc5656)
* [RFC8332: Use of RSA Keys with SHA-256 and SHA-512 in the Secure Shell (SSH) Protocol](https://datatracker.ietf.org/doc/html/rfc8332)
* [draft-miller-ssh-agent-04: SSH Agent Protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04)
* [Elliptic Curve Cryptography (Standards for Efficient Cryptography Group)](https://www.secg.org/sec1-v2.pdf)
* [microsoft / TSS.MSR](https://github.com/microsoft/TSS.MSR)
* [infineon / optiga-tpm-cheatsheet](https://github.com/Infineon/optiga-tpm-cheatsheet)
* [google / go-tpm](https://github.com/google/go-tpm)
* [A driver for TPM 1.2 both of SLB9635 and SLB9645 in the Linux kernel](https://github.com/torvalds/linux/blob/master/drivers/char/tpm/tpm_i2c_infineon.c)
* [The Trusted Platform Module Key Hierarchy](https://ericchiang.github.io/post/tpm-keys/)
* [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
* [Overview of the TPM Key Management Standard](https://trustedcomputinggroup.org/wp-content/uploads/Kazmierczak20Greg20-20TPM_Key_Management_KMS2008_v003.pdf)
* Graeme Proudler, Liqun Chen, and Chris Dalton. 2014. [***Trusted Computing Platforms: TPM2.0 in Context***](https://link.springer.com/book/10.1007/978-3-319-08744-3). Springer. 
* Will Arthur, David Challener, and Kenneth Goldman. 2015. [***A Practical Guide to TPM 2.0: Using the Trusted Platform Module in the New Age of Security***](https://link.springer.com/book/10.1007/978-1-4302-6584-9). Apress Berkeley, CA. 
