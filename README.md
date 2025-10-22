# Midnight Anoncreds Integration

A proof-of-concept implementation that integrates Midnight blockchain as a Verifiable Data Registry (VDR) for anonymous credential flow, demonstrating Midnight's capabilities as a zero-knowledge proof revocation mechanism.

## Overview

This project explores the integration of Midnight blockchain with Hyperledger Anoncreds to provide a VDR layer for anoncreds credential-management system.

### Midnight as VDR Integration Options

There are multiple integration options to use Midnight network as a VDR layer in anoncreds ecosystem.

1. **Midnight VDR Storage** - Direct storage of anoncreds objects (schemas, credential definitions, revocation registries) in the ledger state using smart contracts

2. **Midnight as VDR Storage Anchor** - Using Midnight as a data anchor for data stored elsewhere (e.g., IPFS), with ledger updates providing tamper-evidence while mitigating size constraints

3. **Midnight as ZKP Revocation Mechanism** - Leveraging Midnight's native ZKP capabilities to handle non-revocation proofs, offering an alternative to traditional accumulator-based revocation

This POC specifically focuses on **Option 3**, utilizing the built-in Merkle tree to generate inclusion proofs
