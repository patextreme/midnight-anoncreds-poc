# Midnight Anoncreds Integration

A proof-of-concept implementation that integrates Midnight blockchain as a Verifiable Data Registry (VDR) for anonymous credential flow, demonstrating Midnight's capabilities as a zero-knowledge proof revocation mechanism.

## Overview

This project explores the integration of Midnight blockchain with Hyperledger Anoncreds to provide a VDR layer for anoncreds credential management systems.

### Midnight as VDR Integration Options

There are multiple integration options to use Midnight network as a VDR layer in the anoncreds ecosystem.

1. **Midnight VDR Storage** - Direct storage of anoncreds objects (schemas, credential definitions, revocation registries) in the ledger state using smart contracts

2. **Midnight as VDR Storage Anchor** - Using Midnight as a data anchor for data stored elsewhere (e.g., IPFS), with ledger updates providing tamper-evidence while mitigating size constraints

3. **Midnight as ZKP Revocation Mechanism** - Leveraging Midnight's native ZKP capabilities to handle non-revocation proofs, offering an alternative to traditional accumulator-based revocation

This POC specifically focuses on **Option 3**, utilizing the built-in Merkle tree to generate inclusion proofs.

## Credential Flow

The revocation registry smart contract manages credential lifecycle through three main circuits, with ledger state tracking the issuer's public key and a Merkle tree of credential commitments.

### Ledger State

```compact
export ledger issuerPublicKey: Bytes<32>;
export ledger credentialCommitment: MerkleTree<4, Bytes<32>>;
```

### Issuance Flow

1. **Holder creates credential commitment** - Derived from a linked secret or other secret mechanism
2. **Holder provides commitment to issuer** - During the issuance process
3. **Issuer adds credential to registry** - Using the `addCredential` circuit:

```compact
export circuit addCredential(sk: Bytes<32>, idx: Uint<64>, commitment: Bytes<32>): [] {
    checkOwner(sk);
    credentialCommitment.insertIndex(disclose(commitment), disclose(idx));
}
```

The issuer authenticates using their secret key and inserts the commitment into the Merkle tree at the specified index.

### Presentation Flow

1. **Holder generates non-revocation proof** - Using the `proofNonRevoked` circuit with their commitment secret:

```compact
export circuit proofNonRevoked(path: MerkleTreePath<4, Bytes<32>>, commitmentSecret: Bytes<32>): Boolean {
    assert(path.leaf == persistentHash<Bytes<32>>(commitmentSecret), "you are not the holder!!!");
    return credentialCommitment.checkRoot(merkleTreePathRoot<4, Bytes<32>>(disclose(path)));
}
```

2. **Transaction created on blockchain** - The circuit execution generates a transaction proving the holder knows the secret and their credential is included in the Merkle tree
3. **Holder provides transaction transcript to verifier** - As proof of active credential status
4. **Verifier validates transaction** - Confirms successful execution on Midnight blockchain, proving the credential was active at transaction time

### Revocation Flow

The issuer can revoke credentials using the `revokeCredential` circuit:

```compact
export circuit revokeCredential(sk: Bytes<32>, idx: Uint<64>): [] {
    checkOwner(sk);
    const placeholder = pad(32, "");
    credentialCommitment.insertIndex(placeholder, disclose(idx));
}
```

This replaces the commitment at the specified index with an empty placeholder, effectively revoking the credential.

### Limitations and Drawbacks

1. **All proofs are transactions** - Every proof generation requires creating a blockchain transaction, which consumes space and incurs transaction fees, making the approach cost-ineffective for frequent verifications or Merkle tree updates.

2. **Holder computational requirements** - The computational burden on holders can be significant, often requiring the use of Midnight's proof-server infrastructure to handle the complex zero-knowledge proof generation.

3. **Wallet complexity** - Instead of a simple SSI wallet with basic signature capabilities, this approach requires a Midnight wallet with additional key management, increasing the complexity for end users.

4. **Deviation from Anoncreds specification** - This implementation uses a custom revocation mechanism that is not compatible with the standard Anoncreds specification, meaning other ecosystem participants cannot verify these proofs using existing tools.

### Open Exploration Areas

**Transaction Binding to Presentations**

How to properly bind the transaction to the presentation context. Potential approaches include:
- Holder proving ownership of the wallet making the transaction
- Including presentation-specific metadata in the transaction
- Using cryptographic mechanisms to link the proof to specific verification contexts

**Midnight as StatusList Storage**

A simple StatusList implementation might be more efficient and cost-effective with some privacy trade-offs.
The list can be encoded as sparse entries, making it space-efficient for ledger storage.
Midnight smart contract primitives should provide good support for this type of storage pattern.

**Using Merkle Trees for Non-Inclusion Proof**

Merkle trees are publicly readable, so with a carefully designed tree structure, verification might not require a transaction to prove an entry's inclusion in the tree.
This would allow verifiers to use the publicly available tree to perform checks without creating transactions.
