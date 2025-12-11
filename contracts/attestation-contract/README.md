# SimplifiedAttestationCenter Smart Contract

## 📋 Overview

The **SimplifiedAttestationCenter** is a blockchain-based attestation system that allows authorized entities to create, manage, and verify digital attestations. 

## 🌐 Deployed Contract

**Network**: Monad Mainnet (Chain ID: 143)  
**Address**: ~~[`0x5a2fA76D1595B4D047c54e0DDdF36e5b2Dd3AACd`](https://monadvision.com/address/0x5a2fA76D1595B4D047c54e0DDdF36e5b2Dd3AACd)~~ *(deprecated — pending redeployment)*

## Audit
<a href="/contracts/attestation-contract/dFusion Monad Contracts - FailSafe Security Report - Final.pdf">FailSafe Report of findings + Confirmation of Remediations</a>

## ✨ Key Features

### 🔐 **Authorization System**
- Only pre-authorized attesters can create attestations
- Owner-controlled authorization management
- Batch authorization capabilities

### 📝 **Attestation Management**
- Create cryptographically signed attestations with expiry deadlines
- Revoke attestations when needed
- Prevent duplicate attestations
- Immutable attestation history

### 🔍 **Query & Verification**
- Retrieve attestations by ID, attester, or subject
- Verify attestation validity
- Check total attestation counts

### 🛡️ **Security Features**
- Cryptographic signature verification with deadline expiry
- Reentrancy protection
- Access control mechanisms (authorization required for both creation and revocation)
- Duplicate prevention
- Hash collision resistance via `abi.encode`
- Ownership renunciation disabled to prevent accidental lockout

## 🏗️ Contract Architecture

```
┌─────────────────────────────────────┐
│        Contract Owner               │
│  (Manages attester authorization)   │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│     Authorized Attesters            │
│   (Can create & revoke attestations)│
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│         Attestations                │
│  (Stored on-chain permanently)      │
└─────────────────────────────────────┘
```

## 📚 Core Data Structures

### Attestation Structure
```solidity
struct Attestation {
    uint256 attestationId;    // Unique identifier
    address attester;         // Who made the attestation
    bytes32 subject;          // What/who is being attested to
    bytes data;              // Additional attestation data
    uint256 timestamp;       // When it was created
    bool isValid;           // Whether it's currently valid
}
```

### Attestation Request Structure
```solidity
struct AttestationRequest {
    bytes32 subject;    // The subject being attested to
    bytes data;        // Additional attestation data
    bytes signature;   // Cryptographic signature
    uint256 deadline;  // Timestamp after which signature expires
}
```

## 🔧 Contract Functions

### 👑 Owner Functions

#### `setAttesterAuthorization(address attester, bool isAuthorized)`
**Purpose**: Authorize or deauthorize an attester
**Access**: Owner only
**Parameters**:
- `attester`: Address of the attester
- `isAuthorized`: True to authorize, false to deauthorize

**Example Usage**:
```javascript
// Authorize an attester
await contract.setAttesterAuthorization("0x1234...", true);

// Deauthorize an attester
await contract.setAttesterAuthorization("0x1234...", false);
```

#### `batchSetAttesterAuthorization(address[] attesters, bool isAuthorized)`
**Purpose**: Authorize or deauthorize multiple attesters at once
**Access**: Owner only
**Parameters**:
- `attesters`: Array of attester addresses
- `isAuthorized`: True to authorize all, false to deauthorize all

**Example Usage**:
```javascript
const attesters = ["0x1234...", "0x5678...", "0x9abc..."];
await contract.batchSetAttesterAuthorization(attesters, true);
```

#### `renounceOwnership()` *(Disabled)*
**Purpose**: Prevented to avoid accidental contract lockout
**Behavior**: Always reverts with "Ownership renunciation disabled"

### 🎭 Attester Functions

#### `createAttestation(AttestationRequest request)`
**Purpose**: Create a new attestation
**Access**: Authorized attesters only
**Returns**: `uint256 attestationId`

**Parameters**:
- `request.subject`: 32-byte identifier of what's being attested
- `request.data`: Additional data (flexible format)
- `request.signature`: Cryptographic signature
- `request.deadline`: Unix timestamp after which the signature is invalid

**Example Usage**:
```javascript
// Generate signature (off-chain)
const deadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

const messageHash = ethers.utils.keccak256(
  ethers.utils.defaultAbiCoder.encode(
    ["address", "bytes32", "bytes", "uint256", "uint256", "address"],
    [attesterAddress, subject, data, deadline, chainId, contractAddress]
  )
);
const signature = await signer.signMessage(ethers.utils.arrayify(messageHash));

// Create attestation
const request = {
  subject: ethers.utils.formatBytes32String("user123"),
  data: ethers.utils.toUtf8Bytes(JSON.stringify({
    type: "identity_verification",
    level: "kyc_passed",
    timestamp: Date.now()
  })),
  signature: signature,
  deadline: deadline
};

const attestationId = await contract.createAttestation(request);
```

#### `revokeAttestation(uint256 attestationId)`
**Purpose**: Revoke an existing attestation
**Access**: Original attester or contract owner (must be authorized)
**Parameters**:
- `attestationId`: ID of the attestation to revoke

**Example Usage**:
```javascript
await contract.revokeAttestation(1);
```

> ⚠️ **Note**: The caller must still be an authorized attester to revoke. Deauthorized attesters cannot revoke their previous attestations.

### 🔍 View Functions

#### `getAttestation(uint256 attestationId)`
**Purpose**: Retrieve a specific attestation
**Returns**: `Attestation struct`
**Access**: Public

**Example Usage**:
```javascript
const attestation = await contract.getAttestation(1);
console.log({
  id: attestation.attestationId,
  attester: attestation.attester,
  subject: attestation.subject,
  data: ethers.utils.toUtf8String(attestation.data),
  timestamp: new Date(attestation.timestamp * 1000),
  isValid: attestation.isValid
});
```

#### `getAttestationsByAttester(address attester)`
**Purpose**: Get all attestation IDs created by a specific attester
**Returns**: `uint256[]` array of attestation IDs
**Access**: Public

**Example Usage**:
```javascript
const attestationIds = await contract.getAttestationsByAttester("0x1234...");
```

#### `getAttestationsBySubject(bytes32 subject)`
**Purpose**: Get all attestation IDs for a specific subject
**Returns**: `uint256[]` array of attestation IDs
**Access**: Public

**Example Usage**:
```javascript
const subject = ethers.utils.formatBytes32String("user123");
const attestationIds = await contract.getAttestationsBySubject(subject);
```

#### `getTotalAttestations()`
**Purpose**: Get the total number of attestations created
**Returns**: `uint256` total count
**Access**: Public

#### `isValidAttestation(uint256 attestationId)`
**Purpose**: Check if an attestation exists and is valid
**Returns**: `bool` validity status
**Access**: Public

**Example Usage**:
```javascript
const isValid = await contract.isValidAttestation(1);
```

#### `authorizedAttesters(address attester)`
**Purpose**: Check if an address is an authorized attester
**Returns**: `bool` authorization status
**Access**: Public

## 📡 Events

### `AttestationCreated`
```solidity
event AttestationCreated(
    uint256 indexed attestationId,
    address indexed attester,
    bytes32 indexed subject,
    uint256 timestamp
);
```

### `AttestationRevoked`
```solidity
event AttestationRevoked(
    uint256 indexed attestationId,
    address indexed revoker
);
```

### `AttesterAuthorizationChanged`
```solidity
event AttesterAuthorizationChanged(
    address indexed attester,
    bool isAuthorized
);
```

## ⚠️ Error Handling

### Custom Errors

| Error | Description |
|-------|-------------|
| `UnauthorizedAttester()` | Caller is not an authorized attester |
| `InvalidSignature()` | Provided signature is invalid |
| `AttestationNotFound()` | Attestation with given ID doesn't exist |
| `AttestationAlreadyExists()` | Duplicate attestation detected |
| `AttestationAlreadyRevoked()` | Attempting to revoke already revoked attestation |
| `OnlyAttesterCanRevoke()` | Only original attester or owner can revoke |
| `SignatureExpired()` | The signature deadline has passed |

### Error Handling Example
```javascript
try {
  await contract.createAttestation(request);
} catch (error) {
  if (error.message.includes("UnauthorizedAttester")) {
    console.log("This address is not authorized to create attestations");
  } else if (error.message.includes("InvalidSignature")) {
    console.log("The signature provided is invalid");
  } else if (error.message.includes("AttestationAlreadyExists")) {
    console.log("This attestation already exists");
  } else if (error.message.includes("SignatureExpired")) {
    console.log("The signature has expired - generate a new one with a future deadline");
  }
}
```

## 🔗 Integration Guide

### Signature Generation

The signature must be computed over a hash that includes the deadline:

```javascript
function generateAttestationSignature(signer, subject, data, deadline, chainId, contractAddress) {
  // Use abi.encode (NOT solidityKeccak256/encodePacked) to match contract
  const messageHash = ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["address", "bytes32", "bytes", "uint256", "uint256", "address"],
      [await signer.getAddress(), subject, data, deadline, chainId, contractAddress]
    )
  );
  
  // Sign as Ethereum signed message
  return await signer.signMessage(ethers.utils.arrayify(messageHash));
}
```

### Backend Integration Example

```javascript
// 1. Contract setup
const contract = new ethers.Contract(
  contractAddress,
  contractABI,
  signer
);

// 2. Authorization check
async function isAuthorizedAttester(address) {
  return await contract.authorizedAttesters(address);
}

// 3. Create attestation function
async function createIdentityAttestation(userAddress, verificationData) {
  const subject = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userAddress));
  const data = ethers.utils.toUtf8Bytes(JSON.stringify(verificationData));
  const deadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour validity
  
  // Generate signature using abi.encode
  const messageHash = ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["address", "bytes32", "bytes", "uint256", "uint256", "address"],
      [await signer.getAddress(), subject, data, deadline, network.chainId, contract.address]
    )
  );
  const signature = await signer.signMessage(ethers.utils.arrayify(messageHash));
  
  const request = { subject, data, signature, deadline };
  
  try {
    const tx = await contract.createAttestation(request);
    const receipt = await tx.wait();
    
    // Extract attestation ID from events
    const event = receipt.events.find(e => e.event === 'AttestationCreated');
    return event.args.attestationId;
  } catch (error) {
    throw new Error(`Failed to create attestation: ${error.message}`);
  }
}

// 4. Verify attestation function
async function verifyUserAttestation(userAddress) {
  const subject = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userAddress));
  const attestationIds = await contract.getAttestationsBySubject(subject);
  
  const validAttestations = [];
  for (const id of attestationIds) {
    if (await contract.isValidAttestation(id)) {
      const attestation = await contract.getAttestation(id);
      validAttestations.push(attestation);
    }
  }
  
  return validAttestations;
}
```

### Frontend Integration Example

```javascript
// React component example
import { useState, useEffect } from 'react';

function AttestationViewer({ userAddress, contract }) {
  const [attestations, setAttestations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadAttestations() {
      try {
        const subject = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userAddress));
        const ids = await contract.getAttestationsBySubject(subject);
        
        const attestationPromises = ids.map(async (id) => {
          const isValid = await contract.isValidAttestation(id);
          if (isValid) {
            return await contract.getAttestation(id);
          }
          return null;
        });
        
        const results = await Promise.all(attestationPromises);
        setAttestations(results.filter(Boolean));
      } catch (error) {
        console.error('Failed to load attestations:', error);
      } finally {
        setLoading(false);
      }
    }

    loadAttestations();
  }, [userAddress, contract]);

  if (loading) return <div>Loading attestations...</div>;

  return (
    <div>
      <h3>Attestations for {userAddress}</h3>
      {attestations.length === 0 ? (
        <p>No valid attestations found</p>
      ) : (
        attestations.map((attestation) => (
          <div key={attestation.attestationId} className="attestation-card">
            <p><strong>ID:</strong> {attestation.attestationId.toString()}</p>
            <p><strong>Attester:</strong> {attestation.attester}</p>
            <p><strong>Date:</strong> {new Date(attestation.timestamp * 1000).toLocaleDateString()}</p>
            <p><strong>Data:</strong> {ethers.utils.toUtf8String(attestation.data)}</p>
          </div>
        ))
      )}
    </div>
  );
}
```

## 🚀 Deployment Guide

### Prerequisites
- Solidity ^0.8.19
- OpenZeppelin Contracts
- Foundry for testing

### Deployment Script Example
```javascript
async function deploy() {
  const [deployer] = await ethers.getSigners();
  
  console.log("Deploying with account:", deployer.address);
  console.log("Account balance:", (await deployer.getBalance()).toString());

  const SimplifiedAttestationCenter = await ethers.getContractFactory("SimplifiedAttestationCenter");
  const contract = await SimplifiedAttestationCenter.deploy(deployer.address);

  await contract.deployed();

  console.log("SimplifiedAttestationCenter deployed to:", contract.address);
  
  // Authorize initial attesters
  const initialAttesters = ["0x1234...", "0x5678..."];
  for (const attester of initialAttesters) {
    await contract.setAttesterAuthorization(attester, true);
    console.log(`Authorized attester: ${attester}`);
  }
}
```

## 🛡️ Security Considerations

### 1. **Access Control**
- Only authorized attesters can create attestations
- Only authorized attesters can revoke their own attestations
- Only the contract owner can manage attester permissions
- Deauthorized attesters lose all privileges immediately

### 2. **Signature Verification**
- All attestations must be cryptographically signed
- Signatures are verified against the expected attester
- Message hash includes contract address and chain ID to prevent cross-chain replay
- **Signatures have a deadline** — expired signatures are rejected

### 3. **Reentrancy Protection**
- All state-changing functions are protected against reentrancy attacks
- Uses OpenZeppelin's ReentrancyGuard

### 4. **Duplicate Prevention**
- Identical attestations (same attester, subject, data, deadline) cannot be created twice
- Hash-based duplicate detection
- To re-attest after revocation, use a different deadline

### 5. **Hash Collision Resistance**
- Uses `abi.encode` instead of `abi.encodePacked` to prevent hash collisions with dynamic data

### 6. **Ownership Protection**
- `renounceOwnership()` is disabled to prevent accidental contract lockout

## 📊 Gas Optimization

### Function Gas Costs (Approximate)
| Function | Gas Cost |
|----------|----------|
| `createAttestation` | ~280,000 |
| `revokeAttestation` | ~32,000 |
| `setAttesterAuthorization` | ~47,000 |
| View functions | ~2,000-5,000 |

### Optimization Tips
- Batch operations when possible using `batchSetAttesterAuthorization`
- Use view functions for data retrieval to avoid gas costs
- Consider off-chain signature generation and verification
- Set reasonable deadlines (e.g., 1 hour) to allow re-attestation without excessive delay

## 🧪 Testing

The contract includes comprehensive tests covering:
- ✅ All function scenarios
- ✅ Error conditions
- ✅ Security vulnerabilities (audit findings addressed)
- ✅ Edge cases
- ✅ Signature expiry
- ✅ Deauthorized attester restrictions

Run tests with:
```bash
forge test -vv
```

## 🔄 Workflow Examples

### Complete Attestation Lifecycle

```javascript
// 1. Owner authorizes attester
await contract.setAttesterAuthorization(attesterAddress, true);

// 2. Attester creates attestation (with 1 hour deadline)
const deadline = Math.floor(Date.now() / 1000) + 3600;
const attestationId = await createAttestation(subject, data, signature, deadline);

// 3. Anyone can verify the attestation
const isValid = await contract.isValidAttestation(attestationId);

// 4. Retrieve full attestation details
const attestation = await contract.getAttestation(attestationId);

// 5. Optionally revoke if needed (attester must still be authorized)
await contract.revokeAttestation(attestationId);

// 6. Re-attest with new deadline if needed
const newDeadline = Math.floor(Date.now() / 1000) + 3600;
const newAttestationId = await createAttestation(subject, data, newSignature, newDeadline);
```

## 📝 Changelog

### v2.0.0 (Pending Deployment)
**Security Fixes:**
- Added `deadline` field to `AttestationRequest` to prevent indefinite signature replay
- Added `onlyAuthorizedAttester` modifier to `revokeAttestation()` — deauthorized attesters can no longer revoke
- Changed `abi.encodePacked` to `abi.encode` in hash computation to prevent collision attacks
- Disabled `renounceOwnership()` to prevent accidental contract lockout

**Breaking Changes:**
- `AttestationRequest` struct now requires a `deadline` field
- Signatures must include the deadline in the hash computation
- Revocation now requires the caller to be an authorized attester

## 🤝 Support & Integration

For integration support or questions:
1. Review this documentation thoroughly
2. Check the comprehensive test suite for usage examples
3. Refer to the contract source code for implementation details

## 📄 License

This project is licensed under the MIT License.
