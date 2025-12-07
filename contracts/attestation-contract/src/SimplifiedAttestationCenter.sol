// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title SimplifiedAttestationCenter
 * @dev A simplified version of the AttestationCenter contract focusing on basic attestation functionality
 * @notice This contract allows creating, storing, and retrieving attestations without complex reward systems
 */
contract SimplifiedAttestationCenter is Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

    // ============ STRUCTURES ============

    /**
     * @dev Basic attestation information structure
     * @param attestationId Unique identifier for the attestation
     * @param attester Address of the entity making the attestation
     * @param subject Address or identifier being attested to
     * @param data Additional data for the attestation
     * @param timestamp When the attestation was created
     * @param isValid Whether the attestation is currently valid
     */
    struct Attestation {
        uint256 attestationId;
        address attester;
        bytes32 subject;
        bytes data;
        uint256 timestamp;
        bool isValid;
    }

    /**
     * @dev Attestation request structure for submission
     * @param subject The subject being attested to
     * @param data Additional attestation data
     * @param signature Signature from the attester
     * @param deadline Timestamp after which the signature is no longer valid
     */
    struct AttestationRequest {
        bytes32 subject;
        bytes data;
        bytes signature;
        uint256 deadline;
    }

    // ============ STATE VARIABLES ============

    /// @dev Counter for generating unique attestation IDs
    uint256 private _attestationCounter;

    /// @dev Mapping from attestation ID to attestation data
    mapping(uint256 => Attestation) public attestations;

    /// @dev Mapping from attester to list of their attestation IDs
    mapping(address => uint256[]) public attesterToAttestations;

    /// @dev Mapping from subject to list of attestation IDs about them
    mapping(bytes32 => uint256[]) public subjectToAttestations;

    /// @dev Mapping to check if an attestation hash already exists (prevent duplicates)
    mapping(bytes32 => bool) public attestationExists;

    /// @dev Mapping of authorized attesters
    mapping(address => bool) public authorizedAttesters;

    // ============ EVENTS ============

    /**
     * @dev Emitted when a new attestation is created
     * @param attestationId The unique ID of the attestation
     * @param attester Address of the attester
     * @param subject Subject being attested to
     * @param timestamp When the attestation was created
     */
    event AttestationCreated(
        uint256 indexed attestationId,
        address indexed attester,
        bytes32 indexed subject,
        uint256 timestamp
    );

    /**
     * @dev Emitted when an attestation is revoked
     * @param attestationId The ID of the revoked attestation
     * @param revoker Address that revoked the attestation
     */
    event AttestationRevoked(
        uint256 indexed attestationId,
        address indexed revoker
    );

    /**
     * @dev Emitted when an attester is authorized or deauthorized
     * @param attester Address of the attester
     * @param isAuthorized Whether they are now authorized
     */
    event AttesterAuthorizationChanged(
        address indexed attester,
        bool isAuthorized
    );

    // ============ ERRORS ============

    error UnauthorizedAttester();
    error InvalidSignature();
    error AttestationNotFound();
    error AttestationAlreadyExists();
    error AttestationAlreadyRevoked();
    error OnlyAttesterCanRevoke();
    error SignatureExpired();

    // ============ CONSTRUCTOR ============

    /**
     * @dev Constructor sets the contract owner
     * @param _owner Address of the contract owner
     */
    constructor(address _owner) Ownable(_owner) {
        _attestationCounter = 1; // Start from 1 to avoid confusion with default values
    }

    // ============ MODIFIERS ============

    /**
     * @dev Modifier to check if the caller is an authorized attester
     */
    modifier onlyAuthorizedAttester() {
        if (!authorizedAttesters[msg.sender]) {
            revert UnauthorizedAttester();
        }
        _;
    }

    // ============ MAIN FUNCTIONS ============

    /**
     * @dev Creates a new attestation
     * @param request The attestation request containing subject, data, signature, and deadline
     * @return attestationId The ID of the newly created attestation
     */
    function createAttestation(AttestationRequest calldata request) 
        external 
        onlyAuthorizedAttester 
        nonReentrant 
        returns (uint256 attestationId) 
    {
        // Check signature expiry
        if (block.timestamp > request.deadline) {
            revert SignatureExpired();
        }

        // Verify signature (now includes deadline)
        bytes32 messageHash = _getAttestationHash(msg.sender, request.subject, request.data, request.deadline);
        if (!_verifySignature(messageHash, request.signature, msg.sender)) {
            revert InvalidSignature();
        }

        // Check for duplicate attestation
        if (attestationExists[messageHash]) {
            revert AttestationAlreadyExists();
        }

        // Create new attestation
        attestationId = _attestationCounter++;
        
        Attestation memory newAttestation = Attestation({
            attestationId: attestationId,
            attester: msg.sender,
            subject: request.subject,
            data: request.data,
            timestamp: block.timestamp,
            isValid: true
        });

        // Store attestation
        attestations[attestationId] = newAttestation;
        attesterToAttestations[msg.sender].push(attestationId);
        subjectToAttestations[request.subject].push(attestationId);
        attestationExists[messageHash] = true;

        emit AttestationCreated(attestationId, msg.sender, request.subject, block.timestamp);
    }

    /**
     * @dev Revokes an existing attestation
     * @param attestationId The ID of the attestation to revoke
     */
    function revokeAttestation(uint256 attestationId) external onlyAuthorizedAttester nonReentrant {
        Attestation storage attestation = attestations[attestationId];
        
        if (attestation.attestationId == 0) {
            revert AttestationNotFound();
        }
        
        if (!attestation.isValid) {
            revert AttestationAlreadyRevoked();
        }
        
        // Only the original attester or owner can revoke
        if (msg.sender != attestation.attester && msg.sender != owner()) {
            revert OnlyAttesterCanRevoke();
        }

        attestation.isValid = false;
        emit AttestationRevoked(attestationId, msg.sender);
    }

    // ============ VIEW FUNCTIONS ============

    /**
     * @dev Retrieves an attestation by ID
     * @param attestationId The ID of the attestation
     * @return The attestation data
     */
    function getAttestation(uint256 attestationId) external view returns (Attestation memory) {
        Attestation memory attestation = attestations[attestationId];
        if (attestation.attestationId == 0) {
            revert AttestationNotFound();
        }
        return attestation;
    }

    /**
     * @dev Gets all attestation IDs created by a specific attester
     * @param attester The address of the attester
     * @return Array of attestation IDs
     */
    function getAttestationsByAttester(address attester) external view returns (uint256[] memory) {
        return attesterToAttestations[attester];
    }

    /**
     * @dev Gets all attestation IDs for a specific subject
     * @param subject The subject identifier
     * @return Array of attestation IDs
     */
    function getAttestationsBySubject(bytes32 subject) external view returns (uint256[] memory) {
        return subjectToAttestations[subject];
    }

    /**
     * @dev Gets the total number of attestations created
     * @return The current attestation counter minus 1
     */
    function getTotalAttestations() external view returns (uint256) {
        return _attestationCounter - 1;
    }

    /**
     * @dev Checks if a specific attestation exists and is valid
     * @param attestationId The ID of the attestation
     * @return Whether the attestation exists and is valid
     */
    function isValidAttestation(uint256 attestationId) external view returns (bool) {
        Attestation memory attestation = attestations[attestationId];
        return attestation.attestationId != 0 && attestation.isValid;
    }

    // ============ ADMIN FUNCTIONS ============

    /**
     * @dev Authorizes or deauthorizes an attester
     * @param attester The address of the attester
     * @param isAuthorized Whether to authorize or deauthorize
     */
    function setAttesterAuthorization(address attester, bool isAuthorized) external onlyOwner {
        authorizedAttesters[attester] = isAuthorized;
        emit AttesterAuthorizationChanged(attester, isAuthorized);
    }

    /**
     * @dev Batch authorize multiple attesters
     * @param attesters Array of attester addresses
     * @param isAuthorized Whether to authorize or deauthorize all
     */
    function batchSetAttesterAuthorization(address[] calldata attesters, bool isAuthorized) external onlyOwner {
        for (uint256 i = 0; i < attesters.length; i++) {
            authorizedAttesters[attesters[i]] = isAuthorized;
            emit AttesterAuthorizationChanged(attesters[i], isAuthorized);
        }
    }

    /**
     * @dev Override renounceOwnership to prevent accidental ownership loss
     * @notice This function is disabled to prevent bricking the contract
     */
    function renounceOwnership() public view override onlyOwner {
        revert("Ownership renunciation disabled");
    }

    // ============ INTERNAL FUNCTIONS ============

    /**
     * @dev Generates a hash for an attestation using abi.encode to prevent collisions
     * @param attester The address of the attester
     * @param subject The subject being attested to
     * @param data The attestation data
     * @param deadline The signature expiry timestamp
     * @return The computed hash
     */
    function _getAttestationHash(
        address attester,
        bytes32 subject,
        bytes memory data,
        uint256 deadline
    ) internal view returns (bytes32) {
        return keccak256(abi.encode(attester, subject, data, deadline, block.chainid, address(this)));
    }

    /**
     * @dev Verifies an ECDSA signature
     * @param messageHash The hash of the message that was signed
     * @param signature The signature to verify
     * @param expectedSigner The expected signer address
     * @return Whether the signature is valid
     */
    function _verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        address recoveredSigner = ethSignedMessageHash.recover(signature);
        return recoveredSigner == expectedSigner;
    }
}