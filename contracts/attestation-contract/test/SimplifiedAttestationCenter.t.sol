// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/SimplifiedAttestationCenter.sol";

contract SimplifiedAttestationCenterTest is Test {
    SimplifiedAttestationCenter public attestationCenter;
    
    // Test accounts
    address public owner = address(0x1);
    address public attester1 = address(0x2);
    address public attester2 = address(0x3);
    address public unauthorized = address(0x4);
    
    // Test data
    bytes32 public subject1 = keccak256("subject1");
    bytes32 public subject2 = keccak256("subject2");
    bytes public data1 = "attestation data 1";
    bytes public data2 = "attestation data 2";
    
    // Test signatures (will be generated in setup)
    bytes public validSignature1;
    bytes public validSignature2;
    uint256 public attester1PrivateKey = 0xA11CE;
    uint256 public attester2PrivateKey = 0xB0B;
    
    // Default deadline (1 hour from now)
    uint256 public defaultDeadline;
    
    // Events for testing
    event AttestationCreated(
        uint256 indexed attestationId,
        address indexed attester,
        bytes32 indexed subject,
        uint256 timestamp
    );
    
    event AttestationRevoked(
        uint256 indexed attestationId,
        address indexed revoker
    );
    
    event AttesterAuthorizationChanged(
        address indexed attester,
        bool isAuthorized
    );

    function setUp() public {
        // Set a known block timestamp for consistent testing
        vm.warp(1000000);
        
        // Set default deadline to 1 hour from now
        defaultDeadline = block.timestamp + 1 hours;
        
        // Deploy contract
        vm.prank(owner);
        attestationCenter = new SimplifiedAttestationCenter(owner);
        
        // Setup test accounts with known private keys
        attester1 = vm.addr(attester1PrivateKey);
        attester2 = vm.addr(attester2PrivateKey);
        
        // Authorize attesters
        vm.startPrank(owner);
        attestationCenter.setAttesterAuthorization(attester1, true);
        attestationCenter.setAttesterAuthorization(attester2, true);
        vm.stopPrank();
        
        // Generate valid signatures with deadline
        validSignature1 = _generateSignature(attester1PrivateKey, attester1, subject1, data1, defaultDeadline);
        validSignature2 = _generateSignature(attester2PrivateKey, attester2, subject2, data2, defaultDeadline);
    }

    // ============ CONSTRUCTOR TESTS ============
    
    function test_Constructor() public {
        SimplifiedAttestationCenter newCenter = new SimplifiedAttestationCenter(owner);
        assertEq(newCenter.owner(), owner);
        assertEq(newCenter.getTotalAttestations(), 0);
    }

    function test_Constructor_WithDifferentOwner() public {
        address newOwner = address(0x999);
        SimplifiedAttestationCenter newCenter = new SimplifiedAttestationCenter(newOwner);
        assertEq(newCenter.owner(), newOwner);
    }

    // ============ AUTHORIZATION TESTS ============
    
    function test_SetAttesterAuthorization_Success() public {
        address newAttester = address(0x123);
        
        vm.expectEmit(true, false, false, true);
        emit AttesterAuthorizationChanged(newAttester, true);
        
        vm.prank(owner);
        attestationCenter.setAttesterAuthorization(newAttester, true);
        
        assertTrue(attestationCenter.authorizedAttesters(newAttester));
    }
    
    function test_SetAttesterAuthorization_Deauthorize() public {
        vm.expectEmit(true, false, false, true);
        emit AttesterAuthorizationChanged(attester1, false);
        
        vm.prank(owner);
        attestationCenter.setAttesterAuthorization(attester1, false);
        
        assertFalse(attestationCenter.authorizedAttesters(attester1));
    }
    
    function test_SetAttesterAuthorization_OnlyOwner() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        attestationCenter.setAttesterAuthorization(attester1, false);
    }
    
    function test_BatchSetAttesterAuthorization_Success() public {
        address[] memory attesters = new address[](3);
        attesters[0] = address(0x100);
        attesters[1] = address(0x200);
        attesters[2] = address(0x300);
        
        // Expect events for each attester
        for (uint i = 0; i < attesters.length; i++) {
            vm.expectEmit(true, false, false, true);
            emit AttesterAuthorizationChanged(attesters[i], true);
        }
        
        vm.prank(owner);
        attestationCenter.batchSetAttesterAuthorization(attesters, true);
        
        for (uint i = 0; i < attesters.length; i++) {
            assertTrue(attestationCenter.authorizedAttesters(attesters[i]));
        }
    }
    
    function test_BatchSetAttesterAuthorization_OnlyOwner() public {
        address[] memory attesters = new address[](1);
        attesters[0] = address(0x100);
        
        vm.prank(unauthorized);
        vm.expectRevert();
        attestationCenter.batchSetAttesterAuthorization(attesters, true);
    }

    // ============ CREATE ATTESTATION TESTS ============
    
    function test_CreateAttestation_Success() public {
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.expectEmit(true, true, true, false);
        emit AttestationCreated(1, attester1, subject1, block.timestamp);
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        assertEq(attestationId, 1);
        assertEq(attestationCenter.getTotalAttestations(), 1);
        
        // Verify attestation details
        SimplifiedAttestationCenter.Attestation memory attestation = attestationCenter.getAttestation(1);
        assertEq(attestation.attestationId, 1);
        assertEq(attestation.attester, attester1);
        assertEq(attestation.subject, subject1);
        assertEq(attestation.data, data1);
        assertEq(attestation.timestamp, block.timestamp);
        assertTrue(attestation.isValid);
    }
    
    function test_CreateAttestation_MultipleAttestations() public {
        // First attestation
        SimplifiedAttestationCenter.AttestationRequest memory request1 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 id1 = attestationCenter.createAttestation(request1);
        
        // Second attestation
        SimplifiedAttestationCenter.AttestationRequest memory request2 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject2,
            data: data2,
            signature: validSignature2,
            deadline: defaultDeadline
        });
        
        vm.prank(attester2);
        uint256 id2 = attestationCenter.createAttestation(request2);
        
        assertEq(id1, 1);
        assertEq(id2, 2);
        assertEq(attestationCenter.getTotalAttestations(), 2);
    }
    
    function test_CreateAttestation_UnauthorizedAttester() public {
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(unauthorized);
        vm.expectRevert(SimplifiedAttestationCenter.UnauthorizedAttester.selector);
        attestationCenter.createAttestation(request);
    }
    
    function test_CreateAttestation_InvalidSignature() public {
        // Create a signature with wrong length (should be 65 bytes)
        bytes memory invalidSignature = new bytes(65);
        // Fill with invalid data
        for (uint i = 0; i < 65; i++) {
            invalidSignature[i] = bytes1(uint8(i % 256));
        }
        
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: invalidSignature,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        // The ECDSA library will throw its own error for invalid signatures
        vm.expectRevert();
        attestationCenter.createAttestation(request);
    }
    
    function test_CreateAttestation_WrongSigner() public {
        // Generate signature with wrong private key
        bytes memory wrongSignature = _generateSignature(attester2PrivateKey, attester1, subject1, data1, defaultDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: wrongSignature,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        vm.expectRevert(SimplifiedAttestationCenter.InvalidSignature.selector);
        attestationCenter.createAttestation(request);
    }
    
    function test_CreateAttestation_CustomInvalidSignatureError() public {
        // Create a valid signature for a different message to test our custom error
        bytes memory differentData = "different data";
        bytes memory wrongMessageSignature = _generateSignature(attester1PrivateKey, attester1, subject1, differentData, defaultDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1, // Using different data than what was signed
            signature: wrongMessageSignature,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        vm.expectRevert(SimplifiedAttestationCenter.InvalidSignature.selector);
        attestationCenter.createAttestation(request);
    }
    
    function test_CreateAttestation_DuplicateAttestation() public {
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        // Create first attestation
        vm.prank(attester1);
        attestationCenter.createAttestation(request);
        
        // Try to create duplicate
        vm.prank(attester1);
        vm.expectRevert(SimplifiedAttestationCenter.AttestationAlreadyExists.selector);
        attestationCenter.createAttestation(request);
    }
    
    function test_CreateAttestation_ExpiredSignature() public {
        uint256 expiredDeadline = block.timestamp - 1; // Already expired
        bytes memory expiredSignature = _generateSignature(attester1PrivateKey, attester1, subject1, data1, expiredDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: expiredSignature,
            deadline: expiredDeadline
        });
        
        vm.prank(attester1);
        vm.expectRevert(SimplifiedAttestationCenter.SignatureExpired.selector);
        attestationCenter.createAttestation(request);
    }
    
    function test_CreateAttestation_SignatureExpiresAfterSubmission() public {
        // Create attestation just before deadline
        uint256 tightDeadline = block.timestamp + 10;
        bytes memory tightSignature = _generateSignature(attester1PrivateKey, attester1, subject1, data1, tightDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: tightSignature,
            deadline: tightDeadline
        });
        
        // Should work now
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        assertEq(attestationId, 1);
    }
    
    function test_CreateAttestation_DifferentDeadlineAllowsReAttestation() public {
        // This tests the fix for Finding #2 - different deadlines create different hashes
        SimplifiedAttestationCenter.AttestationRequest memory request1 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        attestationCenter.createAttestation(request1);
        
        // Revoke the attestation
        vm.prank(attester1);
        attestationCenter.revokeAttestation(1);
        
        // Now create a new attestation with same subject/data but different deadline
        uint256 newDeadline = defaultDeadline + 1 hours;
        bytes memory newSignature = _generateSignature(attester1PrivateKey, attester1, subject1, data1, newDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request2 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: newSignature,
            deadline: newDeadline
        });
        
        // This should succeed because the deadline is different
        vm.prank(attester1);
        uint256 newAttestationId = attestationCenter.createAttestation(request2);
        assertEq(newAttestationId, 2);
    }

    // ============ REVOKE ATTESTATION TESTS ============
    
    function test_RevokeAttestation_ByAttester() public {
        // Create attestation first
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        // Revoke by attester
        vm.expectEmit(true, true, false, false);
        emit AttestationRevoked(attestationId, attester1);
        
        vm.prank(attester1);
        attestationCenter.revokeAttestation(attestationId);
        
        // Verify revocation
        SimplifiedAttestationCenter.Attestation memory attestation = attestationCenter.getAttestation(attestationId);
        assertFalse(attestation.isValid);
        assertFalse(attestationCenter.isValidAttestation(attestationId));
    }
    
    function test_RevokeAttestation_ByOwner() public {
        // Create attestation first
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        // Owner needs to be authorized to revoke (per the new fix)
        vm.prank(owner);
        attestationCenter.setAttesterAuthorization(owner, true);
        
        // Revoke by owner
        vm.expectEmit(true, true, false, false);
        emit AttestationRevoked(attestationId, owner);
        
        vm.prank(owner);
        attestationCenter.revokeAttestation(attestationId);
        
        // Verify revocation
        SimplifiedAttestationCenter.Attestation memory attestation = attestationCenter.getAttestation(attestationId);
        assertFalse(attestation.isValid);
    }
    
    function test_RevokeAttestation_NonExistentAttestation() public {
        vm.prank(attester1);
        vm.expectRevert(SimplifiedAttestationCenter.AttestationNotFound.selector);
        attestationCenter.revokeAttestation(999);
    }
    
    function test_RevokeAttestation_AlreadyRevoked() public {
        // Create and revoke attestation
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        vm.prank(attester1);
        attestationCenter.revokeAttestation(attestationId);
        
        // Try to revoke again
        vm.prank(attester1);
        vm.expectRevert(SimplifiedAttestationCenter.AttestationAlreadyRevoked.selector);
        attestationCenter.revokeAttestation(attestationId);
    }
    
    function test_RevokeAttestation_UnauthorizedRevoker() public {
        // Create attestation
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        // Try to revoke with unauthorized account (not even authorized as attester)
        vm.prank(unauthorized);
        vm.expectRevert(SimplifiedAttestationCenter.UnauthorizedAttester.selector);
        attestationCenter.revokeAttestation(attestationId);
    }
    
    function test_RevokeAttestation_DifferentAttesterCannotRevoke() public {
        // Create attestation with attester1
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        // Try to revoke with attester2 (authorized but not the original attester)
        vm.prank(attester2);
        vm.expectRevert(SimplifiedAttestationCenter.OnlyAttesterCanRevoke.selector);
        attestationCenter.revokeAttestation(attestationId);
    }
    
    function test_RevokeAttestation_DeauthorizedAttesterCannotRevoke() public {
        // This tests Finding #1 - deauthorized attesters should not be able to revoke
        
        // Create attestation with attester1
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        // Deauthorize attester1
        vm.prank(owner);
        attestationCenter.setAttesterAuthorization(attester1, false);
        
        // Try to revoke - should fail now
        vm.prank(attester1);
        vm.expectRevert(SimplifiedAttestationCenter.UnauthorizedAttester.selector);
        attestationCenter.revokeAttestation(attestationId);
    }

    // ============ VIEW FUNCTION TESTS ============
    
    function test_GetAttestation_Success() public {
        // Create attestation
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        // Get attestation
        SimplifiedAttestationCenter.Attestation memory attestation = attestationCenter.getAttestation(attestationId);
        
        assertEq(attestation.attestationId, attestationId);
        assertEq(attestation.attester, attester1);
        assertEq(attestation.subject, subject1);
        assertEq(attestation.data, data1);
        assertTrue(attestation.isValid);
        assertEq(attestation.timestamp, block.timestamp);
    }
    
    function test_GetAttestation_NonExistent() public {
        vm.expectRevert(SimplifiedAttestationCenter.AttestationNotFound.selector);
        attestationCenter.getAttestation(999);
    }
    
    function test_GetAttestationsByAttester() public {
        // Create multiple attestations by same attester
        SimplifiedAttestationCenter.AttestationRequest memory request1 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        bytes memory data3 = "data3";
        bytes32 subject3 = keccak256("subject3");
        bytes memory signature3 = _generateSignature(attester1PrivateKey, attester1, subject3, data3, defaultDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request2 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject3,
            data: data3,
            signature: signature3,
            deadline: defaultDeadline
        });
        
        vm.startPrank(attester1);
        uint256 id1 = attestationCenter.createAttestation(request1);
        uint256 id2 = attestationCenter.createAttestation(request2);
        vm.stopPrank();
        
        uint256[] memory attestationIds = attestationCenter.getAttestationsByAttester(attester1);
        
        assertEq(attestationIds.length, 2);
        assertEq(attestationIds[0], id1);
        assertEq(attestationIds[1], id2);
    }
    
    function test_GetAttestationsByAttester_Empty() public {
        uint256[] memory attestationIds = attestationCenter.getAttestationsByAttester(address(0x999));
        assertEq(attestationIds.length, 0);
    }
    
    function test_GetAttestationsBySubject() public {
        // Create multiple attestations for same subject
        SimplifiedAttestationCenter.AttestationRequest memory request1 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        bytes memory data3 = "different data";
        bytes memory signature3 = _generateSignature(attester2PrivateKey, attester2, subject1, data3, defaultDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request2 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data3,
            signature: signature3,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 id1 = attestationCenter.createAttestation(request1);
        
        vm.prank(attester2);
        uint256 id2 = attestationCenter.createAttestation(request2);
        
        uint256[] memory attestationIds = attestationCenter.getAttestationsBySubject(subject1);
        
        assertEq(attestationIds.length, 2);
        assertEq(attestationIds[0], id1);
        assertEq(attestationIds[1], id2);
    }
    
    function test_GetAttestationsBySubject_Empty() public {
        uint256[] memory attestationIds = attestationCenter.getAttestationsBySubject(keccak256("nonexistent"));
        assertEq(attestationIds.length, 0);
    }
    
    function test_GetTotalAttestations() public {
        assertEq(attestationCenter.getTotalAttestations(), 0);
        
        // Create first attestation
        SimplifiedAttestationCenter.AttestationRequest memory request1 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        attestationCenter.createAttestation(request1);
        
        assertEq(attestationCenter.getTotalAttestations(), 1);
        
        // Create second attestation
        SimplifiedAttestationCenter.AttestationRequest memory request2 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject2,
            data: data2,
            signature: validSignature2,
            deadline: defaultDeadline
        });
        
        vm.prank(attester2);
        attestationCenter.createAttestation(request2);
        
        assertEq(attestationCenter.getTotalAttestations(), 2);
    }
    
    function test_IsValidAttestation() public {
        // Create attestation
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        // Check valid attestation
        assertTrue(attestationCenter.isValidAttestation(attestationId));
        
        // Revoke and check again
        vm.prank(attester1);
        attestationCenter.revokeAttestation(attestationId);
        
        assertFalse(attestationCenter.isValidAttestation(attestationId));
    }
    
    function test_IsValidAttestation_NonExistent() public {
        assertFalse(attestationCenter.isValidAttestation(999));
    }

    // ============ RENOUNCE OWNERSHIP TESTS (Finding #5) ============
    
    function test_RenounceOwnership_Disabled() public {
        vm.prank(owner);
        vm.expectRevert("Ownership renunciation disabled");
        attestationCenter.renounceOwnership();
    }

    // ============ INTERNAL FUNCTION TESTS ============
    
    function test_AttestationHash_Consistency() public {
        // Create the same attestation twice and verify hash consistency
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        attestationCenter.createAttestation(request);
        
        // Try to create the same attestation - should fail due to duplicate hash
        vm.prank(attester1);
        vm.expectRevert(SimplifiedAttestationCenter.AttestationAlreadyExists.selector);
        attestationCenter.createAttestation(request);
    }

    // ============ EDGE CASE TESTS ============
    
    function test_AttestationWithEmptyData() public {
        bytes memory emptyData = "";
        bytes memory signature = _generateSignature(attester1PrivateKey, attester1, subject1, emptyData, defaultDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: emptyData,
            signature: signature,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        SimplifiedAttestationCenter.Attestation memory attestation = attestationCenter.getAttestation(attestationId);
        assertEq(attestation.data.length, 0);
    }
    
    function test_AttestationWithLargeData() public {
        bytes memory largeData = new bytes(1000);
        for (uint i = 0; i < 1000; i++) {
            largeData[i] = bytes1(uint8(i % 256));
        }
        
        bytes memory signature = _generateSignature(attester1PrivateKey, attester1, subject1, largeData, defaultDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: largeData,
            signature: signature,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        SimplifiedAttestationCenter.Attestation memory attestation = attestationCenter.getAttestation(attestationId);
        assertEq(attestation.data.length, 1000);
        assertEq(attestation.data, largeData);
    }
    
    function test_MultipleAttestersForSameSubject() public {
        // Different attesters attest to the same subject with different data
        bytes memory data3 = "attester2 data for subject1";
        bytes memory signature3 = _generateSignature(attester2PrivateKey, attester2, subject1, data3, defaultDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request1 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data1,
            signature: validSignature1,
            deadline: defaultDeadline
        });
        
        SimplifiedAttestationCenter.AttestationRequest memory request2 = SimplifiedAttestationCenter.AttestationRequest({
            subject: subject1,
            data: data3,
            signature: signature3,
            deadline: defaultDeadline
        });
        
        vm.prank(attester1);
        uint256 id1 = attestationCenter.createAttestation(request1);
        
        vm.prank(attester2);
        uint256 id2 = attestationCenter.createAttestation(request2);
        
        uint256[] memory attestationIds = attestationCenter.getAttestationsBySubject(subject1);
        assertEq(attestationIds.length, 2);
        assertEq(attestationIds[0], id1);
        assertEq(attestationIds[1], id2);
    }

    // ============ INTEGRATION TESTS ============
    
    function test_CompleteWorkflow() public {
        // Complete workflow: authorize, create, verify, revoke
        uint256 newAttesterPk = 0x500;
        address newAttester = vm.addr(newAttesterPk);
        
        // Authorize new attester
        vm.prank(owner);
        attestationCenter.setAttesterAuthorization(newAttester, true);
        
        // Create attestation
        bytes memory newData = "workflow test data";
        bytes32 newSubject = keccak256("workflow subject");
        bytes memory newSignature = _generateSignature(newAttesterPk, newAttester, newSubject, newData, defaultDeadline);
        
        SimplifiedAttestationCenter.AttestationRequest memory request = SimplifiedAttestationCenter.AttestationRequest({
            subject: newSubject,
            data: newData,
            signature: newSignature,
            deadline: defaultDeadline
        });
        
        vm.prank(newAttester);
        uint256 attestationId = attestationCenter.createAttestation(request);
        
        // Verify attestation
        assertTrue(attestationCenter.isValidAttestation(attestationId));
        
        // Revoke attestation
        vm.prank(newAttester);
        attestationCenter.revokeAttestation(attestationId);
        
        // Verify revocation
        assertFalse(attestationCenter.isValidAttestation(attestationId));
        
        // Deauthorize attester
        vm.prank(owner);
        attestationCenter.setAttesterAuthorization(newAttester, false);
        
        assertFalse(attestationCenter.authorizedAttesters(newAttester));
    }

    // ============ HELPER FUNCTIONS ============
    
    function _generateSignature(
        uint256 privateKey,
        address attester,
        bytes32 subject,
        bytes memory data,
        uint256 deadline
    ) internal view returns (bytes memory) {
        // Must match the contract's _getAttestationHash function (now uses abi.encode)
        bytes32 messageHash = keccak256(abi.encode(attester, subject, data, deadline, block.chainid, address(attestationCenter)));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }
}
