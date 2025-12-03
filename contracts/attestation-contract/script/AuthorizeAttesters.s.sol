// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/SimplifiedAttestationCenter.sol";

contract AuthorizeAttestersScript is Script {
    // Update this with the deployed contract address
    address constant ATTESTATION_CENTER = 0x5a2fA76D1595B4D047c54e0DDdF36e5b2Dd3AACd;
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Authorizing attesters on existing contract...");
        console.log("Contract address:", ATTESTATION_CENTER);
        console.log("Deployer/Owner address:", deployer);
        console.log("Deployer balance:", deployer.balance);
        
        // Get the existing contract instance
        SimplifiedAttestationCenter attestationCenter = SimplifiedAttestationCenter(ATTESTATION_CENTER);
        
        // Verify we are the owner
        address contractOwner = attestationCenter.owner();
        console.log("Contract owner:", contractOwner);
        require(contractOwner == deployer, "Only contract owner can authorize attesters");
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Add subnet owner wallet addresses here
        // These are the actual wallet addresses that will be subnet owners/attesters
        address[] memory newAttesters = new address[](1);
        
        // Real user wallet address from JWT token
        newAttesters[0] = 0x93671C1781aF8eb2e7D71E92bAD4c38C6E5ed680; // Real Subnet Owner
        
        // Batch authorize all attesters
        console.log("Authorizing", newAttesters.length, "attesters...");
        
        for (uint i = 0; i < newAttesters.length; i++) {
            // Check if already authorized
            bool isAlreadyAuthorized = attestationCenter.authorizedAttesters(newAttesters[i]);
            
            if (!isAlreadyAuthorized) {
                attestationCenter.setAttesterAuthorization(newAttesters[i], true);
                console.log("Authorized attester:", newAttesters[i]);
            } else {
                console.log("Already authorized:", newAttesters[i]);
            }
        }
        
        vm.stopBroadcast();
        
        console.log("\n=== Authorization Summary ===");
        console.log("Contract:", ATTESTATION_CENTER);
        console.log("Network Chain ID:", block.chainid);
        console.log("Total Attesters Processed:", newAttesters.length);
        
        // Verify authorizations
        console.log("\n=== Verification ===");
        for (uint i = 0; i < newAttesters.length; i++) {
            bool isAuthorized = attestationCenter.authorizedAttesters(newAttesters[i]);
            console.log("Attester", newAttesters[i], "authorized:", isAuthorized);
        }
        console.log("=============================");
    }
}

// Usage:
// forge script script/AuthorizeAttesters.s.sol:AuthorizeAttestersScript --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
