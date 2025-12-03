// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/SimplifiedAttestationCenter.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Deploying SimplifiedAttestationCenter...");
        console.log("Deployer address:", deployer);
        console.log("Deployer balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy the contract with deployer as owner
        SimplifiedAttestationCenter attestationCenter = new SimplifiedAttestationCenter(deployer);
        
        console.log("SimplifiedAttestationCenter deployed at:", address(attestationCenter));
        console.log("Contract owner:", attestationCenter.owner());
        console.log("Total attestations:", attestationCenter.getTotalAttestations());
        
        // Optionally authorize some initial attesters
        // Uncomment and modify addresses as needed
        /*
        address[] memory initialAttesters = new address[](1);
        initialAttesters[0] = 0x93671C1781aF8eb2e7D71E92bAD4c38C6E5ed680; // Replace with actual address
        
        for (uint i = 0; i < initialAttesters.length; i++) {
            attestationCenter.setAttesterAuthorization(initialAttesters[i], true);
            console.log("Authorized attester:", initialAttesters[i]);
        }
        */
        
        vm.stopBroadcast();
        
        console.log("\n=== Deployment Summary ===");
        console.log("Contract Address:", address(attestationCenter));
        console.log("Network:", block.chainid);
        console.log("Block Number:", block.number);
        console.log("Gas Price:", tx.gasprice);
        console.log("==========================");
    }
}


// Mainnet deployment:
// forge script script/Deploy.s.sol:DeployScript --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --etherscan-api-key $ETHERSCAN_API_KEY 
