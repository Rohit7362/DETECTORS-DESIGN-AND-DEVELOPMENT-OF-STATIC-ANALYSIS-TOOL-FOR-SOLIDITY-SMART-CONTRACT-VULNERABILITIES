// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyDemo {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable: external call before state update
    function withdraw() public {
        require(balances[msg.sender] > 0, "No balance");
        (bool sent, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(sent, "Transfer failed");
        balances[msg.sender] = 0;
    }
}
