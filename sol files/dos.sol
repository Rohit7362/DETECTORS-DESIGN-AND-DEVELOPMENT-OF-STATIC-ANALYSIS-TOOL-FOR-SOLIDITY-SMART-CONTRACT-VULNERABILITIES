// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DoSDemo {
    address[] public recipients;
    mapping(address => uint256) public balances;

    function addRecipient() public payable {
        recipients.push(msg.sender);
        balances[msg.sender] += msg.value;
    }

    // DoS Risk: external call in loop
    function distribute() public {
        for (uint i = 0; i < recipients.length; i++) {
            address user = recipients[i];
            uint256 amount = balances[user];
            if (amount > 0) {
                (bool sent, ) = user.call{value: amount}("");
                require(sent, "Send failed");
                balances[user] = 0;
            }
        }
    }
}
