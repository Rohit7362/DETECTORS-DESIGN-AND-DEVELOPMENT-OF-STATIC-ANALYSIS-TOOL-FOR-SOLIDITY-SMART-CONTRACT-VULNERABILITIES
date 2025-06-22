// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IntegerBugDemo {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // Overflow: unchecked math
    function mint(uint256 amount) public {
        balances[msg.sender] = balances[msg.sender] + amount;
        totalSupply = totalSupply + amount;
    }

    // Underflow: if amount > balance
    function burn(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] = balances[msg.sender] - amount;
        totalSupply = totalSupply - amount;
    }
}
