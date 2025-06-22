// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerabilityShowcase {
    address[] public recipients;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    //  Safe deposit
    function deposit() public payable {
        require(msg.value > 0, "No ETH");
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    //  Reentrancy vulnerability: external call before state update
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");

        balances[msg.sender] = 0;
    }

    //  Integer overflow + underflow
    function mint(uint256 amount) public {
        balances[msg.sender] = balances[msg.sender] + amount;
        totalSupply = totalSupply + amount;
    }

    function burn(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Not enough balance");
        balances[msg.sender] = balances[msg.sender] - amount;
        totalSupply = totalSupply - amount;
    }

    //  Compound overflow
    function multiplyAdd(uint256 x, uint256 y) public {
        uint256 result = x * y + 1;
        balances[msg.sender] = balances[msg.sender] + result;
        totalSupply = totalSupply + result;
    }

    //  Reentrancy via internal call
    function unsafeWithdraw() public {
        _doSend(msg.sender, balances[msg.sender]);
        balances[msg.sender] = 0;
    }

    function _doSend(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        require(success, "Send failed");
    }

    //  DoS: external call inside loop
    function distribute() public {
        require(msg.sender == owner, "Only owner");
        for (uint i = 0; i < recipients.length; i++) {
            address user = recipients[i];
            uint256 amount = balances[user];
            if (amount > 0) {
                (bool sent, ) = user.call{value: amount}("");
                require(sent, "Fail");
                balances[user] = 0;
            }
        }
    }

    //  Already safe
    function safeWithdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    //  Unchecked block used properly
    function trustedMint(uint256 amount) public {
        unchecked {
            balances[msg.sender] += amount;
            totalSupply += amount;
        }
    }

    //  Safe loop: no external call
    function reset() public {
        for (uint i = 0; i < recipients.length; i++) {
            balances[recipients[i]] = 0;
        }
    }
}
