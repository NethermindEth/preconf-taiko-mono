// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "src/shared/common/EssentialContract.sol";

contract EssentialContract_EmptyStub is EssentialContract {
    constructor(address _resolver) EssentialContract(_resolver) { }

    function init(address _owner) external initializer {
        __Essential_init(_owner);
    }
}
