//
//  FSHA256Tests.swift
//  FSHA256Tests
//
//  Created by Pusca Ghenadie on 08/04/2019.
//  Copyright © 2019 Pusca Ghenadie. All rights reserved.
//

import XCTest
@testable import FSHA256

class FSHA256Tests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() {
        let strInput = "abcd"
        XCTAssertTrue(FSHA256().getHash(fromString: strInput) == "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589")
        
        let strInput2 = """
        The SHA (Secure Hash Algorithm) is one of a number of cryptographic hash functions. A cryptographic hash is like a signature for a text or a data file. SHA-256 algorithm generates an almost-unique, fixed size 256-bit (32-byte) hash. Hash is a one way function – it cannot be decrypted back. This makes it suitable for password validation, challenge hash authentication, anti-tamper, digital signatures.
        """
        
        XCTAssertTrue(FSHA256().getHash(fromString: strInput2) == "d37e2b4fab26640551c69abc3bdf1c14534b215c7f3e1d44c0b65029c99147fb")
    }
}
