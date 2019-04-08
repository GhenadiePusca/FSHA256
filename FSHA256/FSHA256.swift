//
//  FSHA256.swift
//  FSHA256
//
//  Created by Pusca Ghenadie on 07/04/2019.
//  Copyright © 2019 Pusca Ghenadie. All rights reserved.
//

import Foundation

struct FSHA256 {
    typealias Byte = UInt8

    fileprivate struct Constants {
        static let digestSize = 256
        static let chunckSize = 512
        static let hashValue: [UInt32] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        static let K: [UInt32] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
    }
    
    // MARK: - Public methods

    func getHash(fromString string: String) -> String {
        return (bytesFromString --> getHash --> stringHash)(string)
    }

    func getHash(_ inp: [Byte]) -> [Byte] {
        return (paddInput --> getBlocks --> processBlocks --> computeResult)(inp)
    }

    // MARK: - Core methods

    private func process(_ hash: [UInt32], _ chunk: [UInt8]) -> [UInt32] {
        return (msgSchedule -->
                { (schedule: [UInt32]) -> [UInt32] in
                    self.performHashing(hash: hash, schedule)
                } --> { (hashed: [UInt32]) -> [UInt32] in
                    [hashed[0] &+ hash[0],
                     hashed[1] &+ hash[1],
                     hashed[2] &+ hash[2],
                     hashed[3] &+ hash[3],
                     hashed[4] &+ hash[4],
                     hashed[5] &+ hash[5],
                     hashed[6] &+ hash[6],
                     hashed[7] &+ hash[7]]
                })(chunk)
    }

    private func performHashing(hash: [UInt32], _ msgSchedule: [UInt32]) -> [UInt32] {
        return stride(from: 0, to: Constants.K.count, by: 1).reduce(hash) { (result: [UInt32], idx: Int) -> [UInt32] in
            return ({
                        self.calculateT1T2($0, msgSchedule)(idx)
                    } --> { (t1: UInt32, t2: UInt32) -> [UInt32] in
                        [t1 &+ t2,
                         result[0],
                         result[1],
                         result[2],
                         result[3] &+ t1,
                         result[4],
                         result[5],
                         result[6]]
                    })(result)
        }
    }

    private func msgSchedule(_ inp: [Byte]) -> [UInt32] {
        return stride(from: 0, to: Constants.K.count, by: 1).reduce([UInt32]()) {
            (result: [UInt32], idx: Int) -> [UInt32] in
            result + [switchCaseRange([
                /// Cases
                (0...15, {
                    UInt32(inp[idx * 4]) << 24     |
                    UInt32(inp[idx * 4 + 1]) << 16 |
                    UInt32(inp[idx * 4 + 2]) << 8  |
                    UInt32(inp[idx * 4 + 3]) })
                ])({ // Default case
                    (UInt32(result[idx-2]) >>> UInt32(17)  ^
                     UInt32(result[idx-2]) >>> UInt32(19)  ^
                     UInt32(result[idx-2]) >> UInt32(10))  &+
                     UInt32(result[idx - 7])               &+
                    (UInt32(result[idx-15]) >>> UInt32(7)  ^
                     UInt32(result[idx-15]) >>> UInt32(18) ^
                     UInt32(result[idx-15]) >> UInt32(3))  &+
                     UInt32(result[idx - 16])})(idx)]
        }
    }
    
    private func paddInput(_ inp: [Byte]) -> [Byte] {
        return ({ (_ : Void) -> Int in
                    inp.count * 8 % Constants.chunckSize
                } --> { (mod: Int) -> Int in
                    mod < 448 ? 448 - 1 - mod : Constants.chunckSize + 448 - mod - 1
                } --> { (toAppend: Int) -> [Byte] in
                    inp + [0x80] + [UInt8](repeating: 0, count: (toAppend - 7) / 8)
                } --> { (appended: [Byte]) -> [Byte] in
                    appended + withUnsafeBytes(of: UInt64(inp.count * 8).littleEndian, Array.init).lazy.reversed()
                })(())
    }
    
    private func calculateT1T2(_ hash: [UInt32], _ msgSchedule: [UInt32]) -> (Int) -> (t1: UInt32, t2: UInt32) {
        return {
            ((hash[7] &+ (hash[4] >>> 6 ^ hash[4] >>> 11 ^ hash[4] >>> 25) &+
                ((hash[4] & hash[5]) ^ (~hash[4] & hash[6]))               &+
                Constants.K[$0]                                            &+
                msgSchedule[$0]),
             ((hash[0] >>> 2 ^ hash[0] >>> 13 ^ hash[0] >>> 22) &+
                ((hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]))))
        }
    }

    private func getBlocks(_ inp: [Byte]) -> [[Byte]] {
        return stride(from: 0, to: inp.count, by: Constants.chunckSize / 8).map {
            Array(inp[$0 ..< min($0 + Constants.chunckSize / 8, inp.count)])
        }
    }
    
    private func processBlocks(_ blocks: [[Byte]]) -> [UInt32] {
        return blocks.reduce(Constants.hashValue, {
            process($0, $1)
        })
    }
    
    private func computeResult(_ hash: [UInt32]) -> [UInt8] {
        return hash.enumerated().reduce([UInt8](), {
            $0 + [UInt8(($1.element >> 24) & 0xff),
                  UInt8(($1.element >> 16) & 0xff),
                  UInt8(($1.element >> 8) & 0xff),
                  UInt8($1.element & 0xff)]
        })
    }
    
    private func bytesFromString(_ str: String) -> [UInt8] {
        return [UInt8](str.utf8)
    }
    
    private func stringHash(from byteHash: [UInt8]) -> String {
        return byteHash.reduce("", { (res: String, byte: Byte) -> String in
            ({
                String($0, radix: 16)
             } --> { (byteStr: String) -> String in
                res + (byteStr.count == 1 ? "0" + byteStr : byteStr)
             })(byte)
        })
    }
}

// MARK: - Functional helpers

fileprivate precedencegroup Group { associativity: left }
fileprivate infix operator -->: Group

fileprivate func --> <T, U, V>(left: @escaping (T) -> U, right: @escaping (U) -> V) -> (T) -> V {
    return { right(left($0)) }
}

// MARK: - Switch case

// Substitues the switch case that goes over a range

/// Specialized to the UInt32, to help the swift compiler to type check
fileprivate func switchCaseRange(_ cases: [(range: CountableClosedRange<Int>, value: () -> UInt32)])
    -> (_ defaultValue: @escaping () -> UInt32) -> (_ option: Int) -> UInt32 {
        return { defaultCase in
            { option in
                return cases.first { $0.range ~= option }?.value() ?? defaultCase()
            }
        }
}

// MARK: - Shift op
fileprivate infix operator >>> : BitwiseShiftPrecedence
fileprivate func >>> (lhs:UInt32, rhs:UInt32) -> UInt32 {
    return lhs >> rhs | lhs << (32-rhs)
}

