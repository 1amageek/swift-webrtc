import Testing
@testable import WebRTCMedia
@Suite("H.264 byte-stream parser")
struct H264ByteStreamParserTests {
    private let parser = H264ByteStreamParser()

    @Test("Annex B accepts three- and four-byte delimiters without copying payloads")
    func annexBMixedStartCodes() throws {
        var accessUnit: [UInt8] = [
            0, 0, 0, 1, 0x67, 1, 2,
            0, 0, 1, 0x68, 3,
            0, 0,
        ]
        let ranges = try parser.nalUnitRanges(
            in: accessUnit.span,
            format: .annexB
        )

        #expect(ranges == [4..<7, 10..<12])
        accessUnit[4] = 0x65
        #expect(accessUnit[ranges[0].lowerBound] == 0x65)
    }

    @Test("Annex B accepts leading zero bytes")
    func annexBLeadingZeros() throws {
        let accessUnit: [UInt8] = [0, 0, 0, 0, 0, 1, 0x65, 1]
        let ranges = try parser.nalUnitRanges(
            in: accessUnit.span,
            format: .annexB
        )
        #expect(ranges == [6..<8])
    }

    @Test("Annex B failures are explicit and transactional")
    func annexBFailures() {
        var destination = [9..<10]
        let noStartCode: [UInt8] = [0x65, 1, 2]
        #expect(throws: H264ByteStreamError.missingAnnexBStartCode) {
            try parser.appendNALUnitRanges(
                in: noStartCode.span,
                format: .annexB,
                to: &destination
            )
        }
        #expect(destination == [9..<10])

        let garbagePrefix: [UInt8] = [0x55, 0, 0, 1, 0x65]
        #expect(throws: H264ByteStreamError.nonzeroBytesBeforeFirstStartCode(offset: 0)) {
            try parser.appendNALUnitRanges(
                in: garbagePrefix.span,
                format: .annexB,
                to: &destination
            )
        }
        #expect(destination == [9..<10])

        let emptySecondNAL: [UInt8] = [0, 0, 1, 0x65, 0, 0, 1]
        #expect(throws: H264ByteStreamError.emptyNALUnit(index: 1)) {
            try parser.appendNALUnitRanges(
                in: emptySecondNAL.span,
                format: .annexB,
                to: &destination
            )
        }
        #expect(destination == [9..<10])
    }

    @Test("AVCC extracts one-, two-, and four-byte length prefixes", arguments: [1, 2, 4])
    func avccLengthPrefixes(lengthFieldByteCount: Int) throws {
        let firstNAL: [UInt8] = [0x67, 1, 2]
        let secondNAL: [UInt8] = [0x65, 3]
        var accessUnit: [UInt8] = []
        appendLength(firstNAL.count, byteCount: lengthFieldByteCount, to: &accessUnit)
        let firstStart = accessUnit.count
        accessUnit.append(contentsOf: firstNAL)
        appendLength(secondNAL.count, byteCount: lengthFieldByteCount, to: &accessUnit)
        let secondStart = accessUnit.count
        accessUnit.append(contentsOf: secondNAL)

        let ranges = try parser.nalUnitRanges(
            in: accessUnit.span,
            format: .avcc(lengthFieldByteCount: lengthFieldByteCount)
        )
        #expect(ranges == [
            firstStart..<(firstStart + firstNAL.count),
            secondStart..<(secondStart + secondNAL.count),
        ])
    }

    @Test("AVCC rejects invalid widths, truncation, zero lengths, and overruns")
    func avccFailures() {
        let oneByte: [UInt8] = [0]
        #expect(throws: H264ByteStreamError.invalidAVCCLengthFieldByteCount(actual: 0)) {
            _ = try parser.nalUnitRanges(
                in: oneByte.span,
                format: .avcc(lengthFieldByteCount: 0)
            )
        }

        #expect(throws: H264ByteStreamError.truncatedAVCCLengthField(
            offset: 0,
            expected: 4,
            actual: 1
        )) {
            _ = try parser.nalUnitRanges(
                in: oneByte.span,
                format: .avcc(lengthFieldByteCount: 4)
            )
        }

        let zeroLength: [UInt8] = [0, 0]
        #expect(throws: H264ByteStreamError.emptyNALUnit(index: 0)) {
            _ = try parser.nalUnitRanges(
                in: zeroLength.span,
                format: .avcc(lengthFieldByteCount: 2)
            )
        }

        let overrun: [UInt8] = [0, 4, 0x65, 1]
        #expect(throws: H264ByteStreamError.avccNALUnitOutOfBounds(
            index: 0,
            declaredByteCount: 4,
            availableByteCount: 2
        )) {
            _ = try parser.nalUnitRanges(
                in: overrun.span,
                format: .avcc(lengthFieldByteCount: 2)
            )
        }
    }

    @Test("Empty input is a typed failure")
    func emptyInput() {
        let empty: [UInt8] = []
        #expect(throws: H264ByteStreamError.emptyAccessUnit) {
            _ = try parser.nalUnitRanges(in: empty.span, format: .annexB)
        }
    }

    private func appendLength(
        _ value: Int,
        byteCount: Int,
        to destination: inout [UInt8]
    ) {
        for byteOffset in (0..<byteCount).reversed() {
            destination.append(UInt8(truncatingIfNeeded: value >> (byteOffset * 8)))
        }
    }
}
