import Testing
@testable import WebRTC

@Suite("STUN Binding Transaction Tests")
struct STUNBindingTransactionTests {
    @Test("Binding success returns the XOR-mapped address")
    func parsesSuccess() throws {
        let id = Array(0..<12).map(UInt8.init)
        let transaction = STUNBindingTransaction(transactionID: id)
        let response = STUNMessage.bindingSuccessResponse(
            transactionID: TransactionID(byteValues: id),
            address: [203, 0, 113, 9],
            port: 54_321
        ).encodeBytes()

        let mapped = try transaction.parseResponse(response)

        #expect(mapped.addressBytes == [203, 0, 113, 9])
        #expect(mapped.port == 54_321)
    }

    @Test("Transaction mismatch and trailing bytes fail closed")
    func rejectsMismatchedResponse() throws {
        let transaction = STUNBindingTransaction(
            transactionID: [UInt8](repeating: 1, count: 12)
        )
        let otherID = TransactionID(
            byteValues: [UInt8](repeating: 2, count: 12)
        )
        let otherResponse = STUNMessage.bindingSuccessResponse(
            transactionID: otherID,
            address: [127, 0, 0, 1],
            port: 5_000
        ).encodeBytes()

        #expect(throws: STUNBindingTransactionError.transactionMismatch) {
            _ = try transaction.parseResponse(otherResponse)
        }

        var responseWithTrailingByte = STUNMessage.bindingSuccessResponse(
            transactionID: TransactionID(
                byteValues: [UInt8](repeating: 1, count: 12)
            ),
            address: [127, 0, 0, 1],
            port: 5_000
        ).encodeBytes()
        responseWithTrailingByte.append(0)
        #expect(throws: STUNBindingTransactionError.malformed) {
            _ = try transaction.parseResponse(responseWithTrailingByte)
        }
    }
}
