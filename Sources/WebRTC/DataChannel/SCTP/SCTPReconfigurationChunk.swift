/// A supported parameter carried by an SCTP RE-CONFIG chunk.
enum SCTPReconfigurationParameter: Sendable, Equatable {
    case outgoingSSNReset(SCTPOutgoingSSNResetRequest)
    case incomingSSNReset(SCTPIncomingSSNResetRequest)
    case response(SCTPReconfigurationResponse)
}

/// An SCTP RE-CONFIG chunk (RFC 6525 §3.1).
///
/// The WebRTC data-channel close path uses Outgoing SSN Reset Request and
/// Re-configuration Response parameters. Other RFC 6525 services are rejected
/// explicitly at this boundary instead of being accepted as a silent no-op.
struct SCTPReconfigurationChunk: Sendable, Equatable {
    let parameters: [SCTPReconfigurationParameter]

    init(parameters: [SCTPReconfigurationParameter]) {
        self.parameters = parameters
    }

    func toChunk() throws(SCTPWireError) -> SCTPChunk {
        try Self.validateCombination(parameters)

        var value: [UInt8] = []
        for (index, parameter) in parameters.enumerated() {
            switch parameter {
            case .outgoingSSNReset(let request):
                value.append(contentsOf: try request.encodeParameterBytes())
            case .incomingSSNReset(let request):
                value.append(contentsOf: try request.encodeParameterBytes())
            case .response(let response):
                value.append(contentsOf: try response.encodeParameterBytes())
            }
            // Parameter padding separates two TLVs but trailing padding belongs
            // to the containing SCTP chunk and is excluded from Chunk Length.
            if index + 1 < parameters.count {
                while value.count % 4 != 0 {
                    value.append(0)
                }
            }
        }
        guard value.count <= Int(UInt16.max) - 4 else {
            throw .decode(.invalidFormat("RE-CONFIG value exceeds the SCTP Chunk Length field"))
        }
        return try SCTPChunk(
            chunkType: SCTPChunkType.reConfig.rawValue,
            value: value
        )
    }

    static func decode(from chunk: SCTPChunk) throws(SCTPWireError) -> Self {
        guard chunk.chunkType == SCTPChunkType.reConfig.rawValue else {
            throw .decode(.invalidFormat("Expected a RE-CONFIG chunk"))
        }
        let bytes = chunk.value
        var parameters: [SCTPReconfigurationParameter] = []
        var offset = 0
        while offset < bytes.count {
            guard parameters.count < 2 else {
                throw .decode(.invalidFormat("A RE-CONFIG chunk contains more than two parameters"))
            }
            guard bytes.count - offset >= 4 else {
                throw .decode(.insufficientData(expected: offset + 4, actual: bytes.count))
            }
            let type = sctpReadUInt16(bytes, offset: offset)
            let length = Int(sctpReadUInt16(bytes, offset: offset + 2))
            guard length >= 4 else {
                throw .decode(.invalidFormat("RE-CONFIG parameter length is below four"))
            }
            guard length <= bytes.count - offset else {
                throw .decode(.insufficientData(expected: offset + length, actual: bytes.count))
            }

            switch type {
            case SCTPOutgoingSSNResetRequest.parameterType:
                parameters.append(.outgoingSSNReset(try .decodeParameter(
                    from: bytes,
                    offset: offset,
                    length: length
                )))
            case SCTPIncomingSSNResetRequest.parameterType:
                parameters.append(.incomingSSNReset(try .decodeParameter(
                    from: bytes,
                    offset: offset,
                    length: length
                )))
            case SCTPReconfigurationResponse.parameterType:
                parameters.append(.response(try .decodeParameter(
                    from: bytes,
                    offset: offset,
                    length: length
                )))
            default:
                throw .decode(.invalidFormat("Unsupported RE-CONFIG parameter type \(type)"))
            }

            let end = offset + length
            if end == bytes.count {
                offset = end
                continue
            }
            let (paddedLength, overflow) = length.addingReportingOverflow(3)
            guard !overflow else {
                throw .decode(.invalidFormat("RE-CONFIG parameter padding overflow"))
            }
            let paddedEnd = offset + (paddedLength & ~3)
            guard paddedEnd <= bytes.count else {
                throw .decode(.insufficientData(expected: paddedEnd, actual: bytes.count))
            }
            // RFC 4960 requires senders to use zero padding, but receivers must
            // ignore padding bytes. Interoperability therefore cannot reject a
            // peer solely because these bytes are non-zero.
            offset = paddedEnd
        }

        guard !parameters.isEmpty else {
            throw .decode(.invalidFormat("A RE-CONFIG chunk must contain a parameter"))
        }
        try validateCombination(parameters)
        return Self(parameters: parameters)
    }

    private static func validateCombination(
        _ parameters: [SCTPReconfigurationParameter]
    ) throws(SCTPWireError) {
        guard (1...2).contains(parameters.count) else {
            throw .decode(.invalidFormat("A RE-CONFIG chunk must contain one or two parameters"))
        }
        guard parameters.count == 2 else { return }

        switch (parameters[0], parameters[1]) {
        case (.outgoingSSNReset, .incomingSSNReset),
             (.response, .outgoingSSNReset),
             (.response, .response):
            return
        default:
            throw .decode(.invalidFormat("Unsupported RE-CONFIG parameter combination"))
        }
    }
}
