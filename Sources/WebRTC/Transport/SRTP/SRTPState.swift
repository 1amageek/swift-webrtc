struct SRTPState: Sendable {
    var outboundRTP: [UInt32: OutboundRTPState] = [:]
    var inboundRTP: [UInt32: InboundPacketState] = [:]
    var outboundRTCP: [UInt32: OutboundSRTCPState] = [:]
    var inboundRTCP: [UInt32: InboundPacketState] = [:]

    mutating func reserveOutboundRTP(
        synchronizationSource: UInt32,
        sequenceNumber: UInt16
    ) throws(SRTPError) -> UInt64 {
        var stream = outboundRTP[synchronizationSource] ?? OutboundRTPState()
        let reference = stream.referenceIndex
        if let reference,
           UInt32(reference >> 16) == 0,
           UInt16(reference & 0xFFFF) < 0x8000,
           Int(sequenceNumber) - Int(UInt16(reference & 0xFFFF)) > 0x8000 {
            throw .outboundIndexReuse(
                synchronizationSource: synchronizationSource,
                index: UInt64(sequenceNumber)
            )
        }
        let index = try estimatePacketIndex(
            sequenceNumber: sequenceNumber,
            referenceIndex: reference,
            synchronizationSource: synchronizationSource,
            kind: .rtp
        )
        if let reference, index <= reference || stream.pendingIndices.contains(index) {
            throw .outboundIndexReuse(
                synchronizationSource: synchronizationSource,
                index: index
            )
        }
        stream.pendingIndices.insert(index)
        outboundRTP[synchronizationSource] = stream
        return index
    }

    mutating func commitOutboundRTP(
        synchronizationSource: UInt32,
        index: UInt64
    ) throws(SRTPError) {
        guard var stream = outboundRTP[synchronizationSource],
              stream.pendingIndices.remove(index) != nil else {
            throw .stateReservationLost(
                kind: .rtp,
                synchronizationSource: synchronizationSource,
                index: index
            )
        }
        if let highestCommittedIndex = stream.highestCommittedIndex {
            if index > highestCommittedIndex {
                stream.highestCommittedIndex = index
            }
        } else {
            stream.highestCommittedIndex = index
        }
        outboundRTP[synchronizationSource] = stream
    }

    mutating func burnOutboundRTP(synchronizationSource: UInt32, index: UInt64) -> Bool {
        guard var stream = outboundRTP[synchronizationSource],
              stream.pendingIndices.remove(index) != nil else {
            return false
        }
        if let highestCommittedIndex = stream.highestCommittedIndex {
            if index > highestCommittedIndex {
                stream.highestCommittedIndex = index
            }
        } else {
            stream.highestCommittedIndex = index
        }
        outboundRTP[synchronizationSource] = stream
        return true
    }

    mutating func reserveInboundRTP(
        synchronizationSource: UInt32,
        sequenceNumber: UInt16
    ) throws(SRTPError) -> UInt64 {
        var stream = inboundRTP[synchronizationSource] ?? InboundPacketState()
        let index = try estimatePacketIndex(
            sequenceNumber: sequenceNumber,
            referenceIndex: stream.replayWindow.highestIndex,
            synchronizationSource: synchronizationSource,
            kind: .rtp
        )
        try reserveInbound(
            stream: &stream,
            kind: .rtp,
            synchronizationSource: synchronizationSource,
            index: index
        )
        inboundRTP[synchronizationSource] = stream
        return index
    }

    mutating func reserveOutboundRTCP(synchronizationSource: UInt32) throws(SRTPError) -> UInt32 {
        var stream = outboundRTCP[synchronizationSource] ?? OutboundSRTCPState()
        guard let index = stream.nextIndex else {
            throw .indexExhausted(kind: .rtcp, synchronizationSource: synchronizationSource)
        }
        stream.pendingIndices.insert(index)
        stream.nextIndex = index == OutboundSRTCPState.maximumIndex ? nil : index + 1
        outboundRTCP[synchronizationSource] = stream
        return index
    }

    mutating func commitOutboundRTCP(
        synchronizationSource: UInt32,
        index: UInt32
    ) throws(SRTPError) {
        guard var stream = outboundRTCP[synchronizationSource],
              stream.pendingIndices.remove(index) != nil else {
            throw .stateReservationLost(
                kind: .rtcp,
                synchronizationSource: synchronizationSource,
                index: UInt64(index)
            )
        }
        if let highestCommittedIndex = stream.highestCommittedIndex {
            if index > highestCommittedIndex {
                stream.highestCommittedIndex = index
            }
        } else {
            stream.highestCommittedIndex = index
        }
        outboundRTCP[synchronizationSource] = stream
    }

    mutating func burnOutboundRTCP(synchronizationSource: UInt32, index: UInt32) -> Bool {
        guard var stream = outboundRTCP[synchronizationSource],
              stream.pendingIndices.remove(index) != nil else {
            return false
        }
        if let highestCommittedIndex = stream.highestCommittedIndex {
            if index > highestCommittedIndex {
                stream.highestCommittedIndex = index
            }
        } else {
            stream.highestCommittedIndex = index
        }
        outboundRTCP[synchronizationSource] = stream
        return true
    }

    mutating func reserveInboundRTCP(
        synchronizationSource: UInt32,
        index: UInt32
    ) throws(SRTPError) {
        var stream = inboundRTCP[synchronizationSource] ?? InboundPacketState()
        try reserveInbound(
            stream: &stream,
            kind: .rtcp,
            synchronizationSource: synchronizationSource,
            index: UInt64(index)
        )
        inboundRTCP[synchronizationSource] = stream
    }

    mutating func commitInbound(
        kind: SRTPPacketKind,
        synchronizationSource: UInt32,
        index: UInt64
    ) throws(SRTPError) {
        switch kind {
        case .rtp:
            guard var stream = inboundRTP[synchronizationSource],
                  stream.pendingIndices.remove(index) != nil else {
                throw .stateReservationLost(
                    kind: kind,
                    synchronizationSource: synchronizationSource,
                    index: index
                )
            }
            stream.replayWindow.commit(index)
            inboundRTP[synchronizationSource] = stream
        case .rtcp:
            guard var stream = inboundRTCP[synchronizationSource],
                  stream.pendingIndices.remove(index) != nil else {
                throw .stateReservationLost(
                    kind: kind,
                    synchronizationSource: synchronizationSource,
                    index: index
                )
            }
            stream.replayWindow.commit(index)
            inboundRTCP[synchronizationSource] = stream
        }
    }

    mutating func cancelInbound(
        kind: SRTPPacketKind,
        synchronizationSource: UInt32,
        index: UInt64
    ) {
        switch kind {
        case .rtp:
            guard var stream = inboundRTP[synchronizationSource] else { return }
            stream.pendingIndices.remove(index)
            if stream.replayWindow.highestIndex == nil && stream.pendingIndices.isEmpty {
                inboundRTP.removeValue(forKey: synchronizationSource)
            } else {
                inboundRTP[synchronizationSource] = stream
            }
        case .rtcp:
            guard var stream = inboundRTCP[synchronizationSource] else { return }
            stream.pendingIndices.remove(index)
            if stream.replayWindow.highestIndex == nil && stream.pendingIndices.isEmpty {
                inboundRTCP.removeValue(forKey: synchronizationSource)
            } else {
                inboundRTCP[synchronizationSource] = stream
            }
        }
    }

    private func reserveInbound(
        stream: inout InboundPacketState,
        kind: SRTPPacketKind,
        synchronizationSource: UInt32,
        index: UInt64
    ) throws(SRTPError) {
        if stream.pendingIndices.contains(index) {
            throw .replayedPacket(
                kind: kind,
                synchronizationSource: synchronizationSource,
                index: index
            )
        }
        switch stream.replayWindow.verdict(for: index) {
        case .acceptable:
            stream.pendingIndices.insert(index)
        case .replayed:
            throw .replayedPacket(
                kind: kind,
                synchronizationSource: synchronizationSource,
                index: index
            )
        case .tooOld:
            throw .packetTooOld(
                kind: kind,
                synchronizationSource: synchronizationSource,
                index: index
            )
        }
    }
}

struct OutboundRTPState: Sendable {
    var highestCommittedIndex: UInt64?
    var pendingIndices: Set<UInt64> = []

    var referenceIndex: UInt64? {
        let highestPending = pendingIndices.max()
        switch (highestCommittedIndex, highestPending) {
        case let (committed?, pending?): return max(committed, pending)
        case let (committed?, nil): return committed
        case let (nil, pending?): return pending
        case (nil, nil): return nil
        }
    }
}

struct InboundPacketState: Sendable {
    var replayWindow = ReplayWindow()
    var pendingIndices: Set<UInt64> = []
}

struct OutboundSRTCPState: Sendable {
    static let maximumIndex: UInt32 = 0x7FFF_FFFF

    var nextIndex: UInt32? = 0
    var highestCommittedIndex: UInt32?
    var pendingIndices: Set<UInt32> = []
}

private func estimatePacketIndex(
    sequenceNumber: UInt16,
    referenceIndex: UInt64?,
    synchronizationSource: UInt32,
    kind: SRTPPacketKind
) throws(SRTPError) -> UInt64 {
    guard let referenceIndex else {
        return UInt64(sequenceNumber)
    }

    let referenceROC = UInt32(referenceIndex >> 16)
    let referenceSequence = UInt16(referenceIndex & 0xFFFF)
    var estimatedROC = referenceROC

    if referenceSequence < 0x8000 {
        if Int(sequenceNumber) - Int(referenceSequence) > 0x8000 {
            // RFC 3711 Appendix A describes ROC arithmetic modulo 2^32. In an
            // initial ROC-zero context, however, ROC-1 would be the exhausted
            // final epoch. Accepting it would let an authenticated peer jump a
            // fresh replay window to the maximum 48-bit index. That epoch cannot
            // belong to this key without violating the 2^48 key lifetime.
            guard referenceROC > 0 else {
                throw .packetTooOld(
                    kind: kind,
                    synchronizationSource: synchronizationSource,
                    index: UInt64(sequenceNumber)
                )
            }
            estimatedROC = referenceROC - 1
        }
    } else if Int(referenceSequence) - 0x8000 > Int(sequenceNumber) {
        guard referenceROC < UInt32.max else {
            throw .indexExhausted(kind: kind, synchronizationSource: synchronizationSource)
        }
        estimatedROC = referenceROC + 1
    }

    return UInt64(estimatedROC) << 16 | UInt64(sequenceNumber)
}
