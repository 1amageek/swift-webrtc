/// One packet removed from the bounded reorder index.
struct H264RTPIndexedPacket<Element: Sendable>: Sendable {
    let packet: Element
    let extendedSequenceNumber: UInt64
}

/// Incremental indexes over packet owners retained for sequence reordering.
///
/// The dictionary is the sole owner of each packet. Three eager indexed binary
/// heaps retain only scalar metadata and an immutable identity token. Every
/// removal deletes its node from all three heaps immediately, keeping each
/// insertion and removal O(log n) without stale-node scans or payload copies.
struct H264RTPReorderPacketIndex<Element: Sendable>: Sendable {
    private final class Token: Sendable {}

    struct OperationMetrics: Sendable, Equatable {
        let heapComparisonCount: UInt64
        let heapSwapCount: UInt64
        let heapInsertionCount: UInt64
        let heapRemovalCount: UInt64
        let maximumComparisonCountPerHeapMutation: UInt64
        let retainedHeapNodeCount: Int
        let retainedHeapPositionCount: Int
        let heapPositionsAreConsistent: Bool
    }

    private struct Entry: Sendable {
        let packet: Element
        let token: Token
        let extendedSequenceNumber: UInt64
        let arrivalTimeNanoseconds: UInt64
        let byteCount: Int
    }

    private struct Node: Sendable {
        let sequenceNumber: UInt16
        let extendedSequenceNumber: UInt64
        let arrivalTimeNanoseconds: UInt64
        let token: Token
    }

    private struct Heap: Sendable {
        enum Ordering: Sendable {
            case sequenceAscending
            case sequenceDescending
            case arrivalAscending
        }

        let ordering: Ordering
        let recordsOperations: Bool
        var nodes: [Node] = []
        var positions: [ObjectIdentifier: Int] = [:]
        var comparisonCount: UInt64 = 0
        var swapCount: UInt64 = 0
        var insertionCount: UInt64 = 0
        var removalCount: UInt64 = 0
        var maximumComparisonCountPerMutation: UInt64 = 0

        var first: Node? { nodes.first }

        mutating func insert(_ node: Node) {
            let comparisonCountBeforeMutation = comparisonCount
            defer {
                recordMaximumComparisonCount(
                    since: comparisonCountBeforeMutation
                )
            }
            let identifier = ObjectIdentifier(node.token)
            precondition(positions[identifier] == nil)
            nodes.append(node)
            positions[identifier] = nodes.count - 1
            recordInsertion()
            siftUp(from: nodes.count - 1)
        }

        @discardableResult
        mutating func remove(token: Token) -> Node? {
            let identifier = ObjectIdentifier(token)
            guard let index = positions.removeValue(forKey: identifier) else {
                return nil
            }
            let comparisonCountBeforeMutation = comparisonCount
            defer {
                recordMaximumComparisonCount(
                    since: comparisonCountBeforeMutation
                )
            }
            recordRemoval()

            let lastIndex = nodes.count - 1
            guard index != lastIndex else {
                return nodes.removeLast()
            }

            let removed = nodes[index]
            let replacement = nodes.removeLast()
            nodes[index] = replacement
            positions[ObjectIdentifier(replacement.token)] = index

            if index > 0 {
                let parent = (index - 1) / 2
                if precedes(nodes[index], nodes[parent]) {
                    siftUp(from: index)
                    return removed
                }
            }
            siftDown(from: index)
            return removed
        }

        mutating func removeAll(keepingCapacity: Bool) {
            nodes.removeAll(keepingCapacity: keepingCapacity)
            positions.removeAll(keepingCapacity: keepingCapacity)
        }

        private mutating func siftUp(from initialChild: Int) {
            var child = initialChild
            while child > 0 {
                let parent = (child - 1) / 2
                guard precedes(nodes[child], nodes[parent]) else { return }
                swapNodes(at: child, and: parent)
                child = parent
            }
        }

        private mutating func siftDown(from initialParent: Int) {
            var parent = initialParent
            while true {
                let left = parent * 2 + 1
                guard left < nodes.count else { return }
                let right = left + 1
                var candidate = left
                if right < nodes.count,
                   precedes(nodes[right], nodes[left]) {
                    candidate = right
                }
                guard precedes(nodes[candidate], nodes[parent]) else { return }
                swapNodes(at: parent, and: candidate)
                parent = candidate
            }
        }

        private mutating func swapNodes(at first: Int, and second: Int) {
            nodes.swapAt(first, second)
            positions[ObjectIdentifier(nodes[first].token)] = first
            positions[ObjectIdentifier(nodes[second].token)] = second
            recordSwap()
        }

        private mutating func precedes(_ lhs: Node, _ rhs: Node) -> Bool {
            recordComparison()
            switch ordering {
            case .sequenceAscending:
                return lhs.extendedSequenceNumber < rhs.extendedSequenceNumber
            case .sequenceDescending:
                return lhs.extendedSequenceNumber > rhs.extendedSequenceNumber
            case .arrivalAscending:
                if lhs.arrivalTimeNanoseconds != rhs.arrivalTimeNanoseconds {
                    return lhs.arrivalTimeNanoseconds < rhs.arrivalTimeNanoseconds
                }
                return lhs.extendedSequenceNumber < rhs.extendedSequenceNumber
            }
        }

        func positionsAreConsistent() -> Bool {
            guard positions.count == nodes.count else { return false }
            for (index, node) in nodes.enumerated() {
                guard positions[ObjectIdentifier(node.token)] == index else {
                    return false
                }
            }
            return true
        }

        @inline(__always)
        private mutating func recordComparison() {
            guard recordsOperations else { return }
            comparisonCount &+= 1
        }

        @inline(__always)
        private mutating func recordSwap() {
            guard recordsOperations else { return }
            swapCount &+= 1
        }

        @inline(__always)
        private mutating func recordInsertion() {
            guard recordsOperations else { return }
            insertionCount &+= 1
        }

        @inline(__always)
        private mutating func recordRemoval() {
            guard recordsOperations else { return }
            removalCount &+= 1
        }

        @inline(__always)
        private mutating func recordMaximumComparisonCount(
            since previousComparisonCount: UInt64
        ) {
            guard recordsOperations else { return }
            maximumComparisonCountPerMutation = max(
                maximumComparisonCountPerMutation,
                comparisonCount &- previousComparisonCount
            )
        }
    }

    private var entries: [UInt16: Entry] = [:]
    private var sequenceMinHeap: Heap
    private var sequenceMaxHeap: Heap
    private var arrivalMinHeap: Heap

    private(set) var byteCount = 0

    var count: Int { entries.count }
    var isEmpty: Bool { entries.isEmpty }
    var operationMetrics: OperationMetrics {
        OperationMetrics(
            heapComparisonCount:
                sequenceMinHeap.comparisonCount
                    &+ sequenceMaxHeap.comparisonCount
                    &+ arrivalMinHeap.comparisonCount,
            heapSwapCount:
                sequenceMinHeap.swapCount
                    &+ sequenceMaxHeap.swapCount
                    &+ arrivalMinHeap.swapCount,
            heapInsertionCount:
                sequenceMinHeap.insertionCount
                    &+ sequenceMaxHeap.insertionCount
                    &+ arrivalMinHeap.insertionCount,
            heapRemovalCount:
                sequenceMinHeap.removalCount
                    &+ sequenceMaxHeap.removalCount
                    &+ arrivalMinHeap.removalCount,
            maximumComparisonCountPerHeapMutation: max(
                sequenceMinHeap.maximumComparisonCountPerMutation,
                sequenceMaxHeap.maximumComparisonCountPerMutation,
                arrivalMinHeap.maximumComparisonCountPerMutation
            ),
            retainedHeapNodeCount:
                sequenceMinHeap.nodes.count
                    + sequenceMaxHeap.nodes.count
                    + arrivalMinHeap.nodes.count,
            retainedHeapPositionCount:
                sequenceMinHeap.positions.count
                    + sequenceMaxHeap.positions.count
                    + arrivalMinHeap.positions.count,
            heapPositionsAreConsistent:
                sequenceMinHeap.positionsAreConsistent()
                    && sequenceMaxHeap.positionsAreConsistent()
                    && arrivalMinHeap.positionsAreConsistent()
        )
    }

    init(recordsHeapOperations: Bool = false) {
        sequenceMinHeap = Heap(
            ordering: .sequenceAscending,
            recordsOperations: recordsHeapOperations
        )
        sequenceMaxHeap = Heap(
            ordering: .sequenceDescending,
            recordsOperations: recordsHeapOperations
        )
        arrivalMinHeap = Heap(
            ordering: .arrivalAscending,
            recordsOperations: recordsHeapOperations
        )
    }

    func contains(sequenceNumber: UInt16) -> Bool {
        entries[sequenceNumber] != nil
    }

    mutating func insert(
        _ packet: consuming Element,
        sequenceNumber: UInt16,
        extendedSequenceNumber: UInt64,
        arrivalTimeNanoseconds: UInt64,
        byteCount: Int
    ) {
        precondition(entries[sequenceNumber] == nil)
        let token = Token()
        entries[sequenceNumber] = Entry(
            packet: packet,
            token: token,
            extendedSequenceNumber: extendedSequenceNumber,
            arrivalTimeNanoseconds: arrivalTimeNanoseconds,
            byteCount: byteCount
        )
        self.byteCount += byteCount

        let node = Node(
            sequenceNumber: sequenceNumber,
            extendedSequenceNumber: extendedSequenceNumber,
            arrivalTimeNanoseconds: arrivalTimeNanoseconds,
            token: token
        )
        sequenceMinHeap.insert(node)
        sequenceMaxHeap.insert(node)
        arrivalMinHeap.insert(node)
    }

    mutating func remove(
        sequenceNumber: UInt16
    ) -> H264RTPIndexedPacket<Element>? {
        guard let entry = entries.removeValue(forKey: sequenceNumber) else {
            return nil
        }
        byteCount -= entry.byteCount
        // These removals are internal invariant checks: callers cannot create a
        // dictionary entry without the matching scalar node in every heap.
        let removedFromSequenceMin = sequenceMinHeap.remove(token: entry.token)
        let removedFromSequenceMax = sequenceMaxHeap.remove(token: entry.token)
        let removedFromArrivalMin = arrivalMinHeap.remove(token: entry.token)
        precondition(removedFromSequenceMin != nil)
        precondition(removedFromSequenceMax != nil)
        precondition(removedFromArrivalMin != nil)
        let indexedPacket = H264RTPIndexedPacket(
            packet: entry.packet,
            extendedSequenceNumber: entry.extendedSequenceNumber
        )
        return indexedPacket
    }

    mutating func removeEarliest(
    ) -> H264RTPIndexedPacket<Element>? {
        guard let sequenceNumber = earliestSequenceNumber() else { return nil }
        return remove(sequenceNumber: sequenceNumber)
    }

    mutating func earliestMetadata(
    ) -> (sequenceNumber: UInt16, extendedSequenceNumber: UInt64)? {
        guard let sequenceNumber = earliestSequenceNumber(),
              let entry = entries[sequenceNumber] else {
            return nil
        }
        return (sequenceNumber, entry.extendedSequenceNumber)
    }

    mutating func removeFarthest(
    ) -> H264RTPIndexedPacket<Element>? {
        guard let sequenceNumber = sequenceMaxHeap.first?.sequenceNumber else {
            return nil
        }
        return remove(sequenceNumber: sequenceNumber)
    }

    mutating func earliestArrivalTimeNanoseconds() -> UInt64? {
        arrivalMinHeap.first?.arrivalTimeNanoseconds
    }

    mutating func removeAll(keepingCapacity: Bool) {
        entries.removeAll(keepingCapacity: keepingCapacity)
        sequenceMinHeap.removeAll(keepingCapacity: keepingCapacity)
        sequenceMaxHeap.removeAll(keepingCapacity: keepingCapacity)
        arrivalMinHeap.removeAll(keepingCapacity: keepingCapacity)
        byteCount = 0
    }

    private mutating func earliestSequenceNumber() -> UInt16? {
        sequenceMinHeap.first?.sequenceNumber
    }
}
