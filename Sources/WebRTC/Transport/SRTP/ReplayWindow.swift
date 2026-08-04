struct ReplayWindow: Sendable, Equatable {
    static let width: UInt64 = 64

    private(set) var highestIndex: UInt64?
    private(set) var bitmap: UInt64 = 0

    enum Verdict: Sendable, Equatable {
        case acceptable
        case replayed
        case tooOld
    }

    func verdict(for index: UInt64) -> Verdict {
        guard let highestIndex else {
            return .acceptable
        }
        if index > highestIndex {
            return .acceptable
        }

        let distance = highestIndex - index
        guard distance < Self.width else {
            return .tooOld
        }
        let mask = UInt64(1) << distance
        return bitmap & mask == 0 ? .acceptable : .replayed
    }

    mutating func commit(_ index: UInt64) {
        guard let highestIndex else {
            self.highestIndex = index
            bitmap = 1
            return
        }

        if index > highestIndex {
            let distance = index - highestIndex
            bitmap = distance >= Self.width ? 1 : (bitmap << distance) | 1
            self.highestIndex = index
            return
        }

        let distance = highestIndex - index
        if distance < Self.width {
            bitmap |= UInt64(1) << distance
        }
    }
}
