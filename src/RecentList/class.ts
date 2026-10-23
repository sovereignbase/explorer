import { Sequenced, type SequencedArray } from '@sovereignbase/sequenced'

export type RecentListEntry = Readonly<[path: string, dateAccessed: string]>

export class RecentList {
  private state: SequencedArray<RecentListEntry>
  constructor(actorID: number, snapshot?: unknown) {
    this.state = new Sequenced.Array(actorID, snapshot)
  }

  values(): ArrayIterator<RecentListEntry> {
    return this.state.values()
  }

  update(accessed: RecentListEntry): void {
    void this.state.pop()
    void this.state.unshift(accessed)
  }
}
