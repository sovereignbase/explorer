import type { CipherKey } from '@sovereignbase/cryptosuite'
import { Sequenced, type SequencedArray } from '@sovereignbase/sequenced'

export type RecentEntry = Readonly<
  [id: string, path: string, cipherKey: CipherKey, dateAccessed: string]
>

export class RecentEntries {
  private state: SequencedArray<RecentEntry>
  constructor(actorID: number, snapshot?: unknown) {
    this.state = new Sequenced.Array(actorID, snapshot)
  }

  values(): ArrayIterator<RecentEntry> {
    return this.state.values()
  }

  update(accessed: RecentEntry): void {
    void this.state.pop()
    void this.state.unshift(accessed)
  }
}
