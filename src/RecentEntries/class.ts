import type { CipherKey } from '@sovereignbase/cryptosuite'
import {
  Sequenced,
  type SequencedArray,
  type SequencedArrayDelta,
} from '@sovereignbase/sequenced'
import { Explorer } from '../class.js'
import { afterIdleFor, type WritableArray } from '@sovereignbase/utils'

export type RecentEntriesDelta = Readonly<
  ['recentEntries', SequencedArrayDelta<RecentEntry>]
>

export type RecentEntry = {
  id: string
  name: string
  cipherKey: CipherKey
  dateAccessed: string
}

export class RecentEntries {
  private state: SequencedArray<RecentEntry>
  private deltaBuffer: WritableArray<SequencedArrayDelta<RecentEntry>> =
    new Array()
  constructor(
    private readonly id: string,
    actorID: number,
    trustedSnapshot?: unknown
  ) {
    this.state = new Sequenced.Array(actorID, trustedSnapshot)
    //
    const debouncedDispatch = afterIdleFor(500, () => {
      void Explorer.dispatchEvent('delta', ['recentEntries', this.deltaBuffer])
      this.deltaBuffer.length = 0
    })
    void this.state.addEventListener('delta', ({ detail }) => {
      this.deltaBuffer.push(...detail)
      void debouncedDispatch()
    })
    //
    let seen: Set<string> | null = new Set()
    void this.state.forEach((entry, index) => {
      if (seen!.has(entry.id)) {
        this.state.delete(index)
      }
      if (seen!.size <= 20) seen!.add(id)
      else this.state.delete(index)
    })
    seen = null
    //
  }

  values(): ArrayIterator<RecentEntry> {
    return this.state.values()
  }

  update(accessed: RecentEntry): void {
    void this.state.forEach((entry, index) => {
      if (entry.id === accessed.id) {
        this.state.delete(index)
      }
    })

    void this.state.unshift(accessed)

    while (this.state.length > 20) {
      void this.state.pop()
    }

    queueMicrotask(async () => {
      void Explorer.storeObjectByID(
        this.id,
        this.state.toJSON(),
        Explorer.cipherKeyCache.get(this.id) as CipherKey
      )
    })
  }
}
