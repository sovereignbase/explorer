import type { CipherKey } from '@sovereignbase/cryptosuite'
import {
  Sequenced,
  type SequencedArray,
  type SequencedArrayDelta,
  type SequencedArrayChange,
  type SequencedArraySnapshot,
} from '@sovereignbase/sequenced'
import { Explorer } from '../class.js'
import { afterIdleFor, type WritableArray } from '@sovereignbase/utils'
import { unknownError } from '../.errors/unkown.js'

/**
 * Describes an entry in the recent objects list.
 */
export type RecentEntry = {
  /** The identifier of the referenced object. */
  id: string

  /** The display name of the referenced object. */
  name: string

  /** The cipher key used to access the referenced object. */
  cipherKey: CipherKey

  /** The date and time at which the object was most recently accessed. */
  dateAccessed: number
}

/**
 * Represents a sequenced delta produced by the recent entries list.
 */
export type RecentEntriesDelta = Readonly<
  ['recentEntries', SequencedArrayDelta<RecentEntry>]
>

/**
 * Maps event names to the values exposed through `CustomEvent.detail`.
 */
export type RecentEntriesEventMap = {
  /** Fired when the recent entries list changes. */
  change: SequencedArrayChange<RecentEntry>
}

/**
 * Represents an event listener for a {@link RecentEntries} event.
 *
 * @typeParam K The event name that determines the event's `detail` type.
 */
export type RecentEntriesEventListener<K extends keyof RecentEntriesEventMap> =
  | ((event: CustomEvent<RecentEntriesEventMap[K]>) => void)
  | { handleEvent(event: CustomEvent<RecentEntriesEventMap[K]>): void }

/**
 * Resolves a {@link RecentEntries} event name to its corresponding typed
 * listener.
 *
 * @typeParam K The event name to resolve.
 */
export type RecentEntriesEventListenerFor<K extends string> =
  K extends keyof RecentEntriesEventMap
    ? RecentEntriesEventListener<K>
    : EventListenerOrEventListenerObject

/**
 * Maintains the ordered list of recently accessed objects.
 *
 * Entries are ordered from most recently accessed to least recently accessed,
 * deduplicated by identifier, and limited to 20 entries.
 */
export class RecentEntries {
  private state: SequencedArray<RecentEntry>
  private deltaBuffer: WritableArray<SequencedArrayDelta<RecentEntry>> =
    new Array()
  private eventTarget?: EventTarget

  /**
   * Creates a recent entries list.
   *
   * @param id The identifier of the persisted recent entries object.
   * @param actorID The actor identifier used by the sequenced array.
   * @param trustedSnapshot A trusted snapshot used to initialize the state.
   */
  constructor(
    private readonly id: string,
    actorID: number,
    trustedSnapshot?: unknown
  ) {
    try {
      this.state = new Sequenced.Array(actorID, trustedSnapshot)
      //
      const debouncedDispatch = afterIdleFor(250, () => {
        void Explorer.dispatchEvent('delta', [
          'recentEntries',
          this.deltaBuffer.splice(0),
        ])
      })
      void this.state.addEventListener('delta', ({ detail }) => {
        void this.deltaBuffer.push(...detail)
        void debouncedDispatch()
      })
      //
      const debouncedSave = afterIdleFor(
        250,
        (snapshot: SequencedArraySnapshot<RecentEntry>) => {
          void queueMicrotask(() => {
            void Explorer.storeObjectByID(
              this.id,
              snapshot,
              Explorer.cipherKeyCache.get(this.id) as CipherKey
            )
          })
        }
      )
      void this.state.addEventListener('snapshot', ({ detail }) => {
        void debouncedSave(detail)
      })
      //
      void this.state.addEventListener('change', ({ detail }) => {
        void this.dispatchEvent('change', detail)
      })
      //
      const seen = new Set<string>()
      void this.state.forEach((entry, index) => {
        if (seen.has(entry.id) || seen.size >= 20) {
          void this.state.delete(index)
          return
        }
        void seen.add(entry.id)
      })
      //
      if (this.deltaBuffer.length > 0) void this.state.snapshot()
      //
    } catch (cause) {
      throw unknownError(cause, 'RecentEntries.constructor()')
    }
  }

  /**
   * Marks an entry as most recently accessed.
   *
   * Any existing entry with the same identifier is removed before the new
   * entry is inserted at the beginning of the list.
   *
   * @param accessed The entry that was accessed.
   */
  update(accessed: RecentEntry): void {
    try {
      void this.state.forEach((entry, index) => {
        if (entry.id === accessed.id) {
          this.state.delete(index)
        }
      })

      void this.state.unshift(accessed)

      while (this.state.length > 20) {
        void this.state.pop()
      }
      void this.state.snapshot()
    } catch (cause) {
      throw unknownError(cause, 'RecentEntries.update()')
    }
  }
  /**
   * Returns the recent entries ordered by most recent access.
   */
  values(): ReadonlyArray<Readonly<RecentEntry>> {
    try {
      return this.state.slice().sort((a, b) => b.dateAccessed - a.dateAccessed)
    } catch (cause) {
      throw unknownError(cause, 'RecentEntries.values()')
    }
  }
  //
  /**
   * Applies a sequenced delta to the recent entries list.
   *
   * @param delta The delta to apply.
   */
  apply(delta: unknown): void {
    try {
      void this.state.apply(delta)
      void this.state.snapshot()
    } catch (cause) {
      throw unknownError(cause, 'RecentEntries.apply()')
    }
  }

  /**
   * Merges a snapshot into the recent entries list.
   *
   * @param snapshot The snapshot to merge.
   */
  merge(snapshot: unknown): void {
    try {
      void this.state.merge(snapshot)
      void this.state.snapshot()
    } catch (cause) {
      throw unknownError(cause, 'RecentEntries.merge()')
    }
  }

  /**
   * Registers an event listener for the specified event type.
   *
   * @param type The event type.
   * @param listener The listener to register, or `null`.
   * @param options An options object that specifies characteristics of the
   * event listener.
   */
  public addEventListener<K extends keyof RecentEntriesEventMap>(
    type: K,
    listener: RecentEntriesEventListenerFor<K> | null,
    options?: boolean | AddEventListenerOptions
  ): void {
    try {
      void (this.eventTarget ??= new EventTarget()).addEventListener(
        type,
        listener as EventListenerOrEventListenerObject | null,
        options
      )
    } catch (cause) {
      throw unknownError(cause, 'RecentEntries.addEventListener()')
    }
  }

  /**
   * Removes an event listener previously registered with
   * {@link addEventListener}.
   *
   * @param type The event type.
   * @param listener The listener to remove, or `null`.
   * @param options An options object that specifies characteristics of the
   * event listener.
   */
  public removeEventListener<K extends keyof RecentEntriesEventMap>(
    type: K,
    listener: RecentEntriesEventListenerFor<K> | null,
    options?: boolean | EventListenerOptions
  ): void {
    try {
      void this.eventTarget?.removeEventListener(
        type,
        listener as EventListenerOrEventListenerObject | null,
        options
      )
    } catch (cause) {
      throw unknownError(cause, 'RecentEntries.removeEventListener()')
    }
  }

  /**
   * Dispatches an event of the specified type to registered listeners.
   *
   * @param type The event type.
   * @param detail The value exposed through `CustomEvent.detail`.
   */
  public dispatchEvent<K extends keyof RecentEntriesEventMap>(
    type: K,
    detail: RecentEntriesEventMap[K]
  ): void {
    try {
      void this.eventTarget?.dispatchEvent(new CustomEvent(type, { detail }))
    } catch (cause) {
      throw unknownError(cause, 'RecentEntries.dispatchEvent()')
    }
  }
}
