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
 * Describes an entry in the credential objects list.
 */
export type CredentialEntry = {
  /** The identifier of the referenced object. */
  id: string

  /** The display name of the referenced object. */
  name: string

  /** The entropy associated with the credential. */
  entropy: Uint8Array

  /** The timestamp of the most recent use of this credential. */
  lastUsed: number

  /** The user agents that have used this credential. */
  userAgents: Array<{
    /** The user agent string. */
    name: string

    /** The timestamp of the most recent use. */
    lastSeen: number
  }>
}

/**
 * Represents a sequenced delta produced by the Credential entries list.
 */
export type CredentialEntriesDelta = Readonly<
  ['credentialEntries', SequencedArrayDelta<CredentialEntry>]
>

/**
 * Maps event names to the values exposed through `CustomEvent.detail`.
 */
export type CredentialEntriesEventMap = {
  /** Fired when the Credential entries list changes. */
  change: SequencedArrayChange<CredentialEntry>
}

/**
 * Represents an event listener for a {@link CredentialEntries} event.
 *
 * @typeParam K The event name that determines the event's `detail` type.
 */
export type CredentialEntriesEventListener<
  K extends keyof CredentialEntriesEventMap,
> =
  | ((event: CustomEvent<CredentialEntriesEventMap[K]>) => void)
  | { handleEvent(event: CustomEvent<CredentialEntriesEventMap[K]>): void }

/**
 * Resolves a {@link CredentialEntries} event name to its corresponding typed
 * listener.
 *
 * @typeParam K The event name to resolve.
 */
export type CredentialEntriesEventListenerFor<K extends string> =
  K extends keyof CredentialEntriesEventMap
    ? CredentialEntriesEventListener<K>
    : EventListenerOrEventListenerObject

/**
 * Maintains the ordered list of Credentially accessed objects.
 *
 * Entries are ordered from most Credentially accessed to least Credentially accessed,
 * deduplicated by identifier, and limited to 20 entries.
 */
export class CredentialEntries {
  private state: SequencedArray<CredentialEntry>
  private deltaBuffer: WritableArray<SequencedArrayDelta<CredentialEntry>> =
    new Array()
  private eventTarget?: EventTarget

  /**
   * Creates a Credential entries list.
   *
   * @param id The identifier of the persisted Credential entries object.
   * @param actorID The actor identifier used by the sequenced array.
   * @param trustedSnapshot A trusted snapshot used to initialize the state.
   */
  constructor(
    private readonly id: string,
    private readonly cipherKey: CipherKey,
    private readonly sessionCredentialID: string,
    actorID: number,
    trustedSnapshot?: unknown
  ) {
    try {
      this.state = new Sequenced.Array(actorID, trustedSnapshot)
      //
      const debouncedDispatch = afterIdleFor(250, () => {
        void Explorer.dispatchEvent('delta', [
          'credentialEntries',
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
        (snapshot: SequencedArraySnapshot<CredentialEntry>) => {
          void queueMicrotask(() => {
            void Explorer.storeObjectByID(this.id, snapshot, this.cipherKey)
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
        if (seen.has(entry.id)) {
          void this.state.delete(index)
          return
        }
        void seen.add(entry.id)
      })
      //
      if (this.deltaBuffer.length > 0) void this.state.snapshot()
      //
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.constructor()')
    }
  }

  /**
   * Marks an entry as most Credentially accessed.
   *
   * Any existing entry with the same identifier is removed before the new
   * entry is inserted at the beginning of the list.
   *
   * @param accessed The entry that was accessed.
   */
  update(accessed: CredentialEntry): void {
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
      throw unknownError(cause, 'CredentialEntries.update()')
    }
  }
  /**
   * Returns the Credential entries ordered by most Credential access.
   */
  values(): ReadonlyArray<Readonly<CredentialEntry>> {
    try {
      return this.state.slice().sort()
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.values()')
    }
  }
  //
  /**
   * Applies a sequenced delta to the Credential entries list.
   *
   * @param delta The delta to apply.
   */
  apply(delta: unknown): void {
    try {
      void this.state.apply(delta)
      void this.state.snapshot()
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.apply()')
    }
  }

  /**
   * Merges a snapshot into the Credential entries list.
   *
   * @param snapshot The snapshot to merge.
   */
  merge(snapshot: unknown): void {
    try {
      void this.state.merge(snapshot)
      void this.state.snapshot()
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.merge()')
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
  public addEventListener<K extends keyof CredentialEntriesEventMap>(
    type: K,
    listener: CredentialEntriesEventListenerFor<K> | null,
    options?: boolean | AddEventListenerOptions
  ): void {
    try {
      void (this.eventTarget ??= new EventTarget()).addEventListener(
        type,
        listener as EventListenerOrEventListenerObject | null,
        options
      )
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.addEventListener()')
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
  public removeEventListener<K extends keyof CredentialEntriesEventMap>(
    type: K,
    listener: CredentialEntriesEventListenerFor<K> | null,
    options?: boolean | EventListenerOptions
  ): void {
    try {
      void this.eventTarget?.removeEventListener(
        type,
        listener as EventListenerOrEventListenerObject | null,
        options
      )
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.removeEventListener()')
    }
  }

  /**
   * Dispatches an event of the specified type to registered listeners.
   *
   * @param type The event type.
   * @param detail The value exposed through `CustomEvent.detail`.
   */
  public dispatchEvent<K extends keyof CredentialEntriesEventMap>(
    type: K,
    detail: CredentialEntriesEventMap[K]
  ): void {
    try {
      void this.eventTarget?.dispatchEvent(new CustomEvent(type, { detail }))
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.dispatchEvent()')
    }
  }
}
