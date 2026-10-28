
import type { CipherKey } from '@sovereignbase/cryptosuite'
import {
  Sequenced,
  type SequencedArray,
  type SequencedArrayDelta,
  type SequencedArrayChange,
  type SequencedArraySnapshot,
} from '@sovereignbase/sequenced'
import type { DeviceBindingStorage } from '@sovereignbase/hardware-bound'
import { afterIdleFor, type WritableArray } from '@sovereignbase/utils'
import { Explorer } from '../class.js'
import { unknownError } from '../.errors/unkown.js'

/**
 * Describes a credential registered with the database.
 */
export type CredentialEntry = {
  /** The identifier of the credential. */
  id: string

  /** The display name of the credential. */
  name: string

  /** The entropy associated with the credential. */
  entropy: Uint8Array

  /** The storage mechanism used for device binding. */
  storage: DeviceBindingStorage

  /** The timestamp of the most recent use of the credential. */
  lastUsed: number

  /** The user agents that have used the credential. */
  userAgents: Array<{
    /** The user agent string. */
    name: string

    /** The timestamp of the most recent use by the user agent. */
    lastSeen: number
  }>
}

/**
 * Describes the properties used to create or update a credential entry.
 *
 * The identifier, timestamp, and user agent are required when applying
 * a patch. Additional properties are required when creating an entry.
 */
export type CredentialPatch = {
  /** The identifier of the credential. */
  id?: string

  /** The timestamp of the credential use. */
  timestamp?: number

  /** The user agent associated with the credential use. */
  userAgent?: string

  /** The display name of the credential. */
  name?: string

  /** The entropy associated with the credential. */
  entropy?: Uint8Array

  /** The storage mechanism used for device binding. */
  storage?: DeviceBindingStorage
}

/**
 * Represents a sequenced delta produced by the credential entries list.
 */
export type CredentialEntriesDelta = Readonly<
  ['credentialEntries', SequencedArrayDelta<CredentialEntry>]
>

/**
 * Maps credential entries event names to their detail types.
 */
export type CredentialEntriesEventMap = {
  /** Fired when the credential entries list changes. */
  change: SequencedArrayChange<CredentialEntry>
}

/**
 * Represents an event listener for a {@link CredentialEntries} event.
 *
 * @typeParam K The event name that determines the event detail type.
 */
export type CredentialEntriesEventListener<
  K extends keyof CredentialEntriesEventMap,
> =
  | ((event: CustomEvent<CredentialEntriesEventMap[K]>) => void)
  | { handleEvent(event: CustomEvent<CredentialEntriesEventMap[K]>): void }

/**
 * Resolves an event name to its corresponding listener type.
 *
 * @typeParam K The event name to resolve.
 */
export type CredentialEntriesEventListenerFor<K extends string> =
  K extends keyof CredentialEntriesEventMap
    ? CredentialEntriesEventListener<K>
    : EventListenerOrEventListenerObject

/**
 * Maintains the database's credential entries.
 *
 * Entries are identified by credential ID and synchronized through
 * a sequenced array. Changes are persisted as encrypted snapshots.
 */
export class CredentialEntries {
  private state: SequencedArray<CredentialEntry>
  private deltaBuffer: WritableArray<SequencedArrayDelta<CredentialEntry>> =
    new Array()
  private eventTarget?: EventTarget

  /**
   * Creates a credential entries list.
   *
   * @param id The identifier of the persisted entries object.
   * @param cipherKey The key used to encrypt the entries object.
   * @param sessionCredentialID The credential ID of the current session.
   * @param actorID The actor identifier used by the sequenced array.
   * @param trustedSnapshot An optional snapshot used to initialize the state.
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

      void this.state.addEventListener('change', ({ detail }) => {
        void this.dispatchEvent('change', detail)
      })

      const seen = new Set<string>()

      for (let index = this.state.length - 1; index >= 0; index--) {
        const entry = this.state.at(index)
        if (!entry) continue

        if (seen.has(entry.id)) {
          void this.state.delete(index)
        } else {
          void seen.add(entry.id)
        }
      }

      if (this.deltaBuffer.length > 0) void this.state.snapshot()
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.constructor()')
    }
  }

  /**
   * Creates or updates a credential entry.
   *
   * Updates the credential's last-used timestamp and the corresponding
   * user agent's last-seen timestamp. Existing properties are preserved
   * unless replacements are provided.
   *
   * @param credential The credential properties to apply.
   */
  patch(credential: CredentialPatch): void {
    try {
      const { id, timestamp, userAgent, name, entropy, storage } = credential

      if (
        typeof id !== 'string' ||
        typeof timestamp !== 'number' ||
        !Number.isFinite(timestamp) ||
        typeof userAgent !== 'string'
      )
        throw new Error('Invalid credential patch')

      let existing: CredentialEntry | undefined

      for (let index = this.state.length - 1; index >= 0; index--) {
        const entry = this.state.at(index)
        if (entry?.id === id) {
          existing = entry
          break
        }
      }

      if (
        !existing &&
        (typeof name !== 'string' ||
          !(entropy instanceof Uint8Array) ||
          storage === undefined)
      )
        throw new Error('Missing credential setup properties')

      const userAgents = existing?.userAgents.map(agent => ({ ...agent })) ?? []
      const agent = userAgents.find(agent => agent.name === userAgent)

      if (agent) {
        agent.lastSeen = Math.max(agent.lastSeen, timestamp)
      } else {
        userAgents.push({ name: userAgent, lastSeen: timestamp })
      }

      const entry: CredentialEntry = {
        id,
        name: name ?? existing!.name,
        entropy: entropy ?? existing!.entropy,
        storage: storage ?? existing!.storage,
        lastUsed: Math.max(existing?.lastUsed ?? timestamp, timestamp),
        userAgents,
      }

      for (let index = this.state.length - 1; index >= 0; index--) {
        if (this.state.at(index)?.id === id)
          void this.state.delete(index)
      }

      void this.state.unshift(entry)
      void this.state.snapshot()
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.patch()')
    }
  }

  /**
   * Removes a credential from the database.
   * 
   * @param credentialID The identifier of the credential to remove.
   */
  destroy(credentialID: string): void {
    try {
      let removed = false

      for (let index = this.state.length - 1; index >= 0; index--) {
        if (this.state.at(index)?.id !== credentialID) continue

        void this.state.delete(index)
        removed = true
      }

      if (!removed) return

      void this.state.snapshot()
      void Explorer.deleteObjectByID(credentialID)
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.destroy()')
    }
  }

  /**
   * Returns the credential entries ordered by most recent use.
   *
   * Entries with equal timestamps are ordered by identifier.
   */
  values(): ReadonlyArray<Readonly<CredentialEntry>> {
    try {
      return this.state
        .slice()
        .sort(
          (a, b) =>
            b.lastUsed - a.lastUsed || a.id.localeCompare(b.id)
        )
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.values()')
    }
  }

  /**
   * Applies a sequenced delta to the credential entries list.
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
   * Merges a snapshot into the credential entries list.
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
   * @param listener The event listener, or `null`.
   * @param options The event listener options.
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
   * @param listener The event listener to remove, or `null`.
   * @param options The event listener options.
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
   * Dispatches an event to the registered listeners.
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
