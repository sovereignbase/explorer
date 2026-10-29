import {
  Sequenced,
  type SequencedArray,
  type SequencedArrayDelta,
  type SequencedArrayChange,
  type SequencedArraySnapshot,
} from '@sovereignbase/sequenced'
//
import type { CipherKey } from '@sovereignbase/cryptosuite'
import {
  invalidateDeviceBinding,
  type DeviceBindingStorage,
} from '@sovereignbase/hardware-bound'
//
import {
  afterIdleFor,
  type DeepReadonly,
  type WritableArray,
} from '@sovereignbase/utils'
//
import { Explorer } from '../class.js'
import { ExplorerError } from '../.errors/class.js'
import { unknownError } from '../.errors/unkown.js'

/**
 * Describes a credential registered with the database.
 */
export type CredentialEntry = {
  /** The display name of the credential. */
  name: string

  /** The entropy associated with the credential. */
  entropy: Uint8Array

  /** The storage characteristics of the device binding. */
  storage: DeviceBindingStorage

  /** The identifier of the object storing virtual entropy protected by the credential. */
  objectID: string

  /** The WebAuthn credential identifier. */
  credentialID: string

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
 * The object identifier, timestamp, and user agent are required to record use.
 * Creating an entry additionally requires the credential identifier,
 * display name, entropy, and storage characteristics.
 */
export type CredentialEvent = {
  /** The identifier of the object storing the credential's virtual entropy. */
  objectID?: string

  /** The WebAuthn credential identifier. */
  credentialID?: string

  /** The timestamp of the credential use. */
  timestamp?: number

  /** The user agent associated with the credential use. */
  userAgent?: string

  /** The display name of the credential. */
  name?: string

  /** The entropy associated with the credential. */
  entropy?: Uint8Array

  /** The storage characteristics of the device binding. */
  storage?: DeviceBindingStorage
}

/**
 * Represents a sequenced delta produced by the credential entries list.
 */
export type CredentialEntriesDelta = Readonly<
  ['credentialEntries', DeepReadonly<SequencedArrayDelta<CredentialEntry>>]
>

/**
 * Represents a sequenced change produced by the credential entries list.
 */
export type CredentialEntriesChange = DeepReadonly<
  SequencedArrayChange<CredentialEntry>
>

/**
 * Maps credential entries event names to their detail types.
 */
export type CredentialEntriesEventMap = {
  /** Fired when the credential entries list changes. */
  change: CredentialEntriesChange
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
 * Maintains the database's registered credentials.
 *
 * Entries are identified by their object and credential identifiers.
 * Changes are synchronized through a sequenced array and persisted
 * as encrypted snapshots.
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
   * @param sessionCredentialID The WebAuthn credential ID of the current session.
   * @param actorID The actor identifier used by the sequenced array.
   * @param trustedSnapshot An optional snapshot used to initialize the state.
   */
  constructor(
    private readonly id: string,
    private readonly cipherKey: CipherKey,
    public readonly sessionCredentialID: string,
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
        async (snapshot: SequencedArraySnapshot<CredentialEntry>) => {
          void (await Explorer.storeObjectByID(
            this.id,
            snapshot,
            this.cipherKey
          ))
        }
      )

      void this.state.addEventListener('snapshot', ({ detail }) => {
        void debouncedSave(detail)
      })

      void this.state.addEventListener('change', ({ detail }) => {
        void this.dispatchEvent('change', detail)
      })

      const seenObjects = new Set<string>()
      const seenCredentials = new Set<string>()
      const duplicates: number[] = []

      for (let index = 0; index < this.state.length; index++) {
        const entry = this.state.at(index)
        if (!entry) continue

        if (
          seenObjects.has(entry.objectID) ||
          seenCredentials.has(entry.credentialID)
        ) {
          duplicates.push(index)
        } else {
          seenObjects.add(entry.objectID)
          seenCredentials.add(entry.credentialID)
        }
      }

      for (let index = duplicates.length - 1; index >= 0; index--)
        void this.state.delete(duplicates[index])

      if (duplicates.length > 0 || this.deltaBuffer.length > 0)
        void this.state.snapshot()
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
   * @param credentialEvent The credential properties to apply.
   * @throws {ExplorerError} If the event is invalid or setup properties are missing.
   */
  public record(credentialEvent: CredentialEvent): void {
    try {
      if (!credentialEvent || typeof credentialEvent !== 'object')
        throw new ExplorerError(
          'INVALID_CREDENTIAL_EVENT',
          'A credential event must be an object.'
        )

      const {
        objectID,
        credentialID,
        timestamp,
        userAgent,
        name,
        entropy,
        storage,
      } = credentialEvent

      if (
        typeof objectID !== 'string' ||
        typeof timestamp !== 'number' ||
        !Number.isFinite(timestamp) ||
        typeof userAgent !== 'string'
      )
        throw new ExplorerError(
          'INVALID_CREDENTIAL_EVENT',
          'A credential event requires an object ID, a finite timestamp, and a user agent.'
        )

      let existing: CredentialEntry | undefined

      for (let index = this.state.length - 1; index >= 0; index--) {
        const entry = this.state.at(index)

        if (
          entry?.objectID === objectID ||
          (credentialID !== undefined && entry?.credentialID === credentialID)
        ) {
          existing = entry
          break
        }
      }

      if (
        !existing &&
        (typeof credentialID !== 'string' ||
          typeof name !== 'string' ||
          !(entropy instanceof Uint8Array) ||
          typeof storage !== 'string')
      )
        throw new ExplorerError(
          'MISSING_CREDENTIAL_SETUP_PROPERTIES',
          'A new credential requires a credential ID, name, entropy, and binding storage.'
        )

      const userAgents =
        existing?.userAgents.map((agent) => ({ ...agent })) ?? []

      const agent = userAgents.find((agent) => agent.name === userAgent)

      if (agent) {
        agent.lastSeen = Math.max(agent.lastSeen, timestamp)
      } else {
        userAgents.push({ name: userAgent, lastSeen: timestamp })
      }

      const entry: CredentialEntry = {
        objectID,
        credentialID: credentialID ?? existing!.credentialID,
        name: name ?? existing!.name,
        entropy: entropy ?? existing!.entropy,
        storage: storage ?? existing!.storage,
        lastUsed: Math.max(existing?.lastUsed ?? timestamp, timestamp),
        userAgents,
      }

      for (let index = this.state.length - 1; index >= 0; index--) {
        const current = this.state.at(index)

        if (
          current?.objectID === entry.objectID ||
          current?.credentialID === entry.credentialID
        )
          void this.state.delete(index)
      }

      void this.state.unshift(entry)
      void this.state.snapshot()
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.record()')
    }
  }

  /**
   * Revokes a credential and removes its registered entries.
   *
   * Deletes the credential's persisted objects before removing its entries.
   * The entries remain unchanged if deletion fails. Credential invalidation
   * is requested on a best-effort basis after successful removal.
   *
   * @param credentialID The WebAuthn credential identifier to revoke.
   */
  public async revoke(credentialID: string): Promise<void> {
    try {
      const objectIDs = new Set<string>()

      for (let index = this.state.length - 1; index >= 0; index--) {
        const entry = this.state.at(index)

        if (entry?.credentialID === credentialID) objectIDs.add(entry.objectID)
      }

      if (objectIDs.size === 0) return

      for (const objectID of objectIDs)
        await Explorer.deleteObjectByID(objectID)

      let removed = false

      for (let index = this.state.length - 1; index >= 0; index--) {
        if (this.state.at(index)?.credentialID === credentialID) {
          void this.state.delete(index)
          removed = true
        }
      }

      if (removed) void this.state.snapshot()

      try {
        await invalidateDeviceBinding(credentialID)
      } catch {
        // Credential invalidation is best-effort.
      }

      // Log out.
      if (credentialID === this.sessionCredentialID)
        void window.location.reload()
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.revoke()')
    }
  }

  /**
   * Returns the credential entries ordered by most recent use.
   *
   * Entries with equal timestamps are ordered by credential identifier.
   */
  public list(): DeepReadonly<Array<CredentialEntry>> {
    try {
      return this.state
        .slice()
        .sort(
          (a, b) =>
            b.lastUsed - a.lastUsed ||
            a.credentialID.localeCompare(b.credentialID)
        )
    } catch (cause) {
      throw unknownError(cause, 'CredentialEntries.list()')
    }
  }

  /**
   * Applies a sequenced delta to the credential entries list.
   *
   * @param delta The delta to apply.
   */
  public apply(delta: unknown): void {
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
  public merge(snapshot: unknown): void {
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
