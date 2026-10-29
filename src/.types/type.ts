import type { RecentEntriesDelta } from '../RecentEntries/class.js'
import type { CredentialEntriesDelta } from '../CredentialEntries/class.js'
import { DeviceBindingStorage } from '@sovereignbase/hardware-bound'

/**
 * Represents the outcome of a database authentication attempt.
 */
export type AuthenticationResult =
  /** The database was successfully authenticated. */
  | 'authenticated'
  /** The device authenticator could not provide the required entropy. */
  | 'authenticator-error'
  /** The supplied data PIN could not unlock the credential. */
  | 'invalid-data-pin'

/**
 * Describes the parameters used to register a new database credential.
 */
export type AuthenticationSetupParams = Readonly<{
  /** The display name assigned to the credential. */
  credentialName: string

  /** Optional virtual entropy used to establish an existing database. */
  virtualEntropy?: Uint8Array

  /** The storage mechanism used to bind the credential to the device. */
  bindingStorage: DeviceBindingStorage
}>

/**
 * Represents a synchronized delta exchanged between Explorer instances.
 *
 * Includes changes to recent and credential entries, as well as
 * a reserved variant for other delta types.
 */
export type ExplorerDelta =
  RecentEntriesDelta | CredentialEntriesDelta | ['other' | []]

/**
 * Maps Explorer event names to their detail types.
 */
export type ExplorerEventMap = {
  /** Fired when the database authentication state changes. */
  authenticated: boolean

  /** Fired when a synchronized delta is produced. */
  delta: ExplorerDelta
}

/**
 * Represents an event listener for an {@link Explorer} event.
 *
 * @typeParam K The event name that determines the event detail type.
 */
export type ExplorerEventListener<K extends keyof ExplorerEventMap> =
  | ((event: CustomEvent<ExplorerEventMap[K]>) => void)
  | { handleEvent(event: CustomEvent<ExplorerEventMap[K]>): void }

/**
 * Resolves an event name to its corresponding listener type.
 *
 * @typeParam K The event name to resolve.
 */
export type ExplorerEventListenerFor<K extends string> =
  K extends keyof ExplorerEventMap
    ? ExplorerEventListener<K>
    : EventListenerOrEventListenerObject
